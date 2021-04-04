/*******************************************************************************

    Test for Schnorr

    Copyright:
        Copyright (c) 2020-2021 BOSAGORA Foundation
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

import * as crypto from "../lib";

import * as assert from 'assert';

describe ('Test of Schnorr', () =>
{
    it ('Single signature', () =>
    {
        let kp: crypto.Pair  = crypto.Pair.random();
        let signature = crypto.Schnorr.signPair<string>(kp, "Hello world");
        assert.ok(crypto.Schnorr.verify<string>(kp.V, signature, "Hello world"));
    });

    it ('Multi-signature', () =>
    {
        let secret = "BOSAGORA for the win";

        let kp1: crypto.Pair = crypto.Pair.random();
        let kp2: crypto.Pair = crypto.Pair.random();
        let R1: crypto.Pair = crypto.Pair.random();
        let R2: crypto.Pair = crypto.Pair.random();
        let R: crypto.Point = crypto.Point.add(R1.V, R2.V);
        let X: crypto.Point = crypto.Point.add(kp1.V, kp2.V);

        const sig1 = crypto.Schnorr.sign<string>(kp1.v, X, R1.v, R, secret);
        const sig2 = crypto.Schnorr.sign<string>(kp2.v, X, R2.v, R, secret);
        const sig3 = new crypto.Sig(R, crypto.Scalar.add(crypto.Sig.fromSignature(sig1).s, crypto.Sig.fromSignature(sig2).s)).toSignature();

        // No one can verify any of those individually
        assert.ok(!crypto.Schnorr.verify<string>(kp1.V, sig1, secret));
        assert.ok(!crypto.Schnorr.verify<string>(kp1.V, sig2, secret));
        assert.ok(!crypto.Schnorr.verify<string>(kp2.V, sig2, secret));
        assert.ok(!crypto.Schnorr.verify<string>(kp2.V, sig1, secret));
        assert.ok(!crypto.Schnorr.verify<string>(kp1.V, sig3, secret));
        assert.ok(!crypto.Schnorr.verify<string>(kp2.V, sig3, secret));

        // But multisig works
        assert.ok(crypto.Schnorr.verify<string>(X, sig3, secret));
    });

    it ('Test constructing Pair from scalar', () =>
    {
        let s: crypto.Scalar = crypto.Scalar.random();
        let pair1 = new crypto.Pair(s, s.toPoint());
        let pair2 = crypto.Pair.fromScalar(s);
        assert.deepStrictEqual(pair1, pair2);
    });

    it ('Valid signing test with valid scalar', () =>
    {
        let kp: crypto.Pair = crypto.Pair.fromScalar(new crypto.Scalar(`0x074360d5eab8e888df07d862c4fc845ebd10b6a6c530919d66221219bba50216`));
        let message = "Bosagora:-)";
        let signature = crypto.Schnorr.signPair<string>(kp, message);
        assert.ok(crypto.Schnorr.verify<string>(kp.V, signature, message));
    });

    it ('Valid with scalar value 1', () =>
    {
        let kp: crypto.Pair = crypto.Pair.fromScalar(new crypto.Scalar(`0x0000000000000000000000000000000000000000000000000000000000000001`));
        let message = "Bosagora:-)";
        let signature = crypto.Schnorr.signPair<string>(kp, message);
        assert.ok(crypto.Schnorr.verify<string>(kp.V, signature, message));
    });

    it ('Largest value for Scalar', () =>
    {
        // One less than Ed25519 prime order l where l=2^252 + 27742317777372353535851937790883648493
        let kp: crypto.Pair = crypto.Pair.fromScalar(new crypto.Scalar(`0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ec`));
        let message = "Bosagora:-)";
        let signature = crypto.Schnorr.signPair<string>(kp, message);
        assert.ok(crypto.Schnorr.verify<string>(kp.V, signature, message));
    });

    it ('Not valid with blank signature', () =>
    {
        let kp: crypto.Pair = crypto.Pair.fromScalar(new crypto.Scalar(`0x074360d5eab8e888df07d862c4fc845ebd10b6a6c530919d66221219bba50216`));
        let message = "Bosagora:-)";
        let signature = new crypto.Signature(Buffer.alloc(crypto.Signature.Width))
        assert.ok(!crypto.Schnorr.verify<string>(kp.V, signature, message));
    });

    it ('Valid signing test', () =>
    {
        let secret = "BOSAGORA for the win";

        let kp1: crypto.Pair = crypto.Pair.random();
        let kp2: crypto.Pair = crypto.Pair.random();
        let sig1 = crypto.Schnorr.signPair<string>(kp1, secret);
        let sig2 = crypto.Schnorr.signPair<string>(kp2, secret);
        assert.ok(crypto.Schnorr.verify<string>(kp1.V, sig1, secret));
        assert.ok(!crypto.Schnorr.verify<string>(kp1.V, sig2, secret));
        assert.ok(crypto.Schnorr.verify<string>(kp2.V, sig2, secret));
        assert.ok(!crypto.Schnorr.verify<string>(kp2.V, sig1, secret));
    });

    it ('Invalid signing test with invalid Public Key Point X', () =>
    {
        let kp: crypto.Pair = crypto.Pair.fromScalar(new crypto.Scalar(`0x074360d5eab8e888df07d862c4fc845ebd10b6a6c530919d66221219bba50216`));
        let message = "Bosagora:-)";
        let signature = crypto.Schnorr.signPair<string>(kp, message);
        let invalid = new crypto.Point("0xab4f6f6e85b8d0d38f5d5798a4bdc4dd444c8909c8a5389d3bb209a18610511c");
        assert.ok(!crypto.Schnorr.verify<string>(invalid, signature, message));
    });

    it ('Invalid signing test with invalid Point R in Signature', () =>
    {
        let kp: crypto.Pair = crypto.Pair.fromScalar(new crypto.Scalar(`0x074360d5eab8e888df07d862c4fc845ebd10b6a6c530919d66221219bba50216`));
        let message = "Bosagora:-)";
        let signature = crypto.Schnorr.signPair<string>(kp, message);
        let invalid_sig: crypto.Signature =
            new crypto.Sig(
                new crypto.Point("0xab4f6f6e85b8d0d38f5d5798a4bdc4dd444c8909c8a5389d3bb209a18610511c"),
                crypto.Sig.fromSignature(signature).s
            ).toSignature();
        assert.ok(!crypto.Schnorr.verify<string>(kp.V, invalid_sig, message));
    });

    it ('Example of extracting the private key from an insecure signature scheme', () =>
    {
        let message = "BOSAGORA for the win";
        let kp: crypto.Pair = crypto.Pair.random();  // key-pair
        let c: crypto.Scalar = crypto.Scalar.fromHash(crypto.hashFull(message));  // challenge
        let s: crypto.Scalar = crypto.Scalar.mul(kp.v, c);  // signature

        // known public data of the node
        let K: crypto.Point = kp.V;

        // other nodes verify
        assert.deepStrictEqual(s.toPoint(), crypto.Point.scalarMul(c, K));

        // but the other node can also extract the private key!
        let stolen_key: crypto.Scalar = crypto.Scalar.mul(s, c.invert());
        assert.deepStrictEqual(stolen_key, kp.v);
    });

    it ('Possibly secure signature scheme (requires proving ownership of private key)', () =>
    {
        let message = "BOSAGORA for the win";
        let kp: crypto.Pair = crypto.Pair.random();  // key-pair
        let Rp: crypto.Pair = crypto.Pair.random();  // (R, r), the public and private nonce
        let c: crypto.Scalar = crypto.Scalar.fromHash(crypto.hashFull(message));  // challenge
        let s: crypto.Scalar = crypto.Scalar.add(Rp.v, crypto.Scalar.mul(kp.v, c));  // signature

        // known public data of the node
        let K: crypto.Point = kp.V;
        let R: crypto.Point = Rp.V;

        // other nodes verify
        assert.deepStrictEqual(s.toPoint(), crypto.Point.add(R, crypto.Point.scalarMul(c, K)));

        // other nodes cannot extract the private key, they don't know 'r'
        let stolen_key: crypto.Scalar = crypto.Scalar.mul(s, c.invert());
        assert.notDeepStrictEqual(stolen_key, kp.v);
    });

    // rogue-key attack
    // see: https://tlu.tarilabs.com/cryptography/digital_signatures/introduction_schnorr_signatures.html#key-cancellation-attack
    // see: https://blockstream.com/2018/01/23/en-musig-key-aggregation-schnorr-signatures/#:~:text=not%20secure.
    it ('rogue-key attack', () =>
    {
        let message = "BOSAGORA for the win";

        // alice
        const kp1 = crypto.Pair.random(); // key-pair
        const R1 = crypto.Pair.random();  // (R, r), the public and private nonce

        // bob
        const kp2 = crypto.Pair.random(); // ditto
        const R2 = crypto.Pair.random();  // ditto

        let R = crypto.Point.add(R1.V, R2.V);
        let X = crypto.Point.add(kp1.V, kp2.V);
        let c = crypto.Scalar.fromHash(crypto.hashFull(new crypto.Message(X, R, message)));  // challenge

        let s1 = crypto.Scalar.add(R1.v, crypto.Scalar.mul(kp1.v, c));
        let s2 = crypto.Scalar.add(R2.v, crypto.Scalar.mul(kp2.v, c));
        let multi_sig = crypto.Scalar.add(s1, s2);
        assert.deepStrictEqual(multi_sig.toPoint(), crypto.Point.add(R, crypto.Point.scalarMul(c, X)));

        // now assume that bob lied about his V and R during the co-operative phase.
        let bobV = crypto.Point.sub(kp2.V, kp1.V);
        let bobR = crypto.Point.sub(R2.V, R1.V);
        X = crypto.Point.add(kp1.V, bobV);
        R = crypto.Point.add(R1.V, bobR);
        c = crypto.Scalar.fromHash(crypto.hashFull(new crypto.Message(X, R, message)));

        // bob signed the message alone, without co-operation from alice. it passes!
        let bob_sig = crypto.Scalar.add(R2.v, crypto.Scalar.mul(c, kp2.v));
        assert.deepStrictEqual(bob_sig.toPoint(), crypto.Point.add(R, crypto.Point.scalarMul(c, X)));
    });

    // rogue-key attack, but using multi-sig
    it ('rogue-key attack, but using multi-sig', () =>
    {
        let message = "BOSAGORA for the win";

        let c = crypto.Scalar.fromHash(crypto.hashFull(message));  // challenge

        let kp_1 = crypto.Pair.random();  // key-pair
        let Rp_1 = crypto.Pair.random();  // (R, r), the public and private nonce
        let s_1 = crypto.Scalar.add(Rp_1.v, crypto.Scalar.mul(c, kp_1.v));  // signature

        let kp_2 = crypto.Pair.random();  // key-pair
        let Rp_2 = crypto.Pair.random();  // (R, r), the public and private nonce
        let s_2 = crypto.Scalar.add(Rp_2.v, crypto.Scalar.mul(c, kp_2.v));  // signature

        // known public data of the nodes
        let K_1 = kp_1.V;
        let R_1 = Rp_1.V;

        let K_2 = kp_2.V;
        let R_2 = Rp_2.V;

        // verification of individual signatures
        assert.deepStrictEqual(s_1.toPoint(), crypto.Point.add(R_1, crypto.Point.scalarMul(c, K_1)));
        assert.deepStrictEqual(s_2.toPoint(), crypto.Point.add(R_2, crypto.Point.scalarMul(c, K_2)));

        // "multi-sig" - collection of one or more signatures
        let sum_s = crypto.Scalar.add(s_1, s_2);
        assert.deepStrictEqual(sum_s.toPoint(),
            crypto.Point.add(
                crypto.Point.add(R_1, crypto.Point.scalarMul(c, K_1)),
                crypto.Point.add(R_2, crypto.Point.scalarMul(c, K_2))
            ));

        // Or the equivalent:
        assert.deepStrictEqual(sum_s.toPoint(),
            crypto.Point.add(
                crypto.Point.add(
                    crypto.Point.add(R_1, R_2),
                    crypto.Point.scalarMul(c, K_1),
                ),
                crypto.Point.scalarMul(c, K_2)
            ));
    });
});
