/*******************************************************************************

    Test for ECC

    Copyright:
        Copyright (c) 2020-2021 BOSAGORA Foundation
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

import * as crypto from '../lib';

import * as assert from 'assert';

describe ('Test of ECC', () =>
{
    it ('Test Scalar fromString / toString functions', () =>
    {
        const s = "0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ec";
        let scalar = new crypto.Scalar(s);
        assert.strictEqual(scalar.toString(false), s);
    });

    it ('Test of Scalar.isValid() - valid', () =>
    {
        assert.ok(new crypto.Scalar("0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ec").isValid());
        assert.ok(new crypto.Scalar("0x0eadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef").isValid());
        assert.ok(new crypto.Scalar("0x0000000000000000000000000000000000000000000000000000000000000001").isValid());
    });

    it ('Test of Scalar.isValid() - invalid', () =>
    {
        assert.ok(!(new crypto.Scalar("0x0000000000000000000000000000000000000000000000000000000000000000")).isValid());
        assert.ok(!(new crypto.Scalar("0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed")).isValid());
        assert.ok(!(new crypto.Scalar("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")).isValid());
        assert.ok(!(new crypto.Scalar("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")).isValid());
    });

    it ('Test of Scalar.fromHash', () =>
    {
        let message = "BOSAGORA for the win";
        let c = crypto.Scalar.fromHash(crypto.hashFull(message));  // challenge
        assert.strictEqual(c.toString(false), "0x076f92828116e289bb7889b38d6acfa23f04291024c03dfb5265c23894613b18");
    });

    it ('Test of Scalar function', () =>
    {
        let s1: crypto.Scalar = crypto.Scalar.random();
        let s2: crypto.Scalar = crypto.Scalar.random();
        let s3: crypto.Scalar = crypto.Scalar.add(s1, s2);

        assert.deepStrictEqual(crypto.Scalar.sub(s3, s1), s2);
        assert.deepStrictEqual(crypto.Scalar.sub(s3, s2), s1);
        assert.ok(crypto.Scalar.sub(s3, s3).isNull());
        assert.deepStrictEqual(s3.negate(), crypto.Scalar.sub(s1.negate(), s2));
        assert.deepStrictEqual(s3.negate(), crypto.Scalar.sub(s2.negate(), s1));

        let Zero: crypto.Scalar = crypto.Scalar.add(s3, s3.negate());
        assert.ok(Zero.isNull());

        let One: crypto.Scalar =  crypto.Scalar.add(s3, s3.complement());
        assert.deepStrictEqual(crypto.Scalar.mul(One, One), One);

        assert.deepStrictEqual(crypto.Scalar.add(Zero, One), One);
        assert.deepStrictEqual(crypto.Scalar.add(One, Zero), One);

        let G: crypto.Point = One.toPoint();
        assert.deepStrictEqual(crypto.Point.add(G, G), crypto.Scalar.add(One, One).toPoint());

        let p1: crypto.Point = s1.toPoint();
        let p2: crypto.Point = s2.toPoint();
        let p3: crypto.Point = s3.toPoint();

        assert.deepStrictEqual(s1.toPoint(), p1);
        assert.deepStrictEqual(crypto.Point.sub(p3, p1), p2);
        assert.deepStrictEqual(crypto.Point.sub(p3, p2), p1);

        assert.deepStrictEqual(
            crypto.Point.add(
                crypto.Point.scalarMul(s1, p2),
                crypto.Point.scalarMul(s2, p2)
            ),
            crypto.Point.scalarMul(s3, p2));

        let pZero: crypto.Point = crypto.Point.Null;
        assert.deepStrictEqual(crypto.Point.add(pZero, G), G);
        assert.deepStrictEqual(crypto.Point.add(G, pZero), G);
    });

    it ('Test of Point.isValid() - valid', () =>
    {
        let valid = new crypto.Point("0xab4f6f6e85b8d0d38f5d5798a4bdc4dd444c8909c8a5389d3bb209a18610511b");
        assert.ok(valid.isValid());

        let invalid = new crypto.Point("0xab4f6f6e85b8d0d38f5d5798a4bdc4dd444c8909c8a5389d3bb209a18610511c");
        assert.ok(!invalid.isValid());

        let invalid2: crypto.Point = crypto.Point.Null;
        assert.ok(!invalid2.isValid());
    });
});
