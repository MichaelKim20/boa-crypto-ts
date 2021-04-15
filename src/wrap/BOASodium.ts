import { IBOASodium } from "boa-sodium-base-ts";
import * as sodium from '../modules/sodium';
import * as nacl from 'tweetnacl-ts';
import * as xchacha from '@stablelib/xchacha20poly1305';

export class BOASodium implements IBOASodium
{
    public crypto_core_ed25519_BYTES: number = 32;
    public crypto_core_ed25519_UNIFORMBYTES: number = 32;
    public crypto_core_ed25519_SCALARBYTES: number = 32;
    public crypto_core_ed25519_NONREDUCEDSCALARBYTES: number = 64;
    public crypto_aead_xchacha20poly1305_ietf_KEYBYTES: number = 32;
    public crypto_aead_xchacha20poly1305_ietf_NPUBBYTES: number = 24;

    public init (): Promise<IBOASodium>
    {
        return new Promise<IBOASodium>((resolve) =>
        {
            return resolve(this);
        });
    }

    public sodium (): IBOASodium
    {
        return this;
    }

    public crypto_core_ed25519_random(): Uint8Array
    {
        return sodium.crypto_core_ed25519_random();
    }

    public crypto_core_ed25519_from_uniform(r: Uint8Array): Uint8Array
    {
        return sodium.crypto_core_ed25519_from_uniform(r);
    }
    public crypto_core_ed25519_add(p: Uint8Array, q: Uint8Array): Uint8Array
    {
        return sodium.crypto_core_ed25519_add(p, q);
    }

    public crypto_core_ed25519_sub(p: Uint8Array, q: Uint8Array): Uint8Array
    {
        return sodium.crypto_core_ed25519_sub(p, q);
    }

    public crypto_core_ed25519_is_valid_point(p: Uint8Array): boolean
    {
        return sodium.crypto_core_ed25519_is_valid_point(p);
    }

    public crypto_core_ed25519_scalar_random(): Uint8Array
    {
        return sodium.crypto_core_ed25519_scalar_random();
    }

    public crypto_core_ed25519_scalar_add(x: Uint8Array, y: Uint8Array): Uint8Array
    {
        return sodium.crypto_core_ed25519_scalar_add(x, y);
    }

    public crypto_core_ed25519_scalar_sub(x: Uint8Array, y: Uint8Array): Uint8Array
    {
        return sodium.crypto_core_ed25519_scalar_sub(x, y);
    }

    public crypto_core_ed25519_scalar_negate(s: Uint8Array): Uint8Array
    {
        return sodium.crypto_core_ed25519_scalar_negate(s);
    }

    public crypto_core_ed25519_scalar_complement(s: Uint8Array): Uint8Array
    {
        return sodium.crypto_core_ed25519_scalar_complement(s);
    }

    public crypto_core_ed25519_scalar_mul(x: Uint8Array, y: Uint8Array): Uint8Array
    {
        return sodium.crypto_core_ed25519_scalar_mul(x, y);
    }

    public crypto_core_ed25519_scalar_invert(s: Uint8Array): Uint8Array
    {
        return sodium.crypto_core_ed25519_scalar_invert(s);
    }

    public crypto_core_ed25519_scalar_reduce(s: Uint8Array): Uint8Array
    {
        return sodium.crypto_core_ed25519_scalar_reduce(s);
    }

    public crypto_core_ed25519_scalar_is_canonical(s: Uint8Array): boolean
    {
        return sodium.crypto_core_ed25519_scalar_is_canonical(s);
    }

    public crypto_core_ed25519_is_valid_scalar(x: Uint8Array): boolean
    {
        return sodium.crypto_core_ed25519_is_valid_scalar(x);
    }

    public crypto_core_ed25519_is_valid_random_scalar(r: Uint8Array): boolean
    {
        return sodium.crypto_core_ed25519_is_valid_random_scalar(r);
    }

    public crypto_scalarmult_ed25519(n: Uint8Array, p: Uint8Array): Uint8Array
    {
        return sodium.crypto_scalarmult_ed25519(n, p);
    }

    public crypto_scalarmult_ed25519_base(n: Uint8Array): Uint8Array
    {
        return sodium.crypto_scalarmult_ed25519_base(n);
    }

    public crypto_scalarmult_ed25519_base_noclamp(n: Uint8Array): Uint8Array
    {
        return sodium.crypto_scalarmult_ed25519_base_noclamp(n);
    }

    public crypto_scalarmult_ed25519_noclamp(n: Uint8Array, p: Uint8Array): Uint8Array
    {
        return sodium.crypto_scalarmult_ed25519_noclamp(n, p);
    }


    public randombytes_buf(n: number): Uint8Array
    {
        return nacl.randomBytes(n);
    }

    public crypto_generichash(hash_length: number, message: Uint8Array, key?: Uint8Array): Uint8Array
    {
        return nacl.blake2b(message, key, hash_length);
    }

    public crypto_generichash_init(key: Uint8Array, hash_length: number): any
    {
        return nacl.blake2b_init(hash_length, key);
    }

    public crypto_generichash_update(state_address: any, message_chunk: Uint8Array): void
    {
        nacl.blake2b_update(state_address, message_chunk);
    }

    public crypto_generichash_final(state_address: any, hash_length: number): Uint8Array
    {
        return nacl.blake2b_final(state_address);
    }


    public crypto_aead_chacha20poly1305_ietf_keygen(): Uint8Array
    {
        return nacl.randomBytes(this.crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
    }

    public crypto_aead_xchacha20poly1305_ietf_encrypt(
        message: Uint8Array,
        additional_data: Uint8Array | null,
        secret_nonce: Uint8Array | null,
        public_nonce: Uint8Array,
        key: Uint8Array
    ): Uint8Array
    {
        const aead = new xchacha.XChaCha20Poly1305(key);

        let ad: Uint8Array | undefined;
        if (additional_data === null) ad = undefined;
        else ad = additional_data;

        let sn: Uint8Array | undefined;
        if (secret_nonce === null) sn = undefined;
        else sn = secret_nonce;

        return aead.seal(public_nonce, message, ad, sn);
    }

    public crypto_aead_xchacha20poly1305_ietf_decrypt(
        secret_nonce: Uint8Array | null,
        ciphertext: Uint8Array,
        additional_data: Uint8Array | null,
        public_nonce: Uint8Array,
        key: Uint8Array
    ): Uint8Array
    {
        const aead = new xchacha.XChaCha20Poly1305(key);

        let ad: Uint8Array | undefined;
        if (additional_data === null) ad = undefined;
        else ad = additional_data;

        let sn: Uint8Array | undefined;
        if (secret_nonce === null) sn = undefined;
        else sn = secret_nonce;

        let opened = aead.open(public_nonce, ciphertext, ad, sn);

        if (opened !== null)
            return opened;
        else
            return new Uint8Array(0);
    }
}
