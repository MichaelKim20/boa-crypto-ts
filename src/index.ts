/*******************************************************************************

    This is the main file for exporting classes and functions provided
    by the BOA SDK.

    Copyright:
        Copyright (c) 2020-2021 BOSAGORA Foundation
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

export {
    crypto_core_ed25519_BYTES,
    crypto_core_ed25519_UNIFORMBYTES,
    crypto_core_ed25519_SCALARBYTES,
    crypto_core_ed25519_NONREDUCEDSCALARBYTES,
    crypto_core_ed25519_random,
    crypto_core_ed25519_from_uniform,
    crypto_core_ed25519_add,
    crypto_core_ed25519_sub,
    crypto_core_ed25519_is_valid_point,
    crypto_core_ed25519_scalar_random,
    crypto_core_ed25519_scalar_add,
    crypto_core_ed25519_scalar_sub,
    crypto_core_ed25519_scalar_negate,
    crypto_core_ed25519_scalar_complement,
    crypto_core_ed25519_scalar_mul,
    crypto_core_ed25519_scalar_invert,
    crypto_core_ed25519_scalar_reduce,
    crypto_core_ed25519_scalar_is_canonical,
    crypto_core_ed25519_is_valid_scalar,
    crypto_core_ed25519_is_valid_random_scalar,
    crypto_scalarmult_ed25519,
    crypto_scalarmult_ed25519_base,
    crypto_scalarmult_ed25519_base_noclamp,
    crypto_scalarmult_ed25519_noclamp,
    randombytes_buf,
    JSBIUtils
} from './modules/sodium';

export { BOASodium } from './wrap/BOASodium';