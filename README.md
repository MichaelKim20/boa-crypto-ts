# boa-crypto-ts
A library to perform cryptographic operations for the BOA blockchain. 
The library relies on libsodium for cryptographic primitives.
This ported from the C code in libsodium

The original files of libsodium : https://github.com/jedisct1/libsodium/blob/899c3a62b2860e81137830534311218b71f42f04/

## Install
```bash
$ npm install --save boa-crypto-ts
```

## Import the your library
```import * as crypto from "boa-crypto-ts";```

## Usage

TypeScript
```TypeScript
// Create Scalar and Point
let sclar = Buffer.from(crypto.crypto_core_ed25519_scalar_random());
let point = Buffer.from(crypto.crypto_scalarmult_ed25519_base_noclamp(sclar));
```

## Testing
```bash
$ git clone https://github.com/bosagora/boa-crypto-ts.git
$ npm install
$ npm run build
$ npm test
```
