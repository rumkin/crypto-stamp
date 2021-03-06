# Crypto Stamp

[![npm](https://img.shields.io/npm/v/crypto-stamp.svg?style=flat-square)](https://npmjs.com/packages/crypto-stamp)
[![Travis](https://img.shields.io/travis/rumkin/crypto-stamp.svg?style=flat-square)](https://travis-ci.org/rumkin/crypto-stamp)
![](https://img.shields.io/badge/coverage-100%25-green.svg?style=flat-square)
![](https://img.shields.io/badge/source-5.2%20KiB-blue.svg?style=flat-square)
[![npm](https://img.shields.io/npm/dw/crypto-stamp.svg?style=flat-square)](https://npmjs.com/packages/crypto-stamp)


Web-ready format and library for signing and verifying asynchronous
cryptography signatures. It can be used for authorization and document verification
in web pages and web services. It designed to be replay and length expansion
attacks resistant.

## Installation

Install with npm:

```shell
npm i crypto-stamp
```

## Usage

Example of creation, signing and verification stamp with `ed25519` custom
stamp signer and verifier.

```javascript
// Require CryptoStamp methods
const {createStamp, verifyStamp} = require('crypto-stamp');
// Require custom CryptoStamp encryption library for example ed25519
const {Signer, Verifier} = require('./crypto-stamp/ed25519');

// Signature generation item
const signer = new Signer({
    secret: Buffer.alloc(32), // Provide secret key
});

// Signature verification item
const verifier = new Verifier();

// Stamp data
const stampData = {
    type: 'auth',
    date: new Date('1970-01-01T00:00:00.000+00:00'),
    holders: ['cryptodoc.org'],
};

// Generate stamp
const stamp = await createStamp(stampData, signer);

// Verify stamp
if (await verifyStamp(stamp, verifier)) {
    // Stamp is valid. Yaeee!
}
```

Stamp can be used like a WebToken with `encodeToken` and `decodeToken` methods.

## Stamp

Each stamp authorize action with `type` and custom params `payload`
at a time as `date` to unlimited or several `holders`.

```javascript
{
    // Stamp action type. Name or URI.
    type: 'auth',
    // Stamp data (optional)
    payload: {},
    // Date of creation
    date: '1970-01-01T00:00:00.000+00:00',
    // Stamp holders
    holders: ['cryptodoc.org', 'admin@cryptodoc.org'],
    // Stamp verification data
    stamp: {
        // Signature algorithm name or URI.
        alg: 'ed25519',
        // Signature of length prefixed SHA3-256 hash
        signature: '...signature...',
        // Public key is optional and algorithm dependent property
        publicKey: '...public key...',
    },
}
```

## API

### createStamp()

```text
(data:StampData, signer:StampSigner) -> Promise<Stamp,Error>
```

Method createsStamp converts StampData into deterministic length prefixed
hash and sign with Signature interface instance.

```javascript
const stamp = await verifyStamp(data, verifier)
```

### verifyStamp()
```text
(stamp:Stamp, verifier:StampVerifier) -> Promise<Boolean,Error>
```
Method verifyStamp converts StampData from `stamp` into deterministic
length prefixed hash and verify it with StampVerifier interface instance.

```javascript
const isValid = await verifyStamp(stamp, verifier)
```

### StampData Type
```text
{
    type: String,
    payload: Object,
    date: Date|Number,
    holders: String[],
}
```
Params for stamp creation.

### StampSignature Type
```text
{
    alg: String,
    signature: String|Object,
    signer: String?,
}
```

### Stamp Type
```text
{
    type: String,
    payload: Object,
    date: Date|Number,
    holders: String[],
    stamp: StampSignature
}
```
Stamp is StampData with StampSignature object.

### StampSigner Interface
```text
{
    sign(hash:Uint8Array|Buffer) -> Promise<Stamp,Error>
}
```

See example of ed25519 signer implementation in `example/ed25519.js`.

### StampVerifier Interface
```text
{
    verify(hash:Uint8Array|Buffer, StampSignature) -> Promise<Boolean,Error>
}
```

See example of ed25519 verifier implementation in `example/ed25519.js`.

### encodeToken()

```text
(stamp:Stamp) -> String
```
Convert base64 encoded web token string.

```javascript
encodeToken(stamp) // -> String
```

### decodeToken()
```text
(token:String) -> Stamp
```
Convert base64 encoded WebToken to Stamp object.

```javascript
decodeToken(token) // -> Stamp
```

### getHash()
```text
(value:Object, schema?:Object|Array|(() -> Object|Array)) -> Uint8Array
```

Return SHA3 hash from deterministic JSON string from JS `value`. Use `schema`
to select exact object properties with [normjson](https://npmjs.com/package/normjson).

> **NOTE** V8 doesn't sort object properties in
lexicographical order so two familiar objects with different properties order
will produce different JSON strings and thus different hashes.


##### Example

```javascript
toHex(getHash({a: 1, b: 2})); // -> '7ed7e7ed5657f00683c745c9decb1b985bdd634f68f9f07c68e70b9593637da6'
toHex(getHash({b: 2, a: 1})); // -> '7ed7e7ed5657f00683c745c9decb1b985bdd634f68f9f07c68e70b9593637da6'
```

### toHex()
```text
(array:Uint8Array) -> String
```

Receive Uint8Array and convert it to hex string.

## Spec

Data params.

| Param | Type | Description |
|:------|:-----|:------------|
| type | String | **Required**. Stamp type. For example "auth" or "accept". Could be complete URI |
| payload | Object | **Required**. Stamp data. Could be any type. Differs for each action. Could be deleted when stamp created. By default it's an empty object |
| date | String,Number | _Optional_. Date string in ISO 8601 format or unix timestamp |
| holders | String[] | _Optional_. Holders is an array of signature receivers URIs |

Stamp params

| Param | Type | Description |
|:------|:-----|:------------|
| alg | String | Signature algorithm |
| signature | String|Object | Signature itself. Usually hex string but depends on algorithm |
| signer | String | _Optional_. Signature authentication value URI, name, etc |
| ... | * | Multiple algorithm based params, for example `publicKey`. |

### Hash

Hash is a SHA3-256 digest from 32 Uint Big Endian prefix length of stamp data
and data converted to deterministic JSON string.

* type
* payload
* date
* holders

## LICENSE

MIT
