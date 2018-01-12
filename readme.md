# Crypto Stamps

Library for generating and verifying cryptography stamps based on ed25519
elliptic curves and sha256 hashes.

## Installation

Install with npm

```shell
npm i crypto-stamp
```

## Usage

Example using pure functions:

```javascript
const key = cryptoStamp.createKey(
  cryptoStamp.createHash('...YourSecretValue...')
);

// Create crypto stamp
const stamp = cryptoStamp.createStamp({
  type: 'auth',
  signer: 'user@cryptodoc.org',
  date: new Date('1970-01-01T00:00:00.000+00:00'),
  holders: ['cryptodoc.org'],
}, key);

// Verify stamp content and signature
cryptoStamp.verifyStamp(stamp, key);
```

Example with `Stamper` class:

```javascript
const cryptoStamp = require('crypto-stamp');

const stamper = new cryptoStamp.Stamper({
  signer: 'user@cryptodoc.org',
  key: cryptoStamp.createKey(
    cryptoStamp.createHash('...YourSecretValue...'),
  ),
});

const stamp = stamper.stamp({
  type: 'auth',
  holders: ['cryptodoc.org'],
});

stamper.verify(stamp);
```

## Stamp

Each stamp authorize one action at a time from one signer to
one or more holders. Params is an action arguments specific
for custom method.

```javascript
{
  // Stamp action type
  "type": "auth",
  // Stamp data (optional)
  "payload": {},
  // Date of creation
  "date": "1970-01-01T00:00:00.000+00:00",
  // Stamp signer
  "signer": "user@cryptodoc.org",
  // Stamp holders
  "holders": ["cryptodoc.org", "localhost", "user@host3"],
  // Signature human readable description. Optional
  "description": "Authentication token",
  // SHA3-256 hash from "payload"
  "hash": "...hash...",
  // Signature algorithm. Eddsa is currently supported by default
  "alg": "eddsa",
  // Signature of SHA3-256 hash: `sha3(action, hash, signer, holders and date)``
  "signature": "...signature...",
  // Checksum (optional, includes in debug) SHA3-256 from type, signer, holders, date and hash
  "checksum": "...hash...",
}
```

## Specification

| Param       | Type     | Description                                                                                                                  |
|:------------|:---------|:-----------------------------------------------------------------------------------------------------------------------------|
| type        | String   | Stamp type. For example "auth" or "accept"                                                                                  |
| payload     | object        | Stamp data. Could be any type. Differs for each action. Could be deleted when stamp created. By default it's an empty object. |
| date        | String   | Date string in ISO 8601                                                                                                      |
| signer      | String   | **Optional**. Owner URI (username and host): "user@localhost" or username only.                                                                |
| holders     | String[] | **Optional**. Holders is an array of signature receivers URIs                                                                |
| description | String   | **Optional**. Textual representation of stamp content                                                                        |
| hash        | String   | SHA3-256 hash from payload                                                                                                      |
| signature   | String   | ed25519 signature of hash from stamp data
| alg         | String   | Signature algorithm. `eddsa` by default.                                                                                   |
| publicKey   | String   | Public key for signature verification.                                                                                   |

### Hash

Hash is a SHA3-256 hash sum from params converted to JSON string.

### Signature

Signature is a SHA3-256 (NIST) hash from normalized JSON string of object with properties:

* type
* date
* signer
* holders
* hash
