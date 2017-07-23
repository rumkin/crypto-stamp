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
  cryptoStamp.createSecret('...SuperSecretPassword...')
);

// Create crypto stamp
const stamp = cryptoStamp.createStamp({
  type: 'auth',
  owner: 'user@host',
  date: new Date('1970-01-01T00:00:00.000+00:00'),
  holders: ['host1'],
}, key);

// Verify stamp content and signature
cryptoStamp.verifyStamp(stamp, key);
```

Example with `Stamper` class:

```javascript
const cryptoStamp = require('crypto-stamp');

const stamper = new cryptoStamp.Stamper({
  owner: 'user@host',
  key: cryptoStamp.createKey(
    cryptoStamp.createSecret('...SuperSecretPassword...'),
  ),
});

const stamp = stamper.stamp({
  type: 'auth',
  holders: ['host1'],
});

stamper.verify(stamp);
```

## Stamp

Each stamp authorize one action at a time from one owner to
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
  // Stamp owner
  "owner": "user@host0",
  // Stamp holders
  "holders": ["host1", "host2", "user@host3"],
  // Signature human readable description. Optional
  "description": "Authentication token",
  // Sha256 hash from "payload"
  "hash": "...hash...",
  // Signature algorithm. Eddsa is currently supported by default
  "alg": "eddsa",
  // Signature of Sha256(action, hash, owner, holders and date)
  "signature": "...signature...",
  // Checksum (optional, includes in debug) sha256 from type, owner, holders, date and hash
  "checksum": "...hash...",
}
```

## Specification

| Param       | Type     | Description                                                                                                                  |
|:------------|:---------|:-----------------------------------------------------------------------------------------------------------------------------|
| type        | String   | Stamp type. For example "auth" or "accept"                                                                                  |
| payload     | object        | Stamp data. Could be any type. Differs for each action. Could be deleted when stamp created. By default it's an empty object. |
| date        | String   | Date string in ISO 8601                                                                                                      |
| owner       | String   | **Optional**. Owner URI (username and host): "user@localhost" or username only.                                                                |
| holders     | String[] | **Optional**. Holders is an array of signature receivers URIs                                                                |
| description | String   | **Optional**. Textual representation of stamp content                                                                        |
| hash        | String   | Sha256 hash from payload                                                                                                      |
| signature   | String   | ed25519 signature of hash from stamp data
| alg         | String   | Signature algorithm. `eddsa` by default.                                                                                   |
| publicKey   | String   | Public key for signature verification.                                                                                   |

### Hash

Hash is a Sha256 hash sum from params converted to JSON string.

### Signature

Signature is a Sha256 hash from normalized JSON string of object with properties:

* type
* date
* owner
* holders
* hash
