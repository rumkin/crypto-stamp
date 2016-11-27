# Crypto Stamp

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
var key = cryptoStamp.createKey('user', '1234567890');

// Create crypto stamp
var stamp = cryptoStamp.createStamp({
    action: 'auth',
    owner: 'user@host',
    date: new Date('1970-01-01T00:00:00.000+00:00'),
    holders: ['host1'],
}, key.publicKey, key.secretKey);

// Verify stamp content and signature
cryptoStamp.verifyStamp(stamp, key.publicKey);
```

Example with `Stamper` class:

```javascript
const cryptoStamp = require('crypto-stamp');

let stamper = new cryptoStamp.Stamper({
    owner: 'user@host',
    key: cryptoStamp.createKey('user', '*********'),
});

let stamp = stamper.stamp({
   action: 'auth',
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
	"action": "auth",
	// Stamp data (optional)
	"params": {},
	// Date of creation
	"date": "1970-01-01T00:00:00.000+00:00",
	// Stamp owner
	"owner": "user@host0",
	// Stamp holders
	"holders": ["host1", "host2", "user@host3"],
    // Signature human readable description. Optional
    "description": "Authentication token",
	// Sha256 hash from "params"
	"hash": "...hash...",
	// Signature algorithm. Eddsa is currently supported by default
	"alg": "eddsa",
	// Signature of Sha256(action, hash, owner, holders and date)
	"signature": "...signature...",
}
```

## Specification

| Param       | Type     | Description                                                                                                                  |
|:------------|:---------|:-----------------------------------------------------------------------------------------------------------------------------|
| action      | String   | Action name. For example "auth" or "accept"                                                                                  |
| params      | *        | **Optional**. Action params. Could be any type. Differs for each action. Could be deleted from signature for security reason |
| date        | String   | Date string in ISO 8601                                                                                                      |
| owner       | String   | **Optional**. Owner URI (username and host): "user@localhost"                                                                |
| holders     | String[] | **Optional**. Holders is an array of signature receivers URIs                                                                |
| description | String   | **Optional**. Textual representation of stamp content                                                                        |
| hash        | String   | Sha256 hash from params                                                                                                      |
| signature   | String   | ed25519 signature of hash from stamp data as hex string                                                                      |
| alg         | String   | Signature algorithm. `eddsa` by default.                                                                                   |

### Hash

Hash is a Sha256 hash sum from params converted to JSON string.

### Signature

Signature is a Sha256 hash from JSON string of object with properties:

* action
* date
* owner
* holders
* hash (hex string)
