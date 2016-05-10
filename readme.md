# Crypto Stamp

Library for generating and verifying cryptography stamps based on ed25519
elliptic curves and sha256 hashes.

## Installation

Install with npm

```shell
npm i crypto-stamp
```

## Usage

Usage example from test code:

```javascript
var key = cryptoStamp.createKey('user', '1234567890');

// Create crypto stamp
var stamp = cryptoStamp.generate({
    action: 'auth',
    signer: 'user@host',
    date: new Date('0000-00-00T00:00:00.000+00:00'),
    holders: ['host1'],
}, key.publicKey, key.secretKey);

// Verify stamp content and signature
cryptoStamp.verify(stamp, key.publicKey);
```

## Stamp

Each stamp authorize one action at a time from one signer to
one or more holders. Params is an action arguments specific
for custom method.

```javascript
{
	// Stamp action type
	"action": "auth",
	// Stamp data (optional)
	"params": {},
	// Date of creation
	"date": "0000-00-00T00:00:00.000+00:00",
	// Stamp owner
	"signer": "user@host0",
	// Stamp holders
	"holders": ["host1", "host2", "user@host3"],
    // Signature human readable description. Optional
    "description": "Authentication token",
	// Sha256 hash from "params"
	"hash": "...hash...",
	// Ed25519 signature of Sha256(action, hash, signer, holders and date)
	"signature": "...signature..."
}
```

## Specification

| Param       | Type     | Description                                                                                                                  |
|:------------|:---------|:-----------------------------------------------------------------------------------------------------------------------------|
| action      | String   | Action name. For example "auth" or "accept"                                                                                  |
| params      | *        | **Optional**. Action params. Could be any type. Differs for each action. Could be deleted from signature for security reason |
| date        | String   | Date string in ISO 8601                                                                                                      |
| signer      | String   | Signer URI (username and host): "user@localhost"                                                                             |
| holders     | String[] | Holders is an array of signature receivers URIs                                                                              |
| description | String   | **Optional**. Textual representation of signature content                                                                    |
| hash        | String   | Sha256 hash from params                                                                                                      |
| signature   | String   | ed25519 signature of hash from stamp data as hex string                                                                      |

### Hash

Hash is a Sha256 hash sum from params converted to JSON string.

### Signature

Signature is a Sha256 hash from JSON string of object with properties:

* action
* date
* signer
* holders
* hash (hex string)
