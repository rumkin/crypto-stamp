const ed = require('ed25519-supercop');

exports.verifySignature = verifySignature;
exports.createSignature = createSignature;
exports.createKey = createKey;
exports.getPublicKey = getPublicKey;

function verifySignature(publicKey, origin, signature) {
    return ed.verify(signature, origin, publicKey);
}

function createSignature(key, origin) {
    return ed.sign(origin, key.publicKey, key.secretKey).toString('hex');
}

/**
 * Create ed25519 key from username and password
 *
 * @param  {string} password Create key from password
 */
function createKey(secret) {
  return ed.createKeyPair(secret);
}

function getPublicKey(key) {
    return key.publicKey.toString('hex');
}
