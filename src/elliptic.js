'use strict';

const elliptic = require('elliptic');
const ec = new elliptic.eddsa('ed25519');

exports.verifySignature = verifySignature;
exports.createSignature = createSignature;
exports.createKey = createKey;
exports.getPublicKey = getPublicKey;

function verifySignature(publicKey, origin, signature) {
    return ec.verify(origin, signature, publicKey);
}

function createSignature(key, origin) {
    return key.sign(origin).toHex().toLowerCase();
}

/**
 * Create ed25519 key from username and password
 *
 * @param  {string} password Create key from password
 */
function createKey(secret) {
    return ec.keyFromSecret(secret);
}

function getPublicKey(key) {
    return key.getPublic('hex').toLowerCase();
}
