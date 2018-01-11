'use strict';

const elliptic = require('elliptic');
const ec = new elliptic.eddsa('ed25519');

exports.verifySignature = verifySignature;
exports.createSignature = createSignature;
exports.createKey = createKey;
exports.getPublicKey = getPublicKey;

/**
 * verifySignature - verify that `signature` is result of signing `origin`
 * message with `publicKey`.
 *
 * @param {string} publicKey Public key signed the `origin` as hex string.
 * @param {string} origin    Origin signed with `publicKey` as hex string.
 * @param {string} signature Signature of `origin` signed with `privateKey`
 *                           as hex sring.
 *
 * @returns {bool} Returns true if `signature` is result of signing `origin` with
 * `privateKey`.
 */
function verifySignature(publicKey, origin, signature) {
    return ec.verify(origin, signature, publicKey);
}

/**
 * createSignature - signs passed `origin` with the key's secret.
 *
 * @param {elliptic.Key} key Elliptic key instance.
 * @param {string} origin Data to sign.
 *
 * @returns {string} Signature.
 */
function createSignature(key, origin) {
    return key.sign(origin).toHex().toLowerCase();
}

/**
 * createKey - Creates ed25519 key from username and password
 *
 * @param  {string} password Create key from password
 */
function createKey(secret) {
    return ec.keyFromSecret(secret);
}

/**
  * getPublicKey - Extracts public key from elliptic.Key object and return
  * hexed version
  *
  * @param {elliptic.Key} key Elliptic key object
  * @return {string} Hex encoded public key
  */
function getPublicKey(key) {
    return key.getPublic('hex').toLowerCase();
}
