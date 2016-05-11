'use strict';

const crypto = require('crypto');
const ed25519 = require('ed25519-supercop');

exports.generate = generate;
exports.verify = verify;
exports.createKey = createKey;

/**
 * @type cryptoStampData
 * @prop {string} action Action name
 * @prop {*} [params] Params data
 * @prop {Date} [date] Date
 * @prop {string} [signer] Signer URI
 * @prop {string[]} [holders] Holders URIs
 */

/**
 * Generate crytostamp object from data and key.
 *
 * @param  {cryptoStampData} options Cryptostamp data.
 * @param  {string|Buffer} pub   User public key.
 * @param  {string|Buffer} secret   User secret key.
 * @return {cryptoStamp} Cryptostamp instance object.
 */
function generate({action, params, date, signer, holders}, pub, secret) {
    // Create hash data
    var hash = getHash({
        action,
        params,
        date,
        signer,
        holders
    });

    var signature = ed25519.sign(getHash({
        action,
        date,
        signer,
        holders,
        hash: hash.toString('hex'),
    }), pub, secret);

    var stamp = {
        action,
        date,
        signature: signature.toString('hex'),
        hash: hash.toString('hex'),
    };

    if (signer) {
        stamp.signer = signer;
    }

    if (holders) {
        stamp.holders = holders;
    }

    return stamp;
}

/**
 * Verify Cryptostamp instance.
 * @param  {object} stamp Cryptostamp
 * @param  {string|Buffer} pub   Stamp public key.
 * @return {bool} Returns true if value is verified.
 */
function verify(stamp, pub) {
    return ed25519.verify(stamp.signature,
    getHash({
        action: stamp.action,
        date: stamp.date,
        signer: stamp.signer,
        holders: stamp.holders,
        hash: stamp.hash,
    }), pub);
}

/**
 * Get hash from json stringified normalized value.
 *
 * @param  {*} data Any type of data.
 * @return {Buffer}      Sha256 hash buffer.
 */
function getHash(data) {
    return sha256(JSON.stringify(normalize(data)));
}

/**
 * Convert value to sha256 hash
 * @param  {string} value Value to generate hash.
 * @return {buffer}       Hash generation result.
 */
function sha256(value) {
    var hash = crypto.createHash('sha256');

    hash.update(value);

    return hash.digest();
}

/**
 * Normalize value. If it is an object sort it keys.
 * @param  {*} target Value to normalize.
 * @return {*}        Normalized value. In most cases returns the value itself.
 */
function normalize(target) {
    if (target && typeof target === 'object' && ! Array.isArray(target)) {
        return Object.keys(target).sort().reduce((result, key) => {
            result[key] = normalize(target[key]);
            return result;
        }, {});
    } else {
        return target;
    }
}

/**
 * Create ed25519 key from username and password
 *
 * @param  {string} username Username
 * @param  {string} password Password
 * @return {ed25519.keyPair} Keypair
 */
function createKey(username, password) {
    return ed25519.createKeyPair(
        sha256(
            `${username}|${password}|${username.length + password.length}`
        )
    );
}
