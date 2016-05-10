'use strict';

const crypto = require('crypto');
const ed25519 = require('ed25519-supercop');

exports.generate = generate;
exports.verify = verify;
exports.createKey = createKey;

function generate({action, params, date = new Date, signer, holders}, pub, secret) {
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

    return {
        action,
        date,
        signer,
        holders,
        signature: signature.toString('hex'),
        hash: hash.toString('hex'),
    };
}

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

function getHash(data) {
    return sha256(JSON.stringify(normalize(data)));
}

function sha256(value) {
    var hash = crypto.createHash('sha256');

    hash.update(value);

    return hash.digest();
}

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
