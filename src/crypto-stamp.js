/**
 * @module CryptoStamp
 * @description Crypto stamp generation functions and tools for web encoding.
 */
const pick = require('lodash.pick');

const {
    fromBase64,
    toBase64,
    getHash,
    toHex,
} = require('./utils.js');

const VERSION = '2.1.1';

exports.VERSION = VERSION;
exports.createStamp = createStamp;
exports.verifyStamp = verifyStamp;
exports.encodeToken = encodeToken;
exports.decodeToken = decodeToken;
exports.createHash = getHash;
exports.toHex = toHex;

const stampProps = [
    'date',
    'holders',
    'payload',
    'type',
];

/**
 * @typedef {Object} StampSignature
 *
 * @prop {String} alg Signature algorithm: eddsa, ethereum, etc.
 * @prop {String|Object} signature Stamp signature value.
 * @prop {String} [signer] Stamp owner URI: 0x020C9a094CA16d96359517E0Db9016fa70FF51aB@ethereum.org.
 * @prop {*} ... Custom propery set.
 */

/**
 * @typedef {Object} CryptoStamp
 *
 * @prop {String} type Stamp action type
 * @prop {Object} payload Stamp data
 * @prop {Date} date Date
 * @prop {String[]} holders Holders URIs
 * @prop {StampSignature} stamp Stamp signature object
 */

/**
 * Generates crytostamp object from data and key.
 *
 * @param  {CryptoStampParams} options Cryptostamp data.
 * @param  {Object} signer Signer instance.
 * @returns {Promise.<CryptoStamp>} Cryptostamp instance object.
 */
function createStamp({type, payload = {}, date, holders}, signer) {
    const envelope = {
        holders,
        type,
        date,
        payload,
    };

    const hash = getHash(envelope);

    return signer.sign(hash)
    .then(function (stamp) {
        return Object.assign(envelope, {stamp});
    });
}

/**
 * Verifies Cryptostamp instance.
 *
 * @param  {Object} stamp Cryptostamp
 * @param  {Verifier} verifier Stamp public key.
 * @returns {Promise.<Boolean>} Returns true if value is verified.
 */
function verifyStamp(stamp, verifier) {
    const hash = getHash(pick(stamp, stampProps));

    return verifier.verify(hash, stamp.stamp);
}

/**
 * Encode CryptoStamp object into LWT-like base64 envelope.
 *
 * @param {CryptoStamp} body Stamp object.
 * @returns {String} Base64 envelope
 */
function encodeToken(body) {
    const head = {type: 'cryptostamp', v: VERSION};

    return toBase64(JSON.stringify(head)) + '.' + toBase64(JSON.stringify(body));
}

/**
 * Parses JWT-like base64 envelope.
 *
 * @param {String} token Base64 envelope
 * @returns {CryptoStamp} Crypto stamp instance
 */
function decodeToken(token) {
    let [head, body] = token.split('.');

    try {
        head = JSON.parse(fromBase64(head));
    }
    catch (err) {
        throw new Error('Token\'s head JSON parsing error');
    }

    if (head.type !== 'cryptostamp') {
        throw new Error('Not a cryptostamp token');
    }

    try {
        body = JSON.parse(fromBase64(body));
    }
    catch (err) {
        throw new Error('Token\'s body JSON parsing error');
    }

    // Convert date from string
    body.date = new Date(body.date);

    return body;
}
