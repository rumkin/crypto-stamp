const pick = require('lodash.pick');

const {
    fromBase64,
    toBase64,
    getHash,
    toHex,
} = require('./utils.js');

const VERSION = '2.0.1';

exports.VERSION = VERSION;
exports.createStamp = createStamp;
exports.verifyStamp = verifyStamp;
exports.createHash = getHash;
exports.encodeToken = encodeToken;
exports.decodeToken = decodeToken;

const stampProps = [
    'date',
    'holders',
    'payload',
    'type',
];

/**
 * @type Signature
 *
 * @prop {Stamp} alg Signature algorithm: eddsa, ethereum, etc
 * @prop {String} signer Stamp owner URI: 0x020C9a094CA16d96359517E0Db9016fa70FF51aB@ethereum.org
 * @prop {String} signature Stamp signature
 * @prop {*} ... Custom propery set.
 */

/**
 * @type cryptoStamp
 *
 * @prop {String} type Stamp action type
 * @prop {Object} payload Stamp data
 * @prop {Date} date Date
 * @prop {String[]} holders Holders URIs
 * @prop {Stamp} stamp Stamp object
 */

/**
 * Generates crytostamp object from data and key.
 *
 * @param  {CryptoStampParams} options Cryptostamp data.
 * @param  {Boolean} [complete]   Specify wether stamp should contain publicKey and checksum.
 * @param  {Object} key   EC Key
 * @returns {cryptoStamp} Cryptostamp instance object.
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
 * @param  {object} stamp Cryptostamp
 * @param  {string|Buffer} publicKey   Stamp public key.
 * @returns {bool} Returns true if value is verified.
 */
function verifyStamp(stamp, verifier) {
    const hash = getHash(pick(stamp, stampProps));

    return verifier.verify(hash, stamp.stamp);
}

/**
 * Parses base64 envelope.
 *
 * @param {object} head Base64 envelope head
 * @param {object} body Base64 envelope body
 * @param {Buffer|string} Public key
 * @param {Buffer|string} Secret key
 * @returns {string} Base64 envelope
 */
function encodeToken(body) {
    const head = {type: 'cryptostamp', ver: VERSION};

    return toBase64(JSON.stringify(head)) + '.' + toBase64(JSON.stringify(body));
}

/**
 * Parses base64 envelope.
 *
 * @param {string} token Base64 envelope
 * @returns {CryptoStamp} Crypto stamp instance
 */
function decodeToken(token) {
    let [head, body] = token.split('.');

    try {
        head = JSON.parse(fromBase64(head))
    }
    catch (err) {
        throw new Error('Token\'s head JSON parsing error');
    }

    try {
        body = JSON.parse(fromBase64(body))
    }
    catch (err) {
        throw new Error('Token\'s body JSON parsing error');
    }

    if (head.type !== 'cryptostamp') {
        throw new Error('Not a cryptostamp token');
    }

    // Convert date from string
    body.date = new Date(body.date);

    return body;
}
