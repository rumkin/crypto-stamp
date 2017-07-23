'use strict';

const {
    fromBase64,
    toBase64,
    multiSha256,
    getHash,
} = require('./utils.js');

const {
    createKey,
    createSignature,
    verifySignature,
    getPublicKey,
} = require('./elliptic.js');

const VERSION = '0.5.0';
const FORCE_FACTOR = 1024;

exports.VERSION = VERSION;

exports.createStamp = createStamp;
exports.verifyStamp = verifyStamp;
exports.createKey = createKey;
exports.createSecret = createSecret;
exports.getPublicKey = getPublicKey;
exports.createHash = getHash;
exports.encodeToken = encodeToken;
exports.decodeToken = decodeToken;

const stampProps = [
    'date',
    'hash',
    'holders',
    'owner',
    'type',
];

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
 * @param  {object} key   EC Key
 * @return {cryptoStamp} Cryptostamp instance object.
 */
function createStamp({type, payload = {}, date, owner, holders}, ...args) {
    let [full, key] = args;

    if (args.length < 2) {
        key = args[0];
        full = true;
    }

    // Create hash data
    const payloadHash = getHash(payload);
    const stamp = {
        owner,
        holders,
        type,
        date,
        hash: payloadHash,
    };

    const checksum = getHash(stamp, stampProps);

    stamp.signature = createSignature(key, checksum);
    stamp.alg = 'eddsa';
    stamp.payload = payload;

    if (full) {
        stamp.publicKey = getPublicKey(key);
        stamp.checksum = getHash(stamp, stampProps);
    }

    return stamp;
}

/**
 * Verify Cryptostamp instance.
 * @param  {object} stamp Cryptostamp
 * @param  {string|Buffer} publicKey   Stamp public key.
 * @return {bool} Returns true if value is verified.
 */
function verifyStamp(stamp, publicKey) {
    if (stamp.alg !== 'eddsa') {
        return false;
    }

    if ('payload' in stamp) {
        const hash = getHash(stamp.payload);
        if (hash !== stamp.hash) {
            return false;
        }
    }

    return verifySignature(publicKey, getHash(stamp, stampProps), stamp.signature);
}

/**
 * Parse base64 envelope.
 *
 * @param {object} head Base64 envelope head
 * @param {object} body Base64 envelope body
 * @param {Buffer|string} Public key
 * @param {Buffer|string} Secret key
 * @return {string} Base64 envelope
 */
function encodeToken(body) {
    const head = {type: 'cryptostamp', ver: VERSION};

    return toBase64(JSON.stringify(head)) + '.' + toBase64(JSON.stringify(body));
}

/**
 * Parse base64 envelope.
 *
 * @param {string} token Base64 envelope
 * @return {CryptoStamp} Crypto stamp instance
 */
function decodeToken(token) {
    let [head, body] = token.split('.');

    try {
        head = JSON.parse(fromBase64(head))
    }
    catch(err) {
        throw new Error('Token\'s head JSON parsing error');
    }

    try {
        body = JSON.parse(fromBase64(body))
    }
    catch(err) {
        throw new Error('Token\'s body JSON parsing error');
    }

    if (head.type !== 'cryptostamp') {
        throw new Error('Not a cryptostamp token');
    }

    // Convert date from string
    body.date = new Date(body.date);

    return body;
}

// Helpers

/**
 * Create 32 bytes secret from password, with specified force factor
 *
 * @param  {string} password Password
 * @param  {number} forceFactor Ciclec of password recalculation.
 * @return {ed25519.keyPair} Keypair
 */
function createSecret(password, forceFactor = FORCE_FACTOR) {
    if (typeof password !== 'string') {
        throw new Error('Argument #1 hould be a String');
    }

    if (typeof forceFactor !== 'number') {
        throw new Error('Argument #2 hould be a Number');
    }

    return multiSha256(password, forceFactor);
}

class Stamper {
    /**
     * @constructor
     * @param {{owner, key}} options Crypto stamper options object. Contains default values
     */
    constructor(options = {}) {
        if (options.owner) {
            this.setOwner(options.owner);
        }

        if (options.key) {
            this.setKey(options.key);
        }
    }

    /**
     * Set public and private keys
     *
     * @param {Buffer|string|{publicKey,secretKey} Public key buffer or keypair object.
     * @param {Buffer|string} Secret key
     * @return {this}
     */
    setKey(key) {
        this.key = key;

        return this;
    }

    /**
     * Set default owner
     *
     * @param {string} owner Owner name
     * @return {this}
     */
    setOwner(owner) {
        this.owner = owner;
        return this;
    }

    /**
     * Create crypto stamp object
     *
     * @param {object} {} Object with properties: action, params, date, owner, holder
     * @returns {object} CryptoStamp object.
     */
    stamp({type, payload = {}, date = new Date(), owner = this.owner, holders}) {
        if (! this.key) {
            throw new Error('Keys not set');
        }

        const stamp = createStamp({type, payload, date, owner, holders}, this.key);

        if (! this.debug) {
            delete stamp.checksum;
        }

        return stamp;
    }

    /**
     * Verify cryptostamp object or token.
     *
     * @param {object|string} stamp Verify base64 envlope token or stamp object.
     * @returns {boolean} Return true if signature is valid.
     */
    verify(stamp) {
        if (typeof stamp === 'string') {
            stamp = decodeToken(stamp);
        }

        return verifyStamp(stamp, getPublicKey(this.key));
    }

    /**
     * Parse base64 envelope.
     *
     * @param {object} head Base64 envelope head
     * @param {object} body Base64 envelope body
     * @return {string} Base64 envelope
     */
    token(body) {
        return encodeToken(body);
    }
}

exports.Stamper = Stamper;
