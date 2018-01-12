'use strict';

const {
    fromBase64,
    toBase64,
    getHash,
} = require('./utils.js');

const {
    createKey,
    createSignature,
    verifySignature,
    getPublicKey,
} = require('./elliptic.js');

const VERSION = '1.2.0';

exports.VERSION = VERSION;

exports.createStamp = createStamp;
exports.verifyStamp = verifyStamp;
exports.createKey = createKey;
exports.getPublicKey = getPublicKey;
exports.createHash = getHash;
exports.encodeToken = encodeToken;
exports.decodeToken = decodeToken;

const stampProps = [
    'date',
    'hash',
    'holders',
    'signer',
    'type',
];

/**
 * @type cryptoStampParams
 *
 * @prop {string} type Stamp action type
 * @prop {object} [payload] Params data
 * @prop {Date} [date] Date
 * @prop {string} [signer] Signer URI
 * @prop {string[]} [holders] Holders URIs
 */

/**
 * @type cryptoStamp
 *
 * @prop {string} type Stamp action type
 * @prop {string} hash Hash from type, hash(payload), date, holders and signer.
 * @prop {Date} date Date
 * @prop {string} signer Signer URI
 * @prop {string[]} holders Holders URIs
 * @prop {string} [publicKey] Signer public key.
 * @prop {string} [checksum] Hash from payload.
 */

/**
 * @type Key
 *
 * @prop {object} publicKey Key's public part.
 * @prop {object} privateKey Key's secret part.
 */

/**
 * Generates crytostamp object from data and key.
 *
 * @param  {cryptoStampParams} options Cryptostamp data.
 * @param  {object} key   EC Key
 * @returns {cryptoStamp} Cryptostamp instance object.
 */
function createStamp({type, payload = {}, date, signer, holders}, ...args) {
    let [full, key] = args;

    if (args.length < 2) {
        key = args[0];
        full = true;
    }

    // Create hash data
    const hash = getHash(payload).toString('hex');
    const stamp = {
        signer,
        holders,
        type,
        date,
        hash,
    };

    const checksum = getHash(stamp, stampProps).toString('hex');

    stamp.signature = createSignature(key, checksum);
    stamp.alg = 'eddsa';
    stamp.payload = payload;

    if (full) {
        stamp.publicKey = getPublicKey(key);
        stamp.checksum = checksum;
    }

    return stamp;
}

/**
 * Verifies Cryptostamp instance.
 *
 * @param  {object} stamp Cryptostamp
 * @param  {string|Buffer} publicKey   Stamp public key.
 * @returns {bool} Returns true if value is verified.
 */
function verifyStamp(stamp, publicKey) {
    if (stamp.alg !== 'eddsa') {
        return false;
    }

    if ('payload' in stamp) {
        const hash = getHash(stamp.payload).toString('hex');
        if (hash !== stamp.hash) {
            return false;
        }
    }

    return verifySignature(
        publicKey, getHash(stamp, stampProps).toString('hex'), stamp.signature
    );
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

class Stamper {
    /**
     *
     *
     * @constructor
     * @param {{signer:string, key:Key}} options Crypto stamper options object
     *                                           Contains default values.
     */
    constructor(options = {}) {
        if (options.signer) {
            this.setSigner(options.signer);
        }

        if (options.key) {
            this.setKey(options.key);
        }
    }

    /**
     * setKey sets public and private keys.
     *
     * @param {Buffer|string|Key} Public key buffer or keypair object.
     * @param {Buffer|string} Secret key
     * @returns {this}
     */
    setKey(key) {
        this.key = key;

        return this;
    }

    /**
     * Set default signer.
     *
     * @param {string} signer Signer name
     * @returns {this}
     */
    setSigner(signer) {
        this.signer = signer;
        return this;
    }

    /**
     * Creates crypto stamp object.
     *
     * @param {cryptoStampParams} {} Crypto stamp params object.
     * @returns {cryptoStamp} CryptoStamp object.
     */
    stamp({type, payload = {}, date = new Date(), signer = this.signer, holders}) {
        if (! this.key) {
            throw new Error('Keys not set');
        }

        const stamp = createStamp({type, payload, date, signer, holders}, this.key);

        if (! this.debug) {
            delete stamp.checksum;
        }

        return stamp;
    }

    /**
     * Verifies cryptostamp object or token.
     *
     * @param {cryptoStamp|string} stamp Verify base64 envelope token or stamp object.
     * @returns {boolean} Return true if signature is valid.
     */
    verify(stamp) {
        if (typeof stamp === 'string') {
            stamp = decodeToken(stamp);
        }

        return verifyStamp(stamp, getPublicKey(this.key));
    }


    /**
     * token - Creates a base64-token from cryptostamp object.
     *
     * @param {cryptoStamp} stamp Crypto stamp object
     *
     * @returns {string} base64 encoded token.
     */
    token(stamp) {
        return encodeToken(stamp);
    }
}

exports.Stamper = Stamper;
