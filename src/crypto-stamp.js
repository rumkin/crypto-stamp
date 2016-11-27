'use strict';

const crypto = require('crypto');
const ed25519 = require('ed25519-supercop');
const normjson = require('normjson');
const FORCE_FACTOR = 1024;

exports.createStamp = createStamp;
exports.createToken = createToken;
exports.parseToken = parseToken;
exports.verifyStamp = verifyStamp;
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
function createStamp({action, params = {}, date, owner, holders}, pub, secret) {
    // Create hash data
    var hash = getHash(params);
    var stampHash = getHash({
        action,
        date,
        owner,
        holders,
        hash: hash.toString('hex'),
    });
    var signature = ed25519.sign(stampHash, pub, secret);

    var stamp = {
        action,
        date,
        alg: 'eddsa',
        signature: signature.toString('hex'),
        hash: hash.toString('hex'),
        stampHash: stampHash.toString('hex'),
        params,
    };

    if (owner) {
        stamp.owner = owner;
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
function verifyStamp(stamp, pub) {
    if (stamp.alg !== 'eddsa') {
        return false;
    }
    
    let hash;
    if ('params' in stamp) {
        hash = getHash(stamp.params);
        if (hash.toString('hex') !== stamp.hash) {
            return false;
        }
    }
    
    return ed25519.verify(stamp.signature,
    getHash({
        action: stamp.action,
        date: stamp.date,
        owner: stamp.owner,
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
    return sha256(normjson(data));
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
 * Create ed25519 key from username and password
 *
 * @param  {string} username Username
 * @param  {string} password Password
 * @return {ed25519.keyPair} Keypair
 */
function createKey(username, password, forceFactor = FORCE_FACTOR) {
    return ed25519.createKeyPair(
        multiply(
            sha256(`${username}:${password}`), forceFactor
        )
    );
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
function createToken(head, data, publicKey, secretKey) {
    if (arguments.length < 4) {
        secretKey = publicKey;
        publicKey = data;
        data = head;
        head = {type: 'cryptostamp', ver: 0.3};
    }
        
    return toBase64(normjson(head)) + '.'
        + toBase64(normjson(createStamp(data, publicKey, secretKey)))
}

/**
 * Parse base64 envelope.
 * 
 * @param {string} token Base64 envelope
 * @return {CryptoStamp} Crypto stamp instance
 */
function parseToken(token) {
    let [head, stamp] = token.split('.').map(fromBase64).map((i) => JSON.parse(i));
    
    if (head.type !== 'cryptostamp') {
        throw new Error('Not a cryptostamp token');
    }
    
    return stamp;
}

/**
 * Convert string encoded as utf8 into base64 url.
 * 
 * @param {string} str String in utf8
 * @return {string} String in base64 url
 */
function toBase64(str) {
  return Buffer.from(str)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/**
 * Convert string encoded as base64 url into utf8 string.
 * 
 * @param {string} str String in base64 url
 * @return {string} String in utf8
 */
function fromBase64(str) {
  return Buffer.from(str
    .replace(/-/g, '+')
    .replace(/_/g, '/'),
    'base64').toString();
}

/**
 * Get buffer and calculate summary hash from each byte in source buffer.
 * 
 * @params {Buffer} hash Source hash
 * @result {Buffer} Calculated desperced hash.
 */
function disperce(hash) {
    let buff = [];

    for(let i = 0; i < 32; i++) {
        buff.push(sha256(hash[i].toString(16)));
    }

    return sha256(Buffer.concat(buff));
}

/**
 * Repence dispercion multiple times.
 * 
 * @param {Buffer} hash Source buffer to multiply.
 * @result {Buffer} Disperced buffer.
 **/ 
function multiply (hash, n = 1) {
    let result = hash;
    for (let i = 0; i < n; i++) {
        result = disperce(result);
    }
    
    return result;
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
            this.setKeys(options.key);
        }
    }
    
    /**
     * Set public and private keys
     * 
     * @param {Buffer|string|{publicKey,secretKey} Public key buffer or keypair object.
     * @param {Buffer|string} Secret key
     * @return {this}
     */
    setKeys(key, secret) {
        if (typeof key === 'object' && 'publicKey' in key) {
            this.publicKey = key.publicKey;
            this.secretKey = key.secretKey;
        }
        else {
            this.publicKey = key;
            this.secretKey = secret;
        }
        
        return this;
    }
    
    /**
     * Set default owner
     * 
     * @param {string} owner Owner name
     * @return {this}
     */
    setOwner(owner) {
        this.onwer = owner;
        return this;
    }
    
    /**
     * Create crypto stamp object
     * 
     * @param {object} {} Object with properties: action, params, date, owner, holder
     * @returns {object} CryptoStamp object.
     */
    stamp({action, params = {}, date = new Date(), owner = this.owner, holders}) {
        if (! this.publicKey) {
            throw new Error('Keys not set');
        }
        
        let stamp = createStamp({action, params, date, owner, holders}, this.publicKey, this.secretKey);
        
        if (! this.debug) {
            delete stamp.stampHash;
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
            stamp = parseToken(stamp);
        }
        
        return verifyStamp(stamp, this.publicKey);
    }
    
    /**
     * Parse base64 envelope.
     * 
     * @param {object} head Base64 envelope head
     * @param {object} body Base64 envelope body
     * @return {string} Base64 envelope
     */
    token(head, data) {
        if (arguments.length < 2) {
            data = head;
            head = {type: 'cryptostamp', ver: 0.3};
        }
        
        return toBase64(normjson(head)) + '.'
        + toBase64(normjson(this.stamp(data)));
    }
}

exports.Stamper = Stamper;