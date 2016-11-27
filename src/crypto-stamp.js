'use strict';

const crypto = require('crypto');
const ed25519 = require('ed25519-supercop');
const normjson = require('normjson');

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
// FIXME Enforce password generation or remove as unnecessary
function createKey(username, password) {
    return ed25519.createKeyPair(
        sha256(
            `${username}|${password}|${username.length + password.length}`
        )
    );
}

function createToken(stamp, publicKey, secretKey) {
    return toBase64(normjson({
        type: 'cryptostamp',
        ver: 0.3,
    })) + '.' + toBase64(normjson(createStamp(stamp, publicKey, secretKey)))
}

function parseToken(token) {
    let [head, stamp] = token.split('.').map(fromBase64).map((i) => JSON.parse(i));
    
    if (head.type !== 'cryptostamp') {
        throw new Error('Not a cryptostamp token');
    }
    
    return stamp;
}

function toBase64(str) {
  return Buffer.from(str)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

function fromBase64(str) {
  return Buffer.from(str
    .replace(/-/g, '+')
    .replace(/_/g, '/'),
    'base64').toString();
}

class Stamper {
    constructor(options = {}) {
        if (options.owner) {
            this.owner = options.owner;
        }
        
        if (options.key) {
            this.setKeys(options.key);
        }
    }
    
    setKeys(key, secret) {
        if (typeof key === 'object' && 'publicKey' in key) {
            this.publicKey = key.publicKey;
            this.secretKey = key.secretKey;
        }
        else {
            this.publicKey = key;
            this.secretKey = secret;
        }
    }
    
    setOwner(owner) {
        this.onwer = owner;
    }
    
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
    
    verify(stamp) {
        if (typeof stamp === 'string') {
            stamp = parseToken(stamp);
        }
        
        return verifyStamp(stamp, this.publicKey);
    }
    
    token(data) {
        return toBase64(normjson({type: 'cryptostamp', ver: 0.3})) + '.'
        + toBase64(normjson(this.stamp(data)));
    }
}

exports.Stamper = Stamper;