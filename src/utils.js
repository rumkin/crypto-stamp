const sha3 = require("js-sha3").sha3_256;
const normjson = require('normjson');

exports.toBase64 = toBase64;
exports.fromBase64 = fromBase64;
exports.getHash = getHash;
exports.normjson = normjson;
exports.hash = hash;
exports.toHex = toHex;

/**
 * toBase64 - Converts string encoded as utf8 into base64 url.
 *
 * @param {String} str String in utf8
 * @returns {String} String in base64 url
 */
function toBase64(str) {
    return Buffer.from(str)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
 }

/**
 * fromBase64 - Converts string encoded as base64 url into utf8 string.
 *
 * @param {String} str String in base64 url
 * @returns {String} String in utf8
 */
function fromBase64(str) {
    const val = str.replace(/-/g, '+').replace(/_/g, '/');

    return Buffer.from(val, 'base64')
    .toString('utf8');
}

/**
 * getHash - Gets hash from json stringified normalized value.
 *
 * @param  {Object|String|Buffer} data Any type of data.
 * @returns {Buffer}      Sha3-256 hash buffer.
 */
function getHash(data, schema) {
    if (typeof data === 'object') {
        return hash(
            normjson(data, schema)
        );
    }

    return hash(data);
}

/**
 * hash - Converts string value to hash.
 *
 * @param  {String} value Value to generate hash.
 * @returns {Buffer}      Hash generation result.
 */
function hash(value) {
    return sha3Hash(value);
}

/**
 * sha3Hash - Converts value to sha3-256 hash.
 *
 * @param  {String} value Value to generate hash.
 * @returns {Buffer}       Hash generation result.
 */
function sha3Hash(value) {
    const hash = sha3.create();

    const prefix = new DataView(new ArrayBuffer(4));

    prefix.setUint32(0, value.length);

    hash.update(prefix.buffer);
    hash.update(value);

    return new Uint8Array(hash.arrayBuffer(), 0, 32);
}


/**
 * toHex - Converts Uin8Array to hex string.
 *
 * @param  {Uint8Array} value Uint8Array with values
 * @return {String}       Hex encoded string
 */
function toHex(value) {
    if (value instanceof Uint8Array === false) {
        throw new Error('Argument #1 is not an Uint8Array');
    }

    const result = new Array(value.length);

    value.forEach((char, i) => {
        result[i] = char.toString(16).padStart(2, '0');
    });

    return result.join('');
}
