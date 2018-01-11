const keccak = require('keccak');
const normjson = require('normjson');

exports.toBase64 = toBase64;
exports.fromBase64 = fromBase64;
exports.getHash = getHash;
exports.normjson = normjson;
exports.hash = hash;

/**
 * Converts string encoded as utf8 into base64 url.
 *
 * @param {string} str String in utf8
 * @returns {string} String in base64 url
 */
function toBase64(str) {
    return Buffer.from(str)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
 }

/**
 * Converts string encoded as base64 url into utf8 string.
 *
 * @param {string} str String in base64 url
 * @returns {string} String in utf8
 */
function fromBase64(str) {
    const val = str.replace(/-/g, '+').replace(/_/g, '/');

    return Buffer.from(val, 'base64')
    .toString('utf8');
}

/**
 * Gets hash from json stringified normalized value.
 *
 * @param  {object|string|buffer} data Any type of data.
 * @returns {Buffer}      Sha256 hash buffer.
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
 * Converts value to sha256 hash.
 *
 * @param  {string} value Value to generate hash.
 * @returns {buffer}       Hash generation result.
 */
function hash(value) {
    var hash = keccak('keccak256');

    hash.update(value);

    return hash.digest();
}
