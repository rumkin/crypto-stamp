const crypto = require('crypto');
const normjson = require('normjson');

exports.toBase64 = toBase64;
exports.fromBase64 = fromBase64;
exports.getHash = getHash;
exports.normjson = normjson;
exports.sha256 = sha256;
exports.multiSha256 = multiSha256;

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
 * Get hash from json stringified normalized value.
 *
 * @param  {*} data Any type of data.
 * @return {Buffer}      Sha256 hash buffer.
 */
function getHash(data, schema) {
    if (typeof data !== 'string') {
        return sha256(normjson(data, schema));
    }

    return sha256(data);
}

/**
 * Repence dispercion multiple times.
 *
 * @param {Buffer} hash Source buffer to multiply.
 * @result {Buffer} Disperced buffer.
 **/
function multiSha256 (hash, n = 1) {
    let result = hash;
    for (let i = 0; i < n; i++) {
        result = sha256(result);
    }

    return result;
}

/**
 * Convert value to sha256 hash
 * @param  {string} value Value to generate hash.
 * @return {buffer}       Hash generation result.
 */
function sha256(value) {
    var hash = crypto.createHash('sha256');

    hash.update(value);

    return hash.digest().toString('hex');
}
