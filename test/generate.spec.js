const cryptoStamp = require('..');
const assert = require('assert');
const ed25519 = require('ed25519-supercop');

describe('CryptoStamp.generate', () => {
    it('Should generate and verify stamp', () => {
        var key = cryptoStamp.createKey('user', '1234567890');

        var stamp = cryptoStamp.generate({
            action: 'auth',
            signer: 'user@host',
            date: new Date('1970-01-01T00:00:00.000+00:00'),
            holders: ['host1'],
        }, key.publicKey, key.secretKey);

        assert.ok(cryptoStamp.verify(stamp, key.publicKey), 'Signature verified');
    });
});
