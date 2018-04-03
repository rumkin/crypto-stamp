const should = require('should');

const {toHex, createHash} = require('..');

describe('CryptoStamp.Utils', function() {
    describe('toHex()', function() {
        it('Should convert Uint8Array to string', function() {
            const array = new Uint8Array(2);
            array[0] = 0;
            array[1] = 255;

            should(toHex(array)).be.equal('00ff');
        });

        it('Should throw on non Uint8Array argument', function() {
            should.throws(
                () => toHex(true),
                Error,
                /^not an Uint8Array/
            );
        });
    });

    describe('createHash()', function() {
        const SHA_HASH = '8b0a2385d83c8bf7be27e59996f7d881d3bf1fc6606f81ce600b753ad94192a2';

        it('should match standart hash', function() {
            const hash = Buffer.from(createHash('')).toString('hex');

            should(hash).be.a.String();
            should(hash).be.equal(SHA_HASH);
        });
    });
});
