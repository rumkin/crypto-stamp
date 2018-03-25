const cryptoStamp = require('..');
const should = require('should');

const {
    VERSION,
    createStamp,
    verifyStamp,
    encodeToken,
    decodeToken,
    createHash,
} = cryptoStamp;

const meta = require('../package.json');

const {
    Signer,
    Verifier,
} = require('../example/ed25519.js');

describe('CryptoStamp', function () {
    describe('Version', function() {
        it('should match with package.json#version', function() {
            should(meta.version).be.equal(VERSION);
        });
    });

    describe('createStamp()', function() {
        it('Should verify token', function () {
            const signer = new Signer({
                secret: Buffer.alloc(32),
            });

            const verifier = new Verifier();

            return createStamp({
                type: 'auth',
                date: new Date('1970-01-01T00:00:00.000+00:00'),
                holders: ['host1'],
            }, signer)
            .then(function (stamp) {
                const token = encodeToken(stamp);

                return verifyStamp(decodeToken(token), verifier);
            })
            .then(function (result) {
                should(result).be.True();
            });
        });

        it('Should not verify unknown algorithm', function ()  {
            const signer = new Signer({
                secret: Buffer.alloc(32),
            });

            const verifier = new Verifier();

            return createStamp({
                type: 'auth',
                date: new Date('1970-01-01T00:00:00.000+00:00'),
                holders: ['host1'],
            }, signer)
            .then(function (stamp) {
                stamp.stamp.alg = 'rsa';

                return verifyStamp(stamp, verifier);
            })
            .then(function (result) {
                should(result).be.false();
            });
        });

        it('should create encoded token', function() {
            const signer = new Signer({
                secret: Buffer.alloc(32),
            });

            const verifier = new Verifier();

            return createStamp({
                type: 'auth',
                date: new Date('1970-01-01T00:00:00.000+00:00'),
                holders: ['host1'],
            }, signer)
            .then(function (stamp) {
                should(stamp).be.deepEqual(decodeToken(encodeToken(stamp)));
            });

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
