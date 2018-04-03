const should = require('should');
const fs = require('fs');

const {
    VERSION,
    createStamp,
    verifyStamp,
    encodeToken,
    decodeToken,
} = require('..');

const {toBase64} = require('../src/utils');

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

    describe('Token', function() {
        let token;

        before(function() {
            token = fs.readFileSync(__dirname + '/token.txt', 'utf8').trim();
        });

        describe('encodeToken()', function() {
            it('Should encode token', function() {
                const signer = new Signer({
                    secret: Buffer.alloc(32),
                });

                return createStamp({
                    type: 'auth',
                    date: new Date('1970-01-01T00:00:00.000+00:00'),
                    holders: ['host1'],
                }, signer)
                .then(function (stamp) {
                    should(encodeToken(stamp)).be.equal(token);
                });
            });
        });

        describe('decodeToken()', function() {
            it('Should decode token', function() {
                const stamp = decodeToken(token);

                should(stamp).be.an.Object();
                should(stamp).has.ownProperty('type').which.is.equal('auth');
                should(stamp).has.ownProperty('date').which.is.instanceOf(Date);
            });

            it('Should throw when token header is not a base64 encoded JSON', function() {
                should.throws(() => {
                    decodeToken('NotAToken.AtAll');
                }, TypeError, /Token header JSON/);
            });

            it('Should throw when token header `type` is not equal "cryptostamp"', function() {
                const badToken = toBase64(JSON.stringify({type: 'x'})) + '.Something else';

                should.throws(() => {
                    decodeToken(badToken);
                }, TypeError, /Token header JSON/);
            });

            it('Should throw when token body is not a base64 encoded JSON', function() {
                const badToken = token.replace(/\..+$/, '.NotAJson');

                should.throws(() => {
                    decodeToken(badToken);
                }, TypeError, /Token header JSON/);
            });
        });
    });
});
