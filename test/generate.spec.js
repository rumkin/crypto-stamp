const cryptoStamp = require('..');
const assert = require('assert');
const should = require('should');

const {
    createStamp,
    createKey,
    verifyStamp,
    encodeToken,
    decodeToken,
    getPublicKey,
    VERSION,
} = cryptoStamp;

describe('CryptoStamp.generate', function () {
    it('Should verify token', function ()  {
        var key = cryptoStamp.createKey(
            cryptoStamp.createHash('1234567890$#')
        );

        var stamp = cryptoStamp.createStamp({
            type: 'auth',
            signer: 'user@host',
            date: new Date('1970-01-01T00:00:00.000+00:00'),
            holders: ['host1'],
        }, key);

        const token = cryptoStamp.encodeToken(stamp);

        assert(cryptoStamp.verifyStamp(cryptoStamp.decodeToken(token), cryptoStamp.getPublicKey(key)), 'Signature verified');
    });

    it('Should not verify unknown algorithm', function ()  {
        var key = cryptoStamp.createKey(
            cryptoStamp.createHash('1234567890$#')
        );

        var stamp = cryptoStamp.createStamp({
            type: 'auth',
            signer: 'user@host',
            date: new Date('1970-01-01T00:00:00.000+00:00'),
            holders: ['host1'],
        }, key);

        stamp.alg = 'rsa';

        assert(! cryptoStamp.verifyStamp(stamp, key), 'Verify stamp return false');
    });

    it('should create encoded token', function() {
        var key = cryptoStamp.createKey(
            cryptoStamp.createHash('1234567890$#')
        );

        const data = {
            type: 'test',
            payload: {
                data: 'test',
            },
            signer: 'user@localhost',
            holders: ['localhost'],
            date: new Date(),
        };

        const stamp = createStamp(data, key);

        should(stamp).be.deepEqual(decodeToken(encodeToken(stamp)));
    });

    describe('Stamp instance', function ()  {
        it('Should verify stamp', function ()  {
            const stamper = new cryptoStamp.Stamper({
                signer: 'user@host',
                key: cryptoStamp.createKey(
                    cryptoStamp.createHash('1234567890$#')
                ),
            });

            const stamp = stamper.stamp({
               type: 'auth',
               payload: {},
               holders: ['host1'],
            });

            assert(stamper.verify(stamp), 'Signature is valid');
        });

        it('Should not verify changed stamp', function ()  {
            const stamper = new cryptoStamp.Stamper({
                signer: 'user@host',
                key: cryptoStamp.createKey(
                    cryptoStamp.createHash('1234567890$#')
                ),
            });

            const stamp = stamper.stamp({
               type: 'auth',
               payload: {
                   count: 1,
               },
               holders: ['host1'],
            });

            stamp.payload.count = 2;

            assert(! stamper.verify(stamp), 'Signature is valid');
        });

        it('Should verify token', function ()  {
            const stamper = new cryptoStamp.Stamper({
                signer: 'user@host',
                key: cryptoStamp.createKey(
                    cryptoStamp.createHash('1234567890$#')
                ),
            });

            const stamp = stamper.token(
                stamper.stamp({
                    type: 'auth',
                    payload: {},
                    holders: ['host1'],
                    date: new Date('1970-01-01T00:00:00.000+00:00'),
                })
            );

            assert(stamper.verify(stamp), 'Signature is valid');
        });

        it('Should generate custom token', function ()  {
            const stamper = new cryptoStamp.Stamper({
                signer: 'user@host',
                key: cryptoStamp.createKey(
                    cryptoStamp.createHash('1234567890$#')
                ),
            });

            const stamp = stamper.token(
                stamper.stamp({
                    type: 'auth',
                    payload: {},
                    holders: ['host1'],
                    date: new Date('1970-01-01T00:00:00.000+00:00'),
                })
            );

            assert(stamper.verify(stamp), 'Signature is valid');
        });
    });
});
