const cryptoStamp = require('..');
const assert = require('assert');
const ed25519 = require('ed25519-supercop');

describe('CryptoStamp.generate', () => {
    it('Should generate and verify stamp', () => {
        var key = cryptoStamp.createKey('user', '1234567890');

        var stamp = cryptoStamp.createStamp({
            action: 'auth',
            owner: 'user@host',
            date: new Date('1970-01-01T00:00:00.000+00:00'),
            holders: ['host1'],
        }, key.publicKey, key.secretKey);

        assert.ok(cryptoStamp.verifyStamp(stamp, key.publicKey), 'Signature verified');
    });
    
    it('Should verify token', () => {
        var key = cryptoStamp.createKey('user', '1234567890');

        var stamp = cryptoStamp.createToken({
            action: 'auth',
            owner: 'user@host',
            date: new Date('1970-01-01T00:00:00.000+00:00'),
            holders: ['host1'],
        }, key.publicKey, key.secretKey);

        assert.ok(cryptoStamp.verifyStamp(cryptoStamp.parseToken(stamp), key.publicKey), 'Signature verified');
    });
    
    it('Should not verify unknown algorithm', () => {
        var key = cryptoStamp.createKey('user', '1234567890');

        var stamp = cryptoStamp.createStamp({
            action: 'auth',
            owner: 'user@host',
            date: new Date('1970-01-01T00:00:00.000+00:00'),
            holders: ['host1'],
        }, key.publicKey, key.secretKey);
    
        stamp.alg = 'rsa';
        
        assert.ok(! cryptoStamp.verifyStamp(stamp, key.publicKey), 'Verify stamp return false');
    });
    
    describe('Stamp instance', () => {
        it('Should verify stamp', () => {
            let stamper = new cryptoStamp.Stamper({
                owner: 'user@host',
                key: cryptoStamp.createKey('user', '*********'),
            });
            
            let stamp = stamper.stamp({
               action: 'auth',
               params: {},
               holders: ['host1'],
            });
            
            assert.ok(stamper.verify(stamp), 'Signature is valid'); 
        });
        
        it('Should not verify changed stamp', () => {
            let stamper = new cryptoStamp.Stamper({
                owner: 'user@host',
                key: cryptoStamp.createKey('user', '*********'),
            });
            
            let stamp = stamper.stamp({
               action: 'auth',
               params: {
                   count: 1,
               },
               holders: ['host1'],
            });
            
            stamp.params.count = 2;
            
            assert.ok(! stamper.verify(stamp), 'Signature is valid'); 
        });
        
        it('Should verify token', () => {
            let stamper = new cryptoStamp.Stamper({
                owner: 'user@host',
                key: cryptoStamp.createKey('user', '*********'),
            });
            
            let stamp = stamper.token({
               action: 'auth',
               params: {},
               holders: ['host1'],
            });
            
            assert.ok(stamper.verify(stamp), 'Signature is valid'); 
        });
        
        it('Should generate custom token', () => {
            let stamper = new cryptoStamp.Stamper({
                owner: 'user@host',
                key: cryptoStamp.createKey('user', '*********'),
            });
            
            let stamp = stamper.token({
                type: 'cryptostamp',
                version: 0.4,
            }, {
               action: 'auth',
               params: {},
               holders: ['host1'],
            });
            
            assert.ok(stamper.verify(stamp), 'Signature is valid'); 
        });
        
        it('Should throw on unknown token type', () => {
            let stamper = new cryptoStamp.Stamper({
                owner: 'user@host',
                key: cryptoStamp.createKey('user', '*********'),
            });
            
            let stamp = stamper.token({
                type: 'otherstamp',
                ver: 0.4,
            }, {
               action: 'auth',
               params: {},
               holders: ['host1'],
            });
            
            assert.throws(() => stamper.verify(stamp), 'Thows on `otherstamp` type'); 
        });
    });
});
