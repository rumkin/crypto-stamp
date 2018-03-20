const elliptic = require('elliptic');
const ec = new elliptic.eddsa('ed25519');

class Signer {
    constructor({secret}) {
        this.key = ec.keyFromSecret(secret);
    }

    sign(hash) {
        return new Promise(function (resolve) {
            const signature = this.key.sign(hash);

            resolve({
                alg: 'ed25519',
                signer: this.key.getPublic('hex'),
                signature: signature.toHex().toLowerCase(),
            });
        });
    }
}

class Verifier {
    verify(hash, {alg, signer, signature}) {
        return new Promise(function (resolve) {
            if (alg !== 'ed25519') {
                return false;
            }

            const key = ec.keyFromPublic(signer);

            resolve(
                key.verify(hash, signature)
            );
        });
    }
}

exports.Signer = Signer;
exports.Verifier = Verifier;
