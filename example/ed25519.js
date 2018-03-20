const elliptic = require('elliptic');
const ec = new elliptic.eddsa('ed25519');

class Signer {
    constructor({secret}) {
        this.key = ec.keyFromSecret(secret);
    }

    sign(hash) {
        const {key} = this;

        return new Promise(function (resolve) {
            const signature = key.sign(hash);

            resolve({
                alg: 'ed25519',
                signer: key.getPublic('hex'),
                signature: signature.toHex().toLowerCase(),
            });
        });
    }
}

class Verifier {
    verify(hash, {alg, signer, signature}) {
        return new Promise(function (resolve) {
            if (alg !== 'ed25519') {
                resolve(false);
                return;
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
