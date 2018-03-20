const elliptic = require('elliptic');
const ec = new elliptic.eddsa('ed25519');

class Signer {
    constructor({secret}) {
        this.key = ec.keyFromSecret(secret);
    }

    async sign(hash) {
        const signature = this.key.sign(hash);

        return {
            alg: 'ed25519',
            signer: this.key.getPublic('hex'),
            signature: signature.toHex().toLowerCase(),
        };
    }
}

class Verifier {
    async verify(hash, {alg, signer, signature}) {
        if (alg !== 'ed25519') {
            return false;
        }

        const key = ec.keyFromPublic(signer);

        return key.verify(hash, signature);
    }
}

exports.Signer = Signer;
exports.Verifier = Verifier;
