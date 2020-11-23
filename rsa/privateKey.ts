import { PublicKey  as publickey} from "../rsa/publicKey";

export class PrivateKey{
    d: BigInt;
    publicKey: publickey;
    bcu = require('bigint-crypto-utils');
//import * as bc from 'bigint-conversion';
bc = require('bigint-conversion');
    constructor (d, publicKey) {
        this.d = BigInt(d);
        this.publicKey = publicKey;
    }

    decrypt (c) {
        return this.bcu.modPow(c, this.d, this.publicKey.n);
    }

    sign (m) {
        m = this.bc.textToBigint(m);
        return this.bc.bigintToText(this.bcu.modPow(m, this.d, this.publicKey.n));
    }
  }