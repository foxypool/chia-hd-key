import { mnemonicToSeedSync } from 'bip39';
import { deriveChild, deriveMaster } from 'bls12-381-keygen';
import { getPublicKey, sign } from 'noble-bls12-381';

import { PublicKey } from './public-key';

export class PrivateKey {
  static fromHex(privateKeyHex: string): PrivateKey {
    return new PrivateKey(Buffer.from(privateKeyHex, 'hex'));
  }

  static fromMnemonic(mnemonic: string): PrivateKey {
    const seed = mnemonicToSeedSync(mnemonic);

    return PrivateKey.fromSeed(seed);
  }

  static fromSeed(seed: Buffer): PrivateKey {
    const masterSk = deriveMaster(seed);

    return new PrivateKey(Buffer.from(masterSk));
  }

  public buffer: Buffer;

  constructor(privateKeyBuffer: Buffer) {
    this.buffer = privateKeyBuffer;
  }

  toHex(): string {
    return this.buffer.toString('hex');
  }

  getPublicKey(): PublicKey {
    return new PublicKey(Buffer.from(getPublicKey(this.buffer)));
  }

  async sign(message: string) {
    return sign(message, this.buffer);
  }

  deriveChildKey(path: number[]): PrivateKey {
    let childPrivateKey: Uint8Array = this.buffer;
    path.forEach(index => childPrivateKey = deriveChild(childPrivateKey, index));

    return new PrivateKey(Buffer.from(childPrivateKey));
  }
}
