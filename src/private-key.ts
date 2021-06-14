import { mnemonicToSeedSync } from 'bip39';
import { deriveChild, deriveMaster } from 'bls12-381-keygen-chia';
import { getPublicKey, sign } from 'noble-bls12-381';

import { PublicKey } from './public-key';
import { isUsingAugmentedScheme } from './scheme';

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

  async signString(message: string) {
    return this.signHex(Buffer.from(message, 'utf8').toString('hex'));
  }

  async signHex(messageHex: string) {
    return this.signBuffer(Buffer.from(messageHex, 'hex'));
  }

  async signBuffer(messageBuffer: Buffer) {
    const bufferToSign = isUsingAugmentedScheme()
      ? Buffer.concat([this.getPublicKey().buffer, messageBuffer])
      : messageBuffer;

    return sign(bufferToSign.toString('hex'), this.buffer);
  }

  deriveChildKey(path: number[]): PrivateKey {
    let childPrivateKey: Uint8Array = this.buffer;
    path.forEach(index => childPrivateKey = deriveChild(childPrivateKey, index));

    return new PrivateKey(Buffer.from(childPrivateKey));
  }
}
