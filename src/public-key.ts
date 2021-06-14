import { verify } from 'noble-bls12-381';

import { isUsingAugmentedScheme } from './scheme';

export class PublicKey {
  static fromHex(publicKeyHex: string): PublicKey {
    return new PublicKey(Buffer.from(publicKeyHex, 'hex'));
  }

  public buffer: Buffer;

  constructor(publicKeyBuffer: Buffer) {
    this.buffer = publicKeyBuffer;
  }

  toHex(): string {
    return this.buffer.toString('hex');
  }

  async verifyString(signature: string, message: string) {
    return this.verifyHex(signature, Buffer.from(message, 'utf8').toString('hex'));
  }

  async verifyHex(signature: string, messageHex: string) {
    return this.verifyBuffer(signature, Buffer.from(messageHex, 'hex'));
  }

  async verifyBuffer(signature: string, messageBuffer: Buffer) {
    const bufferToVerify = isUsingAugmentedScheme()
      ? Buffer.concat([this.buffer, messageBuffer])
      : messageBuffer;

    return verify(signature, bufferToVerify.toString('hex'), this.buffer);
  }
}
