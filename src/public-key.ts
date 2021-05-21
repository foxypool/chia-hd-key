import { verify } from 'noble-bls12-381';

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

  async verify(signature: string, message: string) {
    return verify(signature, message, this.buffer);
  }
}
