import {bls12_381} from '@noble/curves/bls12-381'

import {AUGMENTED_SCHEME_DST_LABEL, BASIC_SCHEME_DST_LABEL} from './scheme'
import {VerifyOptions} from './verify-options'

export class PublicKey {
  public static fromBuffer(buffer: Uint8Array): PublicKey {
    return new PublicKey(Buffer.from(buffer))
  }

  public static fromHex(publicKeyHex: string): PublicKey {
    return new PublicKey(Buffer.from(publicKeyHex, 'hex'))
  }

  public readonly buffer: Buffer

  public constructor(publicKeyBuffer: Buffer) {
    this.buffer = publicKeyBuffer
  }

  public toHex(): string {
    return this.buffer.toString('hex')
  }

  public verifyString(signature: string, message: string, options?: Partial<VerifyOptions>): boolean {
    return this.verifyBuffer(signature, Buffer.from(message, 'utf8'), options)
  }

  public verifyHex(signature: string, messageHex: string, options?: Partial<VerifyOptions>): boolean {
    return this.verifyBuffer(signature, Buffer.from(messageHex, 'hex'), options)
  }

  public verifyBuffer(signature: string, messageBuffer: Uint8Array, options?: Partial<VerifyOptions>): boolean {
    const useAugmentedScheme = options?.useAugmentedScheme ?? true
    const bufferToVerify = useAugmentedScheme
      ? Buffer.concat([this.buffer, messageBuffer])
      : messageBuffer
    const DST = useAugmentedScheme ? AUGMENTED_SCHEME_DST_LABEL : BASIC_SCHEME_DST_LABEL

    // @ts-expect-error untyped option
    return bls12_381.verify(signature, bufferToVerify.toString('hex'), this.buffer, { DST })
  }
}
