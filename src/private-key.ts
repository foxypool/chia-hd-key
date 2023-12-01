import { mnemonicToSeedSync } from 'bip39'
import { deriveChild, deriveMaster } from 'bls12-381-keygen-chia'
import {bls12_381} from '@noble/curves/bls12-381'
import {mod} from '@noble/curves/abstract/modular'
import {createHash} from 'crypto'

import { PublicKey } from './public-key'
import {AUGMENTED_SCHEME_DST_LABEL, BASIC_SCHEME_DST_LABEL} from './scheme'
import {SigningOptions} from './signing-options'
import {bigEndianBytesToBigInt, bigIntToBigEndianBytes, defaultEcN} from './util'

export class PrivateKey {
  public static fromBuffer(buffer: Uint8Array): PrivateKey {
    return new PrivateKey(Buffer.from(buffer))
  }

  public static fromHex(privateKeyHex: string): PrivateKey {
    return new PrivateKey(Buffer.from(privateKeyHex, 'hex'))
  }

  public static fromMnemonic(mnemonic: string): PrivateKey {
    const seed = mnemonicToSeedSync(mnemonic)

    return PrivateKey.fromSeed(seed)
  }

  public static fromSeed(seed: Buffer): PrivateKey {
    const masterSk = deriveMaster(seed)

    return new PrivateKey(Buffer.from(masterSk))
  }

  // TODO: verify this works correctly
  public static aggregate(privateKeys: PrivateKey[]): PrivateKey {
    const aggregateBigInt = mod(
      privateKeys.reduce(
        (aggregate, privateKey) => aggregate + bigEndianBytesToBigInt(privateKey.buffer),
        0n
      ),
      defaultEcN,
    )

    return PrivateKey.fromBuffer(bigIntToBigEndianBytes(aggregateBigInt, 32))
  }

  public readonly buffer: Buffer

  public constructor(privateKeyBuffer: Buffer) {
    this.buffer = privateKeyBuffer
  }

  public toHex(): string {
    return this.buffer.toString('hex')
  }

  public getPublicKey(): PublicKey {
    return new PublicKey(Buffer.from(bls12_381.getPublicKey(this.buffer)))
  }

  public signString(message: string, options?: Partial<SigningOptions>): Uint8Array {
    return this.signBuffer(Buffer.from(message, 'utf8'), options)
  }

  public signHex(messageHex: string, options?: Partial<SigningOptions>): Uint8Array {
    return this.signBuffer(Buffer.from(messageHex, 'hex'), options)
  }

  public signBuffer(messageBuffer: Uint8Array, options?: Partial<SigningOptions>): Uint8Array {
    const useAugmentedScheme = options?.useAugmentedScheme ?? true
    const bufferToSign = useAugmentedScheme
      ? Buffer.concat([this.getPublicKey().buffer, messageBuffer])
      : messageBuffer
    const DST = useAugmentedScheme ? AUGMENTED_SCHEME_DST_LABEL : BASIC_SCHEME_DST_LABEL
    
    // @ts-expect-error untyped option
    return bls12_381.sign(bufferToSign, this.buffer, { DST })
  }

  public deriveChildKey(path: number[]): PrivateKey {
    let childPrivateKey: Uint8Array = this.buffer
    path.forEach(index => childPrivateKey = deriveChild(childPrivateKey, index))

    return new PrivateKey(Buffer.from(childPrivateKey))
  }

  // TODO: verify this works correctly
  public deriveChildKeyUnhardened(path: number[]): PrivateKey {
    let childPrivateKey: PrivateKey = this
    path.forEach(index => {
      const publicKey = childPrivateKey.getPublicKey()
      const indexBuffer = Buffer.alloc(4)
      indexBuffer.writeInt32BE(index)
      const buffer = Buffer.concat([
        publicKey.buffer,
        indexBuffer,
      ])
      const hash = createHash('sha256').update(buffer).digest()
      childPrivateKey = PrivateKey.aggregate([PrivateKey.fromBuffer(hash), childPrivateKey])
    })

    return childPrivateKey
  }
}
