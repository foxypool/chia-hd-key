import {bls12_381} from '@noble/curves/bls12-381'
import {Hex} from '@noble/curves/abstract/utils'

import {VerifyOptions} from './verify-options'
import {AUGMENTED_SCHEME_DST_LABEL, BASIC_SCHEME_DST_LABEL} from './scheme'
import {PublicKey} from './public-key'

export function verifyBatch(signature: Uint8Array, messages: Uint8Array[], publicKeys: Uint8Array[], options?: Partial<VerifyOptions>): boolean {
  if (messages.length !== publicKeys.length) {
    return false
  }

  const useAugmentedScheme = options?.useAugmentedScheme ?? true
  const messagesToVerify = useAugmentedScheme
    ? messages.map((message, index) => Buffer.concat([publicKeys[index], message]))
    : messages
  const DST = useAugmentedScheme ? AUGMENTED_SCHEME_DST_LABEL : BASIC_SCHEME_DST_LABEL

  return bls12_381.verifyBatch(
    signature,
    messagesToVerify,
    publicKeys,
    // @ts-expect-error untyped options
    { DST },
  )
}

export function aggregateSignatures(signatures: Hex[]): Uint8Array {
  return bls12_381.aggregateSignatures(signatures)
}

export function aggregatePublicKeys(publicKeys: PublicKey[]): PublicKey {
  return PublicKey.fromBuffer(bls12_381.aggregatePublicKeys(publicKeys.map(publicKey => publicKey.buffer)))
}
