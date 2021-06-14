import * as bls from 'noble-bls12-381';

const BASIC_SCHEME_DST_LABEL = 'BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_';
const AUGMENTED_SCHEME_DST_LABEL = 'BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_AUG_';

export function useBasicScheme() {
  // @ts-ignore
  bls.DST_LABEL = BASIC_SCHEME_DST_LABEL;
}

export function useAugmentedScheme() {
  // @ts-ignore
  bls.DST_LABEL = AUGMENTED_SCHEME_DST_LABEL;
}

export function isUsingAugmentedScheme() {
  return bls.DST_LABEL === AUGMENTED_SCHEME_DST_LABEL;
}
