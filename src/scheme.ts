import * as bls from 'noble-bls12-381';

export function useBasicScheme() {
  // @ts-ignore
  bls.DST_LABEL = 'BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_';
}

export function useAugmentedScheme() {
  // @ts-ignore
  bls.DST_LABEL = 'BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_AUG_';
}
