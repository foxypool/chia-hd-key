const purpose = 12381 // BLS12-381
const coinType = 8444 // Chia

const farmerAccount = 0
const poolAccount = 1
const walletAccount = 2
const localAccount = 3
const backupAccount = 4

export const keyPath = {
  farmer: [purpose, coinType, farmerAccount, 0],
  pool: [purpose, coinType, poolAccount, 0],
  wallet: (index: number) => [purpose, coinType, walletAccount, index],
  local: [purpose, coinType, localAccount, 0],
  backup: [purpose, coinType, backupAccount, 0],
}
