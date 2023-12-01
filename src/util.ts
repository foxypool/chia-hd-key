export function bigEndianBytesToBigInt(
  bytes: Uint8Array,
  signed: boolean = false
): bigint {
  if (bytes.length === 0) {
    return 0n
  }
  const sign = bytes[0]
    .toString(2)
    .padStart(8, '0')[0]

  const byteList = bytes
  let binary = ''
  for (const byte of byteList) {
    binary += byte.toString(2).padStart(8, '0')
  }
  if (sign === '1' && signed) {
    binary = (BigInt('0b' + flip(binary)) + 1n)
      .toString(2)
      .padStart(bytes.length * 8, '0')
  }
  const result = BigInt('0b' + binary)

  return sign === '1' && signed ? -result : result
}

export function bigIntToBigEndianBytes(
  value: bigint,
  size: number,
  signed: boolean = false
): Uint8Array {
  if (value < 0n && !signed) {
    throw new Error('Cannot convert negative number to unsigned.')
  }
  let binary = (value < 0n ? -value : value)
    .toString(2)
    .padStart(size * 8, '0')
  if (value < 0) {
    binary = (BigInt('0b' + flip(binary)) + 1n)
      .toString(2)
      .padStart(size * 8, '0')
  }
  const bytes = binary.match(/[01]{8}/g)!.map((match) => parseInt(match, 2))

  return Uint8Array.from(bytes)
}

function flip(binary: string): string {
  return binary.replace(/[01]/g, (match) => (match === '0' ? '1' : '0'))
}

export const defaultEcN = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001n
