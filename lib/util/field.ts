export const BN254_FIELD_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;


/**
* Checks if a value is within the field.
* 
* @param n - The value to check.
* @returns True if the value is within the field, false otherwise.
*/
export function isInField(n: bigint): boolean {
  return n < BN254_FIELD_MODULUS;
}

/**
* Converts a string to an array of 254-bit bigints (big-endian).
* 
* @param str - The string to convert.
* @returns An array of 254-bit bigints (big-endian).
*/
export function utf8ToFr(str: string): bigint[] {
  const bytes = new TextEncoder().encode(str);
  const bits: number[] = [];
  
  // Convert bytes to bit array (big-endian)
  for (const byte of bytes) {
    for (let i = 7; i >= 0; i--) {
      bits.push((byte >> i) & 1);
    }
  }
  
  const result: bigint[] = [];
  for (let i = 0; i < bits.length; i += 254) {
    const chunkBits = bits.slice(i, i + 254);
    let acc = 0n;
    for (const bit of chunkBits) {
      acc = (acc << 1n) | BigInt(bit);
    }
    result.push(acc % BN254_FIELD_MODULUS);
  }
  
  return result;
}

/**
* Generates a random value within the field.
* 
* @returns A random value within the field.
*/
export function getRandomFr() : bigint {
  const buf = new Uint8Array(32);
  crypto.getRandomValues(buf);
  const big = buf.reduce((acc, byte) => (acc << 8n) + BigInt(byte), 0n);
  return big % BN254_FIELD_MODULUS;
}