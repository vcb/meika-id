/**
* crypto.ts - Crypto utilities for vault extension
* 
* This module handles key derivation, encryption and decryption.
* 
* Cryptographic decisions:
* - AES-256-GCM for encryption
* - Argon2id for key derivation
* - WebCrypto API for randomness and AES
* 
* Argon2id is chosen for its memory-hardness and resistance to ASICs and side-channel attacks.
* 
* Parameters are based on OWASP recommendations:
* https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
* 
* Specifically, we use 4 iterations, 64MB memory, 4 threads. So somewhat higher than recommended.
*/

import { logInfo } from './logger';
import { ArgonOpts } from '@noble/hashes/argon2';
import { argon2id as argon2idWasm } from 'hash-wasm';
import { bytesToB64 } from './util';
import { Poseidon } from 'circomlibjs';

const crypto = self.crypto;

export const SALT_LENGTH = 32;
export const MAX_POSEIDON_INPUTS = 16;

interface AesParams {
  algorithm: string;
  ivLength: number;
  tagLength: number;
  keyLength: number;
}

const AES_PARAMS: AesParams = {
  algorithm: 'AES-GCM',
  ivLength: 12, // Bytes
  tagLength: 16, // Bytes
  keyLength: 256  // Bits
}

/**
* Generates a new AES key.
* 
* @returns The new AES key.
*/
export async function newAesKey(): Promise<Uint8Array> {
  const key = await crypto.subtle.generateKey(
    { name: AES_PARAMS.algorithm, length: AES_PARAMS.keyLength },
    true,
    ['encrypt', 'decrypt']
  );
  
  return new Uint8Array(await crypto.subtle.exportKey('raw', key));
}

/**
* Gets cryptographically secure random bytes.
* 
* @param length - The length of the random bytes to get.
* @returns The random bytes.
*/
export async function getRandomBytes(length: number): Promise<Uint8Array> {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

/**
* Encrypts data using AES-256-GCM.
* 
* @param rawKey - The raw key to use for encryption.
* @param data - The data to encrypt.
* @returns The encrypted data and the initialization vector.
*/
export async function encrypt(rawKey: Uint8Array, data: Uint8Array): Promise<{ cipher: Uint8Array, iv: Uint8Array }> {
  const iv = await getRandomBytes(AES_PARAMS.ivLength);
  
  const key = await crypto.subtle.importKey(
    'raw',
    rawKey,
    { name: AES_PARAMS.algorithm },
    false,
    ['encrypt', 'decrypt']
  );
  
  const cipher = await crypto.subtle.encrypt(
    { name: AES_PARAMS.algorithm, iv: iv, tagLength: AES_PARAMS.tagLength * 8 },
    key,
    data
  );
  
  return { cipher: new Uint8Array(cipher), iv };
}

/**
* Decrypts a ciphertext using AES-256-GCM.
* 
* @param rawKey - The raw key to use for decryption.
* @param cipher - The ciphertext to decrypt.
* @param iv - The initialization vector used for encryption.
* @returns The decrypted data.
*/
export async function decrypt(rawKey: Uint8Array, cipher: Uint8Array, iv: Uint8Array): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    'raw',
    rawKey,
    { name: AES_PARAMS.algorithm },
    false,
    ['encrypt', 'decrypt']
  );
  
  const plain = await crypto.subtle.decrypt(
    { name: AES_PARAMS.algorithm, iv: iv, tagLength: AES_PARAMS.tagLength * 8 },
    key,
    cipher
  );
  
  return new Uint8Array(plain);
}

const Argon2Opts: ArgonOpts = {
  t: 4, // iterations
  m: 65536, // memory
  p: 4, // parallelism
}

/**
* Hashes a password using Argon2id.
* 
* @param password - The password to hash.
* @param salt - The salt to use for the hash.
* @returns The hash of the password.
*/
export async function hashArgon2(password: string, salt: Uint8Array): Promise<Uint8Array> {
  try {
    const start = performance.now();
    const hashResult = await argon2idWasm({
      password: password,
      salt: salt,
      iterations: Argon2Opts.t,
      parallelism: Argon2Opts.p,
      memorySize: Argon2Opts.m,
      hashLength: 32,
      outputType: 'binary'
    });
    const end = performance.now();
    
    logInfo('Crypto', `Argon2 (wasm) hash took ${end - start}ms`);
    return new Uint8Array(hashResult);
  } catch (error: any) {
    throw error;
  }
}

/**
* Hashes data using SHA-512.
* 
* @param data - The data to hash.
* @returns The hash of the data.
*/
export async function sha512(data: Uint8Array): Promise<Uint8Array> {
  const hash = await crypto.subtle.digest('SHA-512', data);
  return new Uint8Array(hash);
}

/**
* Hashes an array of inputs using the poseidon hash function.
* 
* @param poseidon - The poseidon instance.
* @param inputs - The inputs to hash. Can be a bigint or an array of bigints.
* @returns The hash of the inputs.
*/
export function hashPoseidon(poseidon: Poseidon, inputs: bigint | bigint[]): Uint8Array {
  if (typeof inputs === 'bigint') {
    inputs = [inputs];
  }
  if (inputs.length > MAX_POSEIDON_INPUTS) {
    throw new Error(`Maximum number of inputs is ${MAX_POSEIDON_INPUTS}`);
  }
  try {
    return poseidon(inputs);
  } catch (error) {
    console.error(`Failed to hash inputs: ${error}`);
    throw new Error(`Failed to hash inputs: ${error}`);
  }
}

/**
* Converts a Uint8Array to a bigint (little-endian).
* 
* @param bytes - The Uint8Array to convert.
* @returns The bigint representation of the Uint8Array.
*/
export function uint8ArrayToBigInt(bytes: Uint8Array): bigint {
  return bytes.reduceRight((acc, byte) => (acc << 8n) + BigInt(byte), 0n);
}