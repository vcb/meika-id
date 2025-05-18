import { buildPoseidon, Poseidon, buildEddsa, Eddsa, buildBabyjub, BabyJub, Signature, Point } from 'circomlibjs';
import { getRandomBytes, encrypt, decrypt, newAesKey, SALT_LENGTH, hashArgon2, sha512, hashPoseidon } from './crypto';
import { logInfo, logError, logWarn } from './logger';
import * as Comlink from 'comlink';
import { bytesToB64, b64ToBytes, compareUint8Arrays } from './util';
import { EncryptedState, EncryptedData } from './types';
import { utf8ToFr } from '@lib/util';
import { Proof, SignalOutputs } from '@lib/types';

logInfo('VaultWorker', 'Vault worker loaded');

let poseidon: Poseidon | undefined;
let eddsa: Eddsa | undefined;
let babyJub: BabyJub | undefined;


interface VaultState {
  ready: boolean;
  symmetricKey: Uint8Array | undefined;
  privateKey: Uint8Array | undefined;
  publicKey: [bigint, bigint] | undefined;
  publicKeyPoint: Point | undefined;
  registrationProof: Proof | undefined;
  signalOutputs: SignalOutputs | undefined;
  commitmentIndices: VaultIndices | undefined;
}

interface VaultIndices {
  dvv: number;
  zk: number;
}

const vaultState: VaultState = {
  ready: false,
  symmetricKey: undefined,
  privateKey: undefined,
  publicKey: undefined,
  publicKeyPoint: undefined,
  registrationProof: undefined,
  signalOutputs: undefined,
  commitmentIndices: undefined,
};

// Initialize eddsa and babyjub instances
export async function ensureReady() {
  if (vaultState.ready) {
    logInfo('VaultWorker', 'Already initialized');
    return;
  }
  
  logInfo('VaultWorker', 'Initializing');
  
  const start = performance.now();
  poseidon = await buildPoseidon();
  eddsa = await buildEddsa();
  babyJub = await buildBabyjub();
  const end = performance.now();
  
  logInfo('VaultWorker', `Ready in ${end - start}ms`);
  vaultState.ready = true;
}

ensureReady();

// -------------------------------------------------------------------------------------------
// Vault API
// -------------------------------------------------------------------------------------------

export type VaultInitResult ={
  masterKeySalt: Uint8Array,
  masterKeyHash: Uint8Array,
  encryptedSymmetricKey: EncryptedData,
  encryptedPrivateKey: EncryptedData,
  unsafePrivateKey: Uint8Array,
}

export type RegisterResult = {
  encryptedRegistrationProof: EncryptedData,
  encryptedSignalOutputs: EncryptedData,
  encryptedCommitmentIndices?: EncryptedData,
}

export interface VaultAPI {
  init(password: string): Promise<{ success: boolean, error?: string, res?: VaultInitResult}>;
  register(registrationProof: Proof, signalOutputs: SignalOutputs, commitmentIndices: VaultIndices): Promise<{ success: boolean, error?: string, res?: RegisterResult }>;
  sign(message: string | bigint | bigint[] | Uint8Array): Promise<{ success: boolean, error?: string, signaturePacked?: Uint8Array, signature?: [bigint, bigint, bigint] }>;
  verify(message: Uint8Array, signature: Signature, publicKey: Point): Promise<{ success: boolean, error?: string, isValid?: boolean }>;
  getPublicKey(): Promise<{ success: boolean, error?: string, pubKey?: [bigint, bigint] }>;
  getDVVCommitment(): Promise<{ success: boolean, error?: string, dvvCommitment?: bigint }>;
  getIndices(): Promise<{ success: boolean, error?: string, indices?: {dvv: number, zk: number} }>;
  unlock(password: string, data: EncryptedState): Promise<{ success: boolean, error?: string }>;
  lock(): Promise<{ success: boolean, error?: string }>;
  poseidonHash(input: string | bigint | bigint[]): Promise<{ success: boolean, error?: string, hash?: bigint, hashArr?: Uint8Array}>;
}

const vaultAPI: VaultAPI = {
  init: async (password: string) => {
    try {
      const res = await initializeVault(password);
      return { success: true, res: res };
    } catch (error: any) {
      logError('VaultWorker', 'Error initializing vault:', error);
      return { success: false, error: error.message };
    }
  },
  
  register: async (registrationProof: Proof, signalOutputs: SignalOutputs, commitmentIndices: VaultIndices) => {
    await ensureReady();
    if (!vaultState.ready) {
      return { success: false, error: 'Vault not initialized' };
    }
    if (!vaultState.symmetricKey) {
      return { success: false, error: 'Vault not unlocked' };
    }
    if (vaultState.registrationProof) {
      return { success: false, error: 'Vault already registered' };
    }

    const encryptedRegistrationProof = await encrypt(
      vaultState.symmetricKey, 
      serializeData(registrationProof)
    );
    const encryptedSignalOutputs = await encrypt(
      vaultState.symmetricKey, 
      serializeData(signalOutputs)
    );
    const encryptedCommitmentIndices = await encrypt(
      vaultState.symmetricKey, 
      serializeData(commitmentIndices)
    );

    // Cache
    vaultState.registrationProof = registrationProof;
    vaultState.signalOutputs = signalOutputs;
    vaultState.commitmentIndices = commitmentIndices;

    console.log('vaultState.signalOutputs:', vaultState.signalOutputs);

    return { success: true, res: {
      encryptedRegistrationProof: encryptedRegistrationProof,
      encryptedSignalOutputs: encryptedSignalOutputs,
      encryptedCommitmentIndices: encryptedCommitmentIndices,
    } };
  },
  
  sign: async (message: string | bigint | bigint[] | Uint8Array) => {
    if (!eddsa || !poseidon || !babyJub || !vaultState.ready) {
      return { success: false, error: 'Vault not initialized' };
    }
    
    let hash: Uint8Array;
    if (typeof message === 'string') {
      const bigMsg = utf8ToFr(message);
      hash = hashPoseidon(poseidon, bigMsg);
    } else if (message instanceof Uint8Array) {
      hash = message;
    } else {
      hash = hashPoseidon(poseidon, message);
    }

    try {
      const signature: Signature = eddsa.signPoseidon(vaultState.privateKey, hash);
      const packedSignature = eddsa.packSignature(signature);
      
      const res = await vaultAPI.verify(hash, signature, vaultState.publicKeyPoint!);
      if (!res.success) {
        throw new Error('Failed to verify generated signature');
      }
      if (!res.isValid) {
        throw new Error('Generated signature is invalid');
      }

      return {
        success: true,
        signaturePacked: packedSignature,
        signature: [signature.S, babyJub.F.toObject(signature.R8[0]), babyJub.F.toObject(signature.R8[1])]
      };
    } catch (error: any) {
      logError('VaultWorker', 'Error signing message:', error);
      return { success: false, error: error.message };
    }
  },
  
  verify: async (message: Uint8Array, signature: Signature, publicKey: Point) => {
    if (!eddsa || !babyJub || !vaultState.ready) {
      return { success: false, error: 'Vault not initialized' };
    }
    
    const isValid = eddsa.verifyPoseidon(message, signature, publicKey);
    return { success: true, isValid: isValid };
  },
  
  getPublicKey: async () => {
    if (!vaultState.ready) {
      return { success: false, error: 'Vault not initialized' };
    }
    
    return { success: true, pubKey: vaultState.publicKey };
  },

  getDVVCommitment: async () => {
    if (!vaultState.ready) {
      return { success: false, error: 'Vault not initialized' };
    }

    if (!vaultState.signalOutputs) {
      return { success: false, error: 'Vault not registered' };
    }

    return { success: true, dvvCommitment: BigInt(vaultState.signalOutputs.dvvCommitment) };
  },

  getIndices: async () => {
    if (!vaultState.ready) {
      return { success: false, error: 'Vault not initialized' };
    }

    if (!vaultState.commitmentIndices) {
      return { success: false, error: 'Vault not registered' };
    }

    return { success: true, indices: vaultState.commitmentIndices };
  },
  
  unlock: async (password: string, data: EncryptedState) => {
    const masterKey = await hashArgon2(password, data.masterKeySalt);
    const masterKeyHash = await sha512(masterKey);
    
    // Check before decrypting
    // TODO: worth storing this over just trying to decrypt?
    if (!compareUint8Arrays(masterKeyHash, data.masterKeyHash)) {
      return { success: false, error: 'Invalid password' };
    }
    
    const unlocked = await unlock(masterKey, data);
    if (!unlocked) {
      return { success: false, error: 'Failed to unlock vault' };
    }
    
    return { success: true };
  },
  
  lock: async () => {
    await lock();
    return { success: true };
  },
  
  poseidonHash: async (input: string | bigint | bigint[]) => {
    if (!poseidon) {
      return { success: false, error: 'Vault not initialized' };
    }
    
    const bigMsg = typeof input === 'string' ? utf8ToFr(input) : input;
    const hash = hashPoseidon(poseidon, bigMsg);
    const hashObj = poseidon.F.toObject(hash);
    return { success: true, hash: hashObj, hashArr: hash };
  }
}

Comlink.expose(vaultAPI);

async function initializeVault(password: string): Promise<VaultInitResult> {
  logInfo('VaultWorker', 'Deriving master key and verification key from password');
  
  // Derive master key 
  const masterKeySalt = await getRandomBytes(SALT_LENGTH);
  const masterKey = await hashArgon2(password, masterKeySalt);
  const masterKeyHash = await sha512(masterKey);
  
  // Generate symmetric key and encrypt it with master key
  const symmetricKey = await newAesKey();
  const symmetricKeyRes = await encrypt(masterKey, symmetricKey);
  
  // Generate private key for Babyjub EdDSA and encrypt it with symmetric key
  const privateKey = await getRandomBytes(32);
  const privateKeyRes = await encrypt(symmetricKey, privateKey);
  
  if (!symmetricKeyRes.iv || !symmetricKeyRes.cipher || !privateKeyRes.cipher || !privateKeyRes.iv) {
    throw new Error('Failed to initialize vault');
  }
  
  return {
    masterKeySalt: masterKeySalt,
    masterKeyHash: masterKeyHash,
    encryptedSymmetricKey: { cipher: symmetricKeyRes.cipher, iv: symmetricKeyRes.iv },
    encryptedPrivateKey: { cipher: privateKeyRes.cipher, iv: privateKeyRes.iv },
    unsafePrivateKey: privateKey,
  }
}

// Serializes data to a Uint8Array
function serializeData(data: any): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(data));
}

// Deserializes data from a Uint8Array
function deserializeData(bytes: Uint8Array): any {
  try {
    const text = new TextDecoder().decode(bytes);
    return JSON.parse(text);
  } catch (error) {
    logError('VaultWorker', 'Error deserializing data:', error);
    return null;
  }
}

// Decrypts the vault state into memory
async function unlock(masterKey: Uint8Array, data: EncryptedState): Promise<boolean> {
  logInfo('VaultWorker', `Unlocking vault...`);
  try {
    if (!data.encryptedSymmetricKey || !data.encryptedPrivateKey) {
      throw new Error('No encrypted symmetric key or private key provided');
    }
    
    vaultState.symmetricKey = await decrypt(
      masterKey, 
      data.encryptedSymmetricKey.cipher,
      data.encryptedSymmetricKey.iv
    );
    
    vaultState.privateKey = await decrypt(
      vaultState.symmetricKey,
      data.encryptedPrivateKey.cipher,
      data.encryptedPrivateKey.iv
    );
    
    vaultState.publicKeyPoint = eddsa?.prv2pub(vaultState.privateKey);
    if (!vaultState.publicKeyPoint) {
      throw new Error('Failed to derive public key');
    }
    vaultState.publicKey = [babyJub?.F.toObject(vaultState.publicKeyPoint[0]), babyJub?.F.toObject(vaultState.publicKeyPoint[1])];
    
    // Use consistent deserialization for registration data
    if (data.encryptedRegistrationProof && data.encryptedRegistrationProof.cipher.length > 0) {
      try {
        const proofBytes = await decrypt(
          vaultState.symmetricKey,
          data.encryptedRegistrationProof.cipher,
          data.encryptedRegistrationProof.iv
        );
        vaultState.registrationProof = deserializeData(proofBytes) as any;
      } catch (error) {
        logError('VaultWorker', 'Error decrypting registration proof:', error);
      }
    }
    
    if (data.encryptedSignalOutputs && data.encryptedSignalOutputs.cipher.length > 0) {
      try {
        const outputsBytes = await decrypt(
          vaultState.symmetricKey,
          data.encryptedSignalOutputs.cipher,
          data.encryptedSignalOutputs.iv
        );

        vaultState.signalOutputs = deserializeData(outputsBytes) as any;
      } catch (error) {
        logError('VaultWorker', 'Error decrypting signal outputs:', error);
      }
    }

    if (data.encryptedCommitmentIndices && data.encryptedCommitmentIndices.cipher.length > 0) {
      try {
        const indicesBytes = await decrypt(
          vaultState.symmetricKey,
          data.encryptedCommitmentIndices.cipher,
          data.encryptedCommitmentIndices.iv
        );
        vaultState.commitmentIndices = deserializeData(indicesBytes) as any || [0, 0];
      } catch (error) {
        logError('VaultWorker', 'Error decrypting commitment indices:', error);
      }
    }
  } catch (error: any) {
    logError('VaultWorker', 'Error unlocking vault:', error);
    return false;
  }
  
  return true;
}

// Locks the vault by clearing the state
async function lock() {
  vaultState.symmetricKey = undefined;
  vaultState.privateKey = undefined;
  vaultState.publicKey = undefined;
  vaultState.publicKeyPoint = undefined;
  vaultState.registrationProof = undefined;
  vaultState.signalOutputs = undefined;
  vaultState.commitmentIndices = undefined;
}