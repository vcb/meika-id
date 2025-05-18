// EncryptedState holds all vault state. Decrypted values are only handled by the vault worker.
export type EncryptedState = {
  initialized: boolean;            // True if the vault and its contents have been initialized
  masterKeySalt: Uint8Array;       // Used for deriving the master key, which encrypts the symmetric key
  masterKeyHash: Uint8Array;       // Used for quick verification of the password
  encryptedSymmetricKey?: EncryptedData;
  encryptedPrivateKey?: EncryptedData;
  encryptedRegistrationProof?: EncryptedData;
  encryptedSignalOutputs?: EncryptedData;
  encryptedCommitmentIndices?: EncryptedData;

  unlocked: boolean; // Not stored
}

export interface EncryptedData {
  cipher: Uint8Array;
  iv: Uint8Array;
}

export type VaultStatus = {
  initialized: boolean;
  unlocked: boolean;
  registered: boolean;
}

export type MerkleData = {
  rootDvv: bigint;
  rootZk: bigint;
  pathDvv: bigint[];
  idxDvv: bigint[];
  pathZk: bigint[];
  idxZk: bigint[];
}
