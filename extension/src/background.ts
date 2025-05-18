// background.ts
import browser from 'webextension-polyfill';
import { browser as browser2, Runtime as Runtime2 } from 'webextension-polyfill-ts'
import { createBackgroundEndpoint } from 'comlink-extension';
import { VaultInitResult, VaultAPI } from './vault-worker';
import { logDebug, logError, logInfo } from './logger';
import * as Comlink from 'comlink';
import { bytesToB64, b64ToBytes } from './util';
import { CircuitSignals } from 'snarkjs';
import { EncryptedState, EncryptedData, VaultStatus, MerkleData } from './types';
import { domainToServiceId } from '@lib/auth';
import { LoginParams, buildLoginInputs, REGISTRATION_MESSAGE, getRandomFr } from '@lib/util';
import { RegistrationProof, Proof, SignalOutputs, WebMessage, WebMessageType, LoginRequest, SignatureRequest, SignatureResponseContent, LoginResponseContent } from '@lib/types';

// TODO: improve instantiation, there's an issue with this on reloads
const vaultWorker: Worker = new Worker(browser.runtime.getURL('build/vault-worker.bundle.js'), { type: 'module' });
const vaultAPI: Comlink.Remote<VaultAPI> = Comlink.wrap(vaultWorker);

vaultWorker.onerror = (event) => {
  logError('Background', 'Vault worker error:', event);
}

if (!vaultAPI) {
  logError('Background', 'Vault API not initialized');
}

// Initialize as empty
const state: EncryptedState = {
  initialized: false,
  masterKeySalt: new Uint8Array(),
  masterKeyHash: new Uint8Array(),
  encryptedSymmetricKey: undefined,
  encryptedPrivateKey: undefined,
  encryptedRegistrationProof: undefined,
  encryptedSignalOutputs: undefined,
  encryptedCommitmentIndices: undefined,
  unlocked: false,
}

type EncryptedStateStorageSchema = {
  initialized: string;
  masterKeySalt: string;
  masterKeyHash: string;
  encryptedSymmetricKey: string;
  encryptedPrivateKey: string;
  encryptedRegistrationProof?: string;
  encryptedSignalOutputs?: string;
  encryptedCommitmentIndices?: string;
}

// Cached signature requests
let signatureRequests: Map<number, SignatureRequest> = new Map();
let requesters: Map<number, browser.Runtime.Port> = new Map();

// Cached proof
let proofSubmission: {
  proof: RegistrationProof,
  origin: string,
  port: browser.Runtime.Port,
} | undefined;

// Cached login request
let loginRequest: {
  request: LoginRequest,
  port: browser.Runtime.Port,
} | undefined;

// Returns the current vault status
// - initialized: true if the vault has been initialized, i.e. a keypair has been generated, password has been set and so on
// - unlocked: true if the vault is unlocked
// - registered: true if the user has added their registration proof and signal outputs
async function getVaultStatus(): Promise<VaultStatus> {
  const status: VaultStatus = {
    initialized: false,
    unlocked: false,
    registered: false
  }
  
  if (!state.initialized) {
    return status;
  }   
  
  status.initialized = true;
  
  status.unlocked = state.unlocked;
  
  if (state.encryptedRegistrationProof && state.encryptedSignalOutputs) {
    status.registered = true;
  }
  
  return status;
}

// Save state except for the unlocked flag to storage
async function saveState() {
  const storage: Partial<EncryptedStateStorageSchema> = {};
  
  // Handle each field with appropriate serialization
  if (state.initialized !== undefined) {
    storage.initialized = state.initialized.toString();
  }
  
  if (state.masterKeySalt?.byteLength > 0) {
    storage.masterKeySalt = bytesToB64(state.masterKeySalt);
  }
  
  if (state.masterKeyHash?.byteLength > 0) {
    storage.masterKeyHash = bytesToB64(state.masterKeyHash);
  }
  
  // Serialize encrypted data
  function serializeData(data?: EncryptedData): string | undefined {
    if (!data?.cipher || !data?.iv) return undefined;
    return JSON.stringify({
      cipher: bytesToB64(data.cipher),
      iv: bytesToB64(data.iv)
    });
  }
  
  const symKey = serializeData(state.encryptedSymmetricKey);
  if (symKey) storage.encryptedSymmetricKey = symKey;
  
  const privKey = serializeData(state.encryptedPrivateKey);
  if (privKey) storage.encryptedPrivateKey = privKey;
  
  const regProof = serializeData(state.encryptedRegistrationProof);
  if (regProof) storage.encryptedRegistrationProof = regProof;
  
  const signalOutputs = serializeData(state.encryptedSignalOutputs);
  if (signalOutputs) storage.encryptedSignalOutputs = signalOutputs;
  
  const commitmentIndices = serializeData(state.encryptedCommitmentIndices);
  if (commitmentIndices) storage.encryptedCommitmentIndices = commitmentIndices;
  
  await browser.storage.local.set(storage);
}

// Load state from storage
async function loadState() {
  const stored = await browser.storage.local.get(null) as EncryptedStateStorageSchema;
  
  if (!stored) {
    return;
  }
  
  // Reset state to defaults
  state.initialized = false;
  state.masterKeySalt = new Uint8Array();
  state.masterKeyHash = new Uint8Array();
  state.encryptedSymmetricKey = undefined;
  state.encryptedPrivateKey = undefined;
  state.encryptedRegistrationProof = undefined;
  state.encryptedSignalOutputs = undefined;
  state.encryptedCommitmentIndices = undefined;
  state.unlocked = false;
  
  // Parse stored data
  for (const [k, v] of Object.entries(stored)) {
    if (!v) continue;
    
    const key = k as Exclude<keyof EncryptedState, 'unlocked'>;
    
    switch (key) {
      case 'masterKeySalt':
      case 'masterKeyHash':
      state[key] = b64ToBytes(v);
      break;
      case 'encryptedSymmetricKey':
      case 'encryptedPrivateKey':
      case 'encryptedRegistrationProof':
      case 'encryptedSignalOutputs':
      case 'encryptedCommitmentIndices': {
        const parsed = JSON.parse(v);
        if (parsed && parsed.cipher && parsed.iv) {
          state[key] = {
            cipher: b64ToBytes(parsed.cipher),
            iv: b64ToBytes(parsed.iv)
          };
        }
        break;
      }
      case 'initialized':
      state.initialized = v === 'true';
      break;
    }
  }
}

loadState();

// -------------------------------------------------------------------------------------------
// Background API
// -------------------------------------------------------------------------------------------

type InitData = Partial<Omit<VaultInitResult, 'unsafePrivateKey'>> | undefined;
let initDataTemp: InitData;

// TODO: improve readability, consistency

export type BackgroundAPI = {
  /**
  * Initialize the vault
  * @param password - The password to use for the vault
  * @returns Vault private key
  */
  init: (password: string) => Promise<{ success: boolean, error?: string, key?: Uint8Array }>;
  
  /**
  * Finish the initialization of the vault
  * @returns Success status
  */
  finishInit: () => Promise<{ success: boolean, error?: string }>;
  
  /**
  * Unlock the vault
  * @param password - The password to use to unlock the vault
  * @returns Success status
  */
  unlock: (password: string) => Promise<{ success: boolean, error?: string }>;
  
  /**
  * Lock the vault
  * @returns Success status
  */
  lock: () => Promise<{ success: boolean, error?: string }>;
  
  /**
  * Get the vault status
  * @returns Status of the vault
  */
  getStatus: () => Promise<VaultStatus>;
  
  /**
  * Register the vault
  * @param data - The data to register the vault with
  * @returns Success status
  */
  register: (data: {
    proof: Proof,
    publicSignals: SignalOutputs,
    dvvIndex: number,
    zkIndex: number
  }) => Promise<{ success: boolean, error?: string }>;
  
  /**
  * Request a signature
  * @param message - The message to sign
  * @param domain - The domain of the message
  * @param sender - The sender of the message
  * @param port - The port to send the signature request to
  * @returns Success status
  */
  requestSignature: (message: string, domain: string, sender: string, port: browser.Runtime.Port) => Promise<{ success: boolean }>;
  
  /**
  * Get cached signature requests
  * @returns Signature requests
  */
  getSignatureRequests: () => Promise<{ success: boolean, requests?: Map<number, SignatureRequest> }>;
  
  /**
  * Reject a signature request
  * @param id - The id of the signature request
  * @returns Success status
  */
  rejectSignatureRequest: (id: number) => Promise<{ success: boolean }>;
  
  /**
  * Sign a signature request
  * @param id - The id of the signature request
  * @returns Success status
  */
  signSignatureRequest: (id: number) => Promise<{ success: boolean, signaturePacked?: Uint8Array, signature?: [bigint, bigint, bigint] }>;
  
  /**
  * Request a proof
  * @param proof - The proof to request
  * @param origin - The origin of the proof
  * @param port - The port to send the proof request to
  * @returns Success status
  */
  requestAddProof: (proof: RegistrationProof, origin: string, port: browser.Runtime.Port) => Promise<{ success: boolean }>;
  
  /**
  * Get registration data
  * @returns Proof and origin
  */  
  getRegistrationData: () => Promise<{ success: boolean, error?: string, registrationData?: RegistrationProof, origin?: string }>;
  
  /**
  * Request a login
  * @param domain - The domain of the login
  * @param challenge - The challenge of the login
  * @param origin - The origin of the login
  * @param port - The port to send the login request to
  * @returns Success status
  */
  requestLogin: (domain: string, challenge: string, origin: string, port: browser.Runtime.Port) => Promise<{ success: boolean }>;
  
  /**
  * Get merkle data for login proof
  * @returns Inclusion proof paths, indices and roots
  */
  getMerkleData: () => Promise<{ success: boolean, error?: string, merkleData?: MerkleData }>;
  
  /**
  * Get cached login request
  * @returns Login request and service id
  */
  getLoginRequest: () => Promise<{ success: boolean, error?: string, loginRequest?: LoginRequest, serviceId?: string }>;
  
  /**
  * Reject a login request
  * @returns Success status
  */
  rejectLoginRequest: () => Promise<{ success: boolean, error?: string }>;
  
  /**
  * Confirm a login
  * @returns Inputs for the login circuit
  */
  confirmLogin: () => Promise<{ success: boolean, error?: string, inputs?: CircuitSignals }>;
  
  /**
  * Generate witness file and proof for login. Result is sent to the content script.
  * @param inputs - The inputs to generate the witness from
  * @returns Success status
  */
  fullProveLogin: (inputs: CircuitSignals) => Promise<{ success: boolean, error?: string }>;
  
  /**
  * Poseidon hash
  * @param input - String input to hash
  * @returns Field element object
  */
  poseidonHash: (input: string) => Promise<{ success: boolean, hash?: bigint }>;
}

const backgroundAPI: BackgroundAPI = {
  init: async (password: string) => {
    const status = await getVaultStatus();
    if (status.initialized) {
      return { success: false, error: 'Vault is already initialized' };
    }
    
    const resp = await vaultAPI.init(password);
    if (!resp.success || !resp.res) {
      logError('Background', 'Error initializing vault:', resp.error);
      return { success: false, error: resp.error || "Failed to initialize vault" };
    }
    
    initDataTemp = (({unsafePrivateKey, ...rest}) => rest)(resp.res);
    
    // WARN: careful with this
    return { success: true, key: resp.res.unsafePrivateKey};
  },
  
  finishInit: async () => {
    const status = await getVaultStatus();
    if (status.initialized) {
      return { success: false, error: 'Vault is already initialized' };
    }
    
    if (initDataTemp === undefined) {
      logError('Background', 'No initialization data found');
      return { success: false, error: 'No initialization data found' };
    }
    
    await initializeVault(initDataTemp);
    initDataTemp = undefined;
    
    return { success: true };
  },
  
  unlock: async (password: string) => {
    const resp = await vaultAPI.unlock(password, state);
    if (!resp.success) {
      return { success: false, error: resp.error || "Failed to unlock vault" };
    }
    
    state.unlocked = true;
    await saveState();
    return { success: true };
  },
  
  lock: async () => {
    const resp = await vaultAPI.lock();
    if (!resp.success) {
      return { success: false, error: resp.error };
    }
    
    state.unlocked = false;
    await saveState();
    return { success: true };
  },
  
  getStatus: async () => {
    return await getVaultStatus();
  },
  
  register: async (data: {
    proof: Proof,
    publicSignals: SignalOutputs,
    dvvIndex: number,
    zkIndex: number
  }) => {
    const status = await getVaultStatus();
    if (!status.unlocked) {
      logError('Background', 'Vault is not unlocked');
      return { success: false, error: 'Vault is not unlocked' };
    }
    if (status.registered) {
      logError('Background', 'Vault is already registered');
      return { success: false, error: 'Vault is already registered' };
    }
    
    const commitmentIndices = {
      dvv: data.dvvIndex,
      zk: data.zkIndex
    };
    
    const resp = await vaultAPI.register(
      data.proof as any, 
      data.publicSignals as any, 
      commitmentIndices as any
    );
    if (!resp.success) {
      logError('Background', 'Error registering vault:', resp.error);
      return { success: false, error: resp.error || "Failed to register vault" };
    }
    
    state.encryptedRegistrationProof = resp.res?.encryptedRegistrationProof;
    state.encryptedSignalOutputs = resp.res?.encryptedSignalOutputs;
    state.encryptedCommitmentIndices = resp.res?.encryptedCommitmentIndices;
    
    await saveState();
    
    proofSubmission = undefined;
    return { success: true };
  },
  
  requestSignature: async (message: string, domain: string, origin: string, port: browser.Runtime.Port) => {
    const status = await getVaultStatus();
    if (!status.initialized) {
      logError('Background', 'Vault is not initialized');
      return { success: false, error: 'Vault is not initialized' };
    }
    
    signatureRequests.set(signatureRequests.size, { message, domain, origin });
    requesters.set(requesters.size, port);
    browser.action.setBadgeText({ text: signatureRequests.size.toString() });
    return { success: true };
  },
  
  getSignatureRequests: async () => {
    const status = await getVaultStatus();
    if (!status.unlocked) {
      logError('Background', 'Vault is not unlocked');
      return { success: false, error: 'Vault is not unlocked' };
    }
    
    return { success: true, requests: signatureRequests };
  },
  
  rejectSignatureRequest: async (id: number) => {
    // Clear the request
    signatureRequests.delete(id);
    requesters.delete(id);
    if (signatureRequests.size === 0) {
      browser.action.setBadgeText({ text: '' });
    } else {
      browser.action.setBadgeText({ text: signatureRequests.size.toString() });
    }
    return { success: true };
  },
  
  signSignatureRequest: async (id: number) => {
    const status = await getVaultStatus();
    if (!status.unlocked) {
      logError('Background', 'Vault is not unlocked');
      return { success: false, error: 'Vault is not unlocked' };
    }
    
    if (!signatureRequests.has(id)) {
      logError('Background', 'No signature request found for id:', id);
      return { success: false, error: 'No signature request found' };
    }
    
    const request = signatureRequests.get(id);
    if (!request || !request.message) {
      logError('Background', 'No signature request found for id:', id);
      return { success: false, error: 'No signature request found' };
    }
    
    const respSign = await vaultAPI.sign(request.message);
    if (!respSign.success) {
      logError('Background', 'Error signing message:', request.message);
      return { success: false, error: "Failed to sign message" };
    }
    
    const respPubKey = await vaultAPI.getPublicKey();
    if (!respPubKey.success) {
      logError('Background', 'Error getting public key');
      return { success: false, error: "Failed to get public key" };
    }
    
    const port = requesters.get(id);
    if (!port) {
      logError('Background', 'No requester found for id:', id);
      return { success: false, error: 'No requester found' };
    }
    
    // Send to requester via content script
    port.postMessage({
      type: WebMessageType.SIGNATURE_RESPONSE,
      content: {
        signature: respSign.signature,
        packed: respSign.signaturePacked,
        pk: respPubKey.pubKey,
        origin: request.origin
      } as SignatureResponseContent
    });
    
    // Clear request
    signatureRequests.delete(id);
    requesters.delete(id);
    if (signatureRequests.size === 0) {
      browser.action.setBadgeText({ text: '' });
    } else {
      browser.action.setBadgeText({ text: signatureRequests.size.toString() });
    }
    
    return {
      success: true, 
      signaturePacked: respSign.signaturePacked,
      signature: respSign.signature,
      pubKey: respPubKey.pubKey
    };
  },
  
  requestAddProof: async (proof: RegistrationProof, origin: string, port: browser.Runtime.Port) => {
    const status = await getVaultStatus();
    if (!status.initialized) {
      logError('Background', 'Vault is not initialized');
      return { success: false, error: 'Vault is not initialized' };
    }
    if (status.registered) {
      logError('Background', 'Vault is already registered');
      return { success: false, error: 'Vault is already registered' };
    }
    
    proofSubmission = { proof, origin, port};
    await openPopup();
    
    return { success: true };
  },
  
  getRegistrationData: async () => {
    return { success: true, registrationData: proofSubmission?.proof, origin: proofSubmission?.origin };
  },
  
  requestLogin: async (domain: string, challenge: string, origin: string, port: browser.Runtime.Port) => {
    if (loginRequest) {
      logError('Background', 'Login request already exists');
      return { success: false, error: 'Login request already exists' };
    }
    loginRequest = { request: { domain, challenge, origin }, port };
    await openPopup();
    return { success: true };
  },
  
  getLoginRequest: async () => {
    if (!loginRequest) {
      return { success: false, error: 'No login request found' };
    }
    const serviceId = domainToServiceId(loginRequest.request.domain);
    return { success: true, loginRequest: loginRequest.request, serviceId: serviceId };
  },

  rejectLoginRequest: async () => {
    if (!loginRequest) {
      return { success: false, error: 'No login request found' };
    }
    // TODO: send reject message to content script
    loginRequest = undefined;
    return { success: true };
  },
  
  getMerkleData: async () => {
    const status = await getVaultStatus();
    if (!status.initialized) {
      logError('Background', 'Vault is not initialized');
      return { success: false, error: 'Vault is not initialized' };
    }
    if (!status.registered) {
      logError('Background', 'Vault is not registered');
      return { success: false, error: 'Vault is not registered' };
    }
    
    const respIndices = await vaultAPI.getIndices();
    if (!respIndices.success) {
      logError('Background', 'Error getting indices');
      return { success: false, error: "Failed to get indices" };
    }
    
    const respMerkleZk = await fetch(`http://localhost:3000/api/merkle_path/meika-zk/${respIndices.indices!.zk}`);
    if (!respMerkleZk.ok) {
      logError('Background', 'Error getting ZK path');
      return { success: false, error: "Failed to get ZK path" };
    }
    const respMerkleDvv = await fetch(`http://localhost:3000/api/merkle_path/meika-dvv/${respIndices.indices!.dvv}`);
    if (!respMerkleDvv.ok) {
      logError('Background', 'Error getting DVV path');
      return { success: false, error: "Failed to get DVV path" };
    }
    
    let merkleZk: any;
    let merkleDvv: any;
    try {
      merkleZk = await respMerkleZk.json();
      merkleDvv = await respMerkleDvv.json();
    } catch (e) {
      logError('Background', 'Error getting merkle data:', e);
      return { success: false, error: "Failed to get merkle data" };
    }
    
    const merkleData: MerkleData = {
      rootZk: hexToBigInt(merkleZk.data.root),
      rootDvv: hexToBigInt(merkleDvv.data.root),
      pathZk: hexArrayToBigIntArray(merkleZk.data.path),
      pathDvv: hexArrayToBigIntArray(merkleDvv.data.path),
      idxZk: merkleZk.data.pathIndices.map(BigInt),
      idxDvv: merkleDvv.data.pathIndices.map(BigInt),
    }
    
    return { success: true, merkleData: merkleData };
  },
  
  confirmLogin: async () => {
    if (!loginRequest) {
      logError('Background', 'No login request found');
      return { success: false, error: 'No login request found' };
    }
    
    logInfo('Background', 'Confirming login');
    
    // Public key
    const respPubKey = await vaultAPI.getPublicKey();
    if (!respPubKey.success) {
      logError('Background', 'Error getting public key');
      return { success: false, error: "Failed to get public key" };
    }
    
    // DVV commitment
    const respDVV = await vaultAPI.getDVVCommitment();
    if (!respDVV.success) {
      logError('Background', 'Error getting DVV commitment');
      return { success: false, error: "Failed to get DVV commitment" };
    }
    
    // Registration signature
    const respRegSig = await vaultAPI.sign(REGISTRATION_MESSAGE);
    if (!respRegSig.success) {
      logError('Background', 'Error signing registration message');
      return { success: false, error: "Failed to sign registration message" };
    }
    
    // Service ID hash
    const serviceId = domainToServiceId(loginRequest.request.domain);
    const respHashService = await vaultAPI.poseidonHash(serviceId);
    if (!respHashService.success) {
      logError('Background', 'Error hashing service ID:', serviceId);
      return { success: false, error: "Failed to hash service ID" };
    }
    
    // Login signature (serviceId || challenge)
    const respHashLogin = await vaultAPI.poseidonHash([respHashService.hash!, BigInt(loginRequest.request.challenge)]);
    if (!respHashLogin.success) {
      logError('Background', 'Error hashing login challenge:', respHashService.hash, loginRequest.request.challenge);
      return { success: false, error: "Failed to hash login challenge" };
    }
    
    const respSigLogin = await vaultAPI.sign(respHashLogin.hashArr!);
    if (!respSigLogin.success) {
      logError('Background', 'Error signing login challenge:', respHashLogin.hash);
      return { success: false, error: "Failed to sign login challenge" };
    }
    
    // Service ID signature
    const respSigService = await vaultAPI.sign(respHashService.hashArr!);
    if (!respSigService.success) {
      logError('Background', 'Error signing service ID:', respHashService.hash);
      return { success: false, error: "Failed to sign service ID" };
    }
    
    // Nonce
    const nonce = getRandomFr();
    
    // Get merkle inclusion proofs
    // TODO: leaks info, change
    logInfo('Background', 'Getting merkle data for login proof');
    const respMerkle = await backgroundAPI.getMerkleData();
    if (!respMerkle.success) {
      logError('Background', 'Error getting merkle data');
      return { success: false, error: "Failed to get merkle data" };
    }
    
    // Build inputs to login circuit
    const params: LoginParams = {
      rootDvv: respMerkle.merkleData!.rootDvv,
      rootZk: respMerkle.merkleData!.rootZk,
      serviceId: respHashService.hash!,
      challenge: BigInt(loginRequest.request.challenge),
      pk: respPubKey.pubKey!,
      dvv: respDVV.dvvCommitment!,
      sigReg: respRegSig.signature!,
      sigLogin: respSigLogin.signature!,
      sigService: respSigService.signature!,
      nonce: nonce,
      pathDvv: respMerkle.merkleData!.pathDvv,
      idxDvv: respMerkle.merkleData!.idxDvv,
      pathZk: respMerkle.merkleData!.pathZk,
      idxZk: respMerkle.merkleData!.idxZk,
    }
    
    const inputs = buildLoginInputs(params);
    logInfo('Background', `Built inputs for logging in to ${serviceId}`);
    return { success: true, inputs: inputs };
  },
  
  fullProveLogin: async (inputs: CircuitSignals) => {
    if (!loginRequest) {
      logError('Background', 'No login request found');
      return { success: false, error: 'No login request found' };
    }
    
    try {
      const wasmUrl = browser.runtime.getURL('build/meika-login.wasm');
      const zkeyUrl = browser.runtime.getURL('build/meika-login.zkey');
      
      // TODO: clean up
      const wrk = new Worker(browser.runtime.getURL('build/witness-worker.bundle.js'), { type: 'module' });
      const wrkApi: Comlink.Remote<{
        fullProve: (inputs: CircuitSignals, wasmUrl: string, zkeyUrl: string) => Promise<{ success: boolean, proof: any, publicSignals: any }>;
      }> = Comlink.wrap(wrk);
      
      logInfo('Background', 'Proving login...');
      const resp = await wrkApi.fullProve(inputs, wasmUrl, zkeyUrl);
      
      loginRequest.port.postMessage({
        type: WebMessageType.LOGIN_RESPONSE,
        content: {
          proof: resp.proof,
          publicSignals: resp.publicSignals,
          origin: loginRequest.request.origin
        } as LoginResponseContent
      });
      logInfo('Background', 'Login proof forwarded to content script');
      
      loginRequest = undefined;
      
      return { success: true };
    } catch (e) {
      logError('Background', 'Error proving login:', e);
      return { success: false, error: "Failed to prove login" };
    }
  },
  
  // TODO: remove
  poseidonHash: async (input: string) => {
    const resp = await vaultAPI.poseidonHash(input);
    if (!resp.success) {
      logError('Background', 'Error hashing message:', input);
      return { success: false, error: resp.error || "Failed to hash message" };
    }
    return { success: true, hash: resp.hash };
  }
}

// Handle connections from the popup and setup page
// TODO: dont import the deprecated polyfill lib for this
browser2.runtime.onConnect.addListener(port => {
  if (port.sender == undefined || port.sender.id !== browser.runtime.id) {
    //logInfo('Background', `Received connection from unknown sender: <${port.sender?.id}>`);
    return;
  }
  
  if (port.name.startsWith('popup-background-') || port.name.startsWith('vault-setup-')) {
    logDebug('Background', `<${port.name}> connected, exposing API`);
    
    Comlink.expose(backgroundAPI, createBackgroundEndpoint(port));
    
    port.onDisconnect.addListener(() => {
      logDebug('Background', `<${port.name}> disconnected`);
    });
  }
});

// Handle messages from the content script
browser.runtime.onConnect.addListener(port => {
  if (port.sender == undefined || port.sender.id !== browser.runtime.id) {
    //logInfo('Background', `Received connection from unknown sender: <${port.sender?.id}>`);
    return;
  }
  
  if (port.name !== 'meika-content-script') {
    //logInfo('Background', `Received connection from unknown port: <${port.name}>`);
    return;
  }
  
  port.onMessage.addListener(message => {
    const msg = message as WebMessage;
    logDebug('Background', `Received <${msg.type}> message from content script`);
    switch (msg.type) {
      case WebMessageType.SIGNATURE_REQUEST:
      backgroundAPI.requestSignature(msg.content.message, msg.content.domain, msg.origin, port);
      break;
      
      case WebMessageType.SUBMIT_PROOF:
      const proof = msg.content as RegistrationProof;
      backgroundAPI.requestAddProof(proof, msg.origin, port);
      break;
      
      case WebMessageType.LOGIN_REQUEST:
      const request = msg.content as LoginRequest;
      backgroundAPI.requestLogin(request.domain, request.challenge, msg.origin, port);
      break;
      
      default:
      logError('Background', `Received unknown message type: <${msg.type}>`);
      break;
    }
  });
});

async function initializeVault(data: InitData) {
  if (state.initialized) {
    logError('Background', 'Vault state already initialized');
    return;
  }
  
  if (!data || !data.masterKeySalt || !data.masterKeyHash || !data.encryptedSymmetricKey || !data.encryptedPrivateKey) {
    logError('Background', 'Missing initialization data');
    return;
  }
  
  state.initialized = true;
  state.masterKeySalt = data.masterKeySalt;
  state.masterKeyHash = data.masterKeyHash;
  state.encryptedSymmetricKey = data.encryptedSymmetricKey;
  state.encryptedPrivateKey = data.encryptedPrivateKey;
  
  await saveState();
}

async function openPopup() {
  const w = await browser.windows.getCurrent();
  browser.windows.create({
    url: browser.runtime.getURL("build/popup.html"),
    type: "popup",
    width: 352,
    height: 464,
    left: w.left! + w.width! - 412,
    top: w.top! + 80
  });
}

function hexToBigInt(hex: string): bigint {
  return BigInt(hex.startsWith('0x') ? hex : '0x' + hex);
}

function hexArrayToBigIntArray(hexArray: string[]): bigint[] {
  return hexArray.map(hexToBigInt);
}