// Generic API Response Types
export interface ApiResponse<T = undefined> {
    message: string;
    status: string;
    env?: string;
    data?: T;
}

export type RegistrationProof = {
  proof: Proof;
  publicSignals: SignalOutputs;
  dvvIndex: number;
  zkIndex: number;
}

export type Proof = {
  pi_a: [string, string, string];
  pi_b: [[string, string], [string, string], [string, string]];
  pi_c: [string, string, string];
  protocol: string;
}

export type SignalOutputs = {
  zkCommitment: string;
  dvvCommitment: string;
  nullifier: string;
}

export type LoginRequest = {
  domain: string;
  challenge: string;
  origin: string;
}

export type LoginResponseContent = {
  proof: any;
  publicSignals: any;
  origin: string;
}

export type SignatureRequest = {
  message: string | bigint[];
  domain: string;
  origin: string;
}

export interface SignatureResponseContent {
  pk: [bigint, bigint];
  signature: [bigint, bigint, bigint];
  packed: Uint8Array;
  origin: string;
}

export interface ApiProofResultData {
    proofId: string;
    verificationResult: boolean;
    merklePath: ApiMerklePathData;
}

export interface ApiMerklePathData {
    leafIndex: number;
    path: string[];         // Array of hash values along the path
    pathIndices: number[]; // 0 for left, 1 for right at each level
    root: string;
}

export interface ApiMerkleTreeData {
    root: string;
    depth: number;
    leavesCount: number;
}

export type ApiProofSubmissionResponse = ApiResponse<ApiProofResultData>;
export type ApiMerklePathResponse = ApiResponse<ApiMerklePathData>;
export type ApiMerkleTreeResponse = ApiResponse<ApiMerkleTreeData>;

export interface ApiErrorResponse {
    error: string;
    code?: number;
} 

export enum WebMessageType {
  PING = 'MEIKA_PING',
  PONG = 'MEIKA_PONG',
  SIGNATURE_REQUEST = 'MEIKA_SIGNATURE_REQUEST',
  SIGNATURE_RESPONSE = 'MEIKA_SIGNATURE_RESPONSE',
  SUBMIT_PROOF = 'MEIKA_SUBMIT_PROOF',
  PROOF_SUBMISSION_RESPONSE = 'MEIKA_PROOF_SUBMISSION_RESPONSE',
  LOGIN_REQUEST = 'MEIKA_LOGIN_REQUEST',
  LOGIN_RESPONSE = 'MEIKA_LOGIN_RESPONSE',
}

export interface WebMessage {
  type: WebMessageType;
  content: any;
  origin: string;
}