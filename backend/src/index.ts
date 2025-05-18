import { Context, Hono, Next } from 'hono';
import { serve } from '@hono/node-server';
import { logger } from 'hono/logger';
import { cors } from 'hono/cors';
import fs from 'node:fs';
import path from 'node:path';
import { config, validateConfig } from './config.js';
import type { 
  ProofContent, 
  ApiProofSubmissionResponse, 
  ApiMerklePathData, 
  ApiMerklePathResponse, 
  ApiMerkleTreeData, 
  ApiMerkleTreeResponse
} from '@lib/types';
import { verifyRegistrationProof } from './proofs.js';
import { MerkleTree } from './merkle.js';
import { saveTree, checkIfTreeExists, loadTree, getAllTreeIds, checkIfNullifierExists, saveProof, getNullifierCount } from './db.js';


validateConfig();

let dvvMerkleTree: MerkleTree | null = null;
let zkMerkleTree: MerkleTree | null = null;

if (!checkIfTreeExists(config.dvvMerkleTreeId)) {
  console.log('DVV commitment tree not found, creating new one');
  dvvMerkleTree = new MerkleTree(config.dvvMerkleTreeId, config.merkleDepth);
  saveTree(dvvMerkleTree);
} else {
  const serializedTree = loadTree(config.dvvMerkleTreeId);
  if (!serializedTree) {
    throw new Error('Failed to load DVV commitment tree');
  }
  dvvMerkleTree = MerkleTree.fromSerialized(serializedTree);
}

if (!checkIfTreeExists(config.zkMerkleTreeId)) {
  console.log('ZK commitment tree not found, creating new one');
  zkMerkleTree = new MerkleTree(config.zkMerkleTreeId, config.merkleDepth);
  saveTree(zkMerkleTree);
} else {
  const serializedTree = loadTree(config.zkMerkleTreeId);
  if (!serializedTree) {
    throw new Error('Failed to load ZK commitment tree');
  }
  zkMerkleTree = MerkleTree.fromSerialized(serializedTree);
}

console.log(`Nullifier count: ${getNullifierCount()}`);

const app = new Hono();
const api = new Hono();

api.post('/submit_proof', async (c) => {
  try {
    const req: ProofContent = await c.req.json<ProofContent>();
    console.log('Received request for proof submission')
    
    const verified = await verifyRegistrationProof(req.proof, req.publicSignals);
    
    console.log(`Proof verification status: ${verified}`)
    
    if (!verified) {
      return c.json({
        message: 'Proof verification failed',
        status: 'error',
        data: undefined
      }, 400);
    }
    
    // Extract commitments and nullifier from signals
    const zkCommitment = BigInt(req.publicSignals[0]);
    const dvvCommitment = BigInt(req.publicSignals[1]);
    const nullifier = BigInt(req.publicSignals[2]);
    
    // Stop if user has already registered
    if (checkIfNullifierExists(nullifier)) {
      return c.json({
        message: 'Nullifier already exists',
        status: 'error',
        data: undefined
      }, 400);
    }
    
    // Save proof
    saveProof(nullifier, req.proof, req.publicSignals);
    
    // Add both commitments to merkle tree
    if (!zkMerkleTree || !dvvMerkleTree) {
      return c.json({
        message: 'Merkle trees not initialized',
        status: 'error',
        data: undefined
      }, 500);
    }
    
    // Insert into the Merkle tree
    const zkLeafIndex = zkMerkleTree.insert(zkCommitment);
    const dvvLeafIndex = dvvMerkleTree.insert(dvvCommitment);
    
    // Save the updated trees
    saveTree(zkMerkleTree);
    saveTree(dvvMerkleTree);
    
    const response: ApiProofSubmissionResponse = {
      message: 'Proof submitted successfully',
      status: 'accepted',
      data: {
        zkIndex: zkLeafIndex,
        dvvIndex: dvvLeafIndex,
        zkRoot: '0x' + zkMerkleTree.getRoot().toString(16).padStart(64, '0'),
        dvvRoot: '0x' + dvvMerkleTree.getRoot().toString(16).padStart(64, '0')
      }
    };
    return c.json(response);
  } catch (error) {
    console.error('Error processing proof submission:', error);
    return c.json({
      message: 'Error submitting proof',
      status: 'error',
      data: undefined
    }, 500);
  }
});

api.get('/merkle_path/:tree_id/:leaf_index', (c) => {
  const treeId = c.req.param('tree_id');
  const leafIndex = parseInt(c.req.param('leaf_index'));
  
  let merkleTree: MerkleTree | null = null;
  
  if (treeId === config.zkMerkleTreeId) {
    merkleTree = zkMerkleTree;
  } else if (treeId === config.dvvMerkleTreeId) {
    merkleTree = dvvMerkleTree;
  } else {
    return c.json({
      message: 'Invalid tree ID',
      status: 'error',
      data: undefined
    }, 400);
  }
  
  if (!merkleTree) {
    return c.json({
      message: 'Merkle tree not initialized',
      status: 'error',
      data: undefined
    }, 500);
  }
  
  try {
    const { path, pathIndices } = merkleTree.buildProof(leafIndex);

    const merklePathData: ApiMerklePathData = {
      leafIndex: leafIndex,
      path: path.map(p => '0x' + p.toString(16).padStart(64, '0')),
      pathIndices: pathIndices,
      root: '0x' + merkleTree.getRoot().toString(16).padStart(64, '0')
    };
    
    const response: ApiMerklePathResponse = {
      message: 'Merkle path retrieved successfully',
      status: 'success',
      data: merklePathData
    };
    
    return c.json(response);
  } catch (error) {
    console.error('Error getting merkle path:', error);
    return c.json({
      message: 'Error getting merkle path',
      status: 'error',
      data: undefined
    }, 500);
  }
});

api.get('/root/:tree_id', (c) => {
  const treeId = c.req.param('tree_id');
  let merkleTree: MerkleTree | null = null;
  
  if (treeId === config.zkMerkleTreeId) {
    merkleTree = zkMerkleTree;
  } else if (treeId === config.dvvMerkleTreeId) {
    merkleTree = dvvMerkleTree;
  } else {
    return c.json({
      message: 'Invalid tree ID',
      status: 'error',
      data: undefined
    }, 400);
  }
  
  if (!merkleTree) {
    return c.json({
      message: 'Merkle tree not initialized',
      status: 'error',
      data: undefined
    }, 500);
  }
  
  const root = merkleTree.getRoot();
  const response: ApiMerkleTreeResponse = {
    message: 'Merkle tree root retrieved successfully',
    status: 'success',
    data: { root: '0x' + root.toString(16).padStart(64, '0') }
  };
  return c.json(response);
}); 

// Middleware
const checkLength = async (c: Context, next: Next) => {
  const raw = c.req.raw;
  const contentLength = raw.headers.get('content-length');
  if (contentLength && parseInt(contentLength) > config.maxBodySize) {
    return c.json({ message: 'Request body too large', status: 'error', data: undefined }, 413);
  }
  await next();
}
app.use('*', checkLength);

const setCSP = async (c: Context, next: Next) => {
  c.res.headers.set(
    'Content-Security-Policy', 
    "default-src 'none';" + 
    "script-src 'self';" +
    "connect-src 'self';"
  )
  await next();
}
app.use('*', setCSP);
app.use('*', logger());
app.use('*', cors({
  origin: config.corsOrigin,
  allowHeaders: ['Content-Type', 'Authorization'],
  allowMethods: ['GET', 'POST', 'OPTIONS'],
  exposeHeaders: ['Content-Type', 'Authorization']
}));

app.route('/api', api);

// Start the server
serve({
  fetch: app.fetch,
  port: config.port,
});

console.log(`Server running at http://localhost:${config.port} in ${config.env} mode`);

