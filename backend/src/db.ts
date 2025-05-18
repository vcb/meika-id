import Database from 'better-sqlite3';
import path from 'path';
import { MerkleTree } from './merkle.js';
const db = new Database(path.resolve(process.cwd(), 'data/merkle.db'));

// Initialize schemas if not present

db.exec(`
  CREATE TABLE IF NOT EXISTS trees (
    id TEXT PRIMARY KEY,
    depth INTEGER NOT NULL,
    leavesCount INTEGER NOT NULL,
    nodes TEXT NOT NULL -- Stored as JSON stringified object of node_index -> value
  );
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS proofs (
    nullifier TEXT PRIMARY KEY,
    proof TEXT NOT NULL,
    publicSignals TEXT NOT NULL
  );
`);

export function saveTree(tree: MerkleTree) {
  console.log("Saving tree", tree.id)
  const stmt = db.prepare(`
    INSERT INTO trees (id, depth, leavesCount, nodes)
    VALUES (@id, @depth, @leavesCount, @nodes)
    ON CONFLICT(id) DO UPDATE SET
      depth = excluded.depth,
      leavesCount = excluded.leavesCount,
      nodes = excluded.nodes
  `);
  
  const nodesObject = tree.getNodesObject();
  
  stmt.run({
    id: tree.id,
    depth: tree.depth,
    leavesCount: tree.leavesCount,
    nodes: JSON.stringify(nodesObject),
  });
}

export interface SerializedMerkleTree {
  id: string;
  depth: number;
  leavesCount: number;
  nodes: Record<string, string>; // Map of node_index -> value as strings
}

export interface SerializedMerkleTreeRaw {
  id: string;
  depth: number;
  leavesCount: number;
  nodes: string; // JSON stringified object of node_index -> value
}

export function loadTree(id: string): SerializedMerkleTree | null {
  const stmt = db.prepare(`SELECT * FROM trees WHERE id = ?`);
  const row = stmt.get(id) as SerializedMerkleTreeRaw;
  if (!row) return null;
  
  const nodeEntries = JSON.parse(row.nodes) as Record<string, string>;
  console.log(`Loaded tree ${id} with depth ${row.depth}, leavesCount ${row.leavesCount} and ${Object.keys(nodeEntries).length} non-default nodes`);
  
  return {
    id: row.id,
    depth: row.depth,
    leavesCount: row.leavesCount,
    nodes: nodeEntries,
  };
}

export function checkIfTreeExists(id: string): boolean {
  const stmt = db.prepare("SELECT COUNT(*) as count FROM trees WHERE id = ?");
  const row = stmt.get(id) as { count: number };
  const count = row.count;
  return count > 0;
}

export function getAllTreeIds(): string[] {
  const stmt = db.prepare(`SELECT id FROM trees`);
  const rows = stmt.all() as SerializedMerkleTreeRaw[];
  return rows.map(row => row.id);
}

export function saveProof(nullifier: bigint, proof: any, publicSignals: any) {
  const stmt = db.prepare(`INSERT INTO proofs (nullifier, proof, publicSignals) VALUES (@nullifier, @proof, @publicSignals)`);
  stmt.run({ 
    nullifier: nullifier.toString(), 
    proof: JSON.stringify(proof), 
    publicSignals: JSON.stringify(publicSignals) 
  });
}

export function checkIfNullifierExists(nullifier: bigint): boolean {
  const stmt = db.prepare("SELECT COUNT(*) as count FROM proofs WHERE nullifier = ?");
  const row = stmt.get(nullifier.toString()) as { count: number };
  const count = row.count;
  return count > 0;
}

export function getNullifierCount(): number {
  const stmt = db.prepare("SELECT COUNT(*) as count FROM proofs");
  const row = stmt.get() as { count: number };
  return row.count;
}