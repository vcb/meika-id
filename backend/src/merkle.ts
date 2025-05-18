import { buildPoseidon, type Poseidon } from 'circomlibjs';
import { buildBabyjub, type BabyJub } from 'circomlibjs';
import { config, FIELD_CHECK_MODES } from './config.js';
import { SerializedMerkleTree } from './db.js';


const MAX_INPUTS = 16;
const CHECK_MODE = config.fieldCheckMode;

const poseidon: Poseidon = await buildPoseidon();
const babyjub: BabyJub = await buildBabyjub();
const p: bigint = poseidon.F.p;

function isInField(n: bigint): boolean {
  return n < p;
}

/**
 * Checks if a number is in the BN254 field. If strict mode is enabled, it will throw an error.
 * @param n - The number to check.
 */
function checkIfInField(n: bigint): void {
  if (CHECK_MODE === FIELD_CHECK_MODES.DISABLED) {
    return;
  }

  if (!isInField(n)) {
    if (CHECK_MODE === FIELD_CHECK_MODES.STRICT) {
      throw new Error(`Number is not in the field: ${n}`);
    } else if (CHECK_MODE === FIELD_CHECK_MODES.WARN) {
      console.warn(`Number is not in the field: ${n}`);
    }
  }
}

/**
 * Hashes an array of inputs using the poseidon hash function. Checks if all inputs are in the field.
 * 
 * @param inputs - The inputs to hash. Can be an array of bigints or number strings.
 * @returns The hash of the inputs.
 */
export function hash(inputs: bigint | bigint[] | string[]): bigint {
  if (typeof inputs === 'bigint') {
    inputs = [inputs];
  }
  if (inputs.length > MAX_INPUTS) {
    throw new Error(`Maximum number of inputs is ${MAX_INPUTS}`);
  }
  for (const input of inputs) {
    if (typeof input === 'string') {
      checkIfInField(BigInt(input));
    } else {
      checkIfInField(input);
    }
  }
  try {
    return poseidon.F.toObject(poseidon(inputs));
  } catch (error) {
    console.error(`Failed to hash inputs: ${error}`);
    throw new Error(`Failed to hash inputs: ${error}`);
  }
}

/**
 * Merkle tree class. Default values are generated and only non-default nodes are stored.
 * Uses a Map for efficient storage of sparse tree.
 */
export class MerkleTree {
  public id: string;
  public depth: number;
  public leavesCount: number;
  private nodes: Map<number, bigint>;
  private defaults: bigint[];

  constructor(id: string, depth: number) {
    this.id = id;
    this.depth = depth;
    this.leavesCount = 0;
    this.nodes = new Map<number, bigint>();
    this.defaults = this.generateDefaults();
  }

  /**
   * Creates a new MerkleTree from a serialized object.
   * @param serialized - The serialized object.
   * @returns A new MerkleTree.
   */
  static fromSerialized(serialized: SerializedMerkleTree): MerkleTree {
    const tree = new MerkleTree(serialized.id, serialized.depth);
    tree.leavesCount = serialized.leavesCount;
    
    // Add nodes
    for (const [indexStr, value] of Object.entries(serialized.nodes)) {
      const index = parseInt(indexStr);
      tree.nodes.set(index, BigInt(value));
    }
    
    return tree;
  }
  
  /**
   * Generates the default values for the merkle tree.
   * @returns Array of default values at each depth
   */
  private generateDefaults(): bigint[] {
    const defaults = new Array(this.depth + 1).fill(0n);
    defaults[this.depth] = hash(0n);

    for (let i = this.depth - 1; i >= 0; i--) {
      const child = defaults[i + 1];
      defaults[i] = hash([child, child]);
    }
    
    return defaults;
  }

  /**
   * Gets a node value, falling back to default if not explicitly set
   * @param index - The index of the node
   * @returns The node value
   */
  private getNodeValue(index: number): bigint {
    // If node exists in our sparse map, return it
    const nodeValue = this.nodes.get(index);
    if (nodeValue !== undefined) {
      return nodeValue;
    }
    
    // Otherwise use the default value for the depth
    const depth = this.getDepthForIndex(index);
    return this.defaults[depth]!;
  }

  /**
   * Updates the nodes of the merkle tree, propagating up the tree from the leaf.
   * Only stores nodes that differ from their default values.
   * @param leafIndex - The index of the leaf node.
   */
  private updateNodes(leafIndex: number): void {
    let currentIndex = leafIndex;
    //console.log(`Updating nodes for leaf index: ${leafIndex}`);
    
    for (let level = 0; level < this.depth; level++) {
      const parentIndex = this.parentIndex(currentIndex);
      //console.log(`Updating node at index: ${parentIndex}`);
      
      const leftChild = this.getNodeValue(this.leftChildIndex(parentIndex));
      const rightChild = this.getNodeValue(this.rightChildIndex(parentIndex));
      
      //console.log(`leftChild: ${leftChild} (index: ${this.leftChildIndex(parentIndex)}), rightChild: ${rightChild} (index: ${this.rightChildIndex(parentIndex)})`);
      
      const newValue = hash([leftChild, rightChild]);
      const depth = this.getDepthForIndex(parentIndex);
      
      // Only store if different from default
      if (newValue !== this.defaults[depth]) {
        this.nodes.set(parentIndex, newValue);
      } else if (this.nodes.has(parentIndex)) {
        // If it matches default and was previously stored, remove it
        this.nodes.delete(parentIndex);
      }
      
      currentIndex = parentIndex;
    }
  }

  /**
   * Gets the depth for a given node index
   * @param index - The node index
   * @returns The depth in the tree
   */
  private getDepthForIndex(index: number): number {
    return Math.floor(Math.log2(index + 1));
  }

  /**
   * Inserts a new leaf node into the merkle tree.
   * @param hash - The hash to insert.
   * @returns The index of the inserted node.
   */
  public insert(hash: bigint): number {
    checkIfInField(hash);
    if (this.leavesCount >= 2 ** this.depth) {
      throw new Error("Merkle tree is full");
    }
    
    const index = this.leavesCount + 2 ** this.depth - 1;
    
    // Only store if different from default
    if (hash !== this.defaults[this.depth]) {
      this.nodes.set(index, hash);
    }
    
    this.leavesCount++;
    this.updateNodes(index);
    return index;
  }

  /**
   * Builds a proof for a given leaf index.
   * @param leafIndex - The index of the leaf node.
   * @returns An object containing the proof path and the path indices.
   */
  public buildProof(leafIndex: number): { path: bigint[], pathIndices: number[] } {
    //console.log(`Building proof for leaf index: ${leafIndex}`);
    const path = [];
    const pathIndices = [];
    let currentIndex = leafIndex;
    
    for (let level = 0; level < this.depth; level++) {
      const sibling = this.getSibling(currentIndex);
      path.push(sibling);
      pathIndices.push(this.childSide(currentIndex));
      currentIndex = this.parentIndex(currentIndex);
    }
    
    return { path, pathIndices };
  }

  /**
   * Verifies a proof for a given leaf.
   * @param leaf - The leaf node.
   * @param proof - The proof path.
   * @param proofIndices - The path indices.
   * @returns True if the proof is valid, false otherwise.
   */
  public verifyProof(leaf: bigint, proof: bigint[], proofIndices: number[]): boolean {
    let current = leaf;
    
    for (let i = 0; i < proof.length; i++) {

      const sibling = proof[i];
      const side = proofIndices[i];
      const [l, r] = side === 0 ? [current, sibling] : [sibling, current];
      current = hash([l!, r!]);
    }
    
    return current === this.getRoot();
  }

  /**
   * Returns the node at a given index.
   * @param index - The index of the node.
   * @returns The node at the given index.
   */
  public getNode(index: number): bigint {
    return this.getNodeValue(index);
  }

  /**
   * Gets the sibling node for a given index
   * @param index - The index of the node
   * @returns The sibling node value
   */
  public getSibling(index: number): bigint {
    const parentIndex = this.parentIndex(index);
    const siblingIndex = this.childSide(index) === 0 
      ? this.rightChildIndex(parentIndex) 
      : this.leftChildIndex(parentIndex);
    
    return this.getNodeValue(siblingIndex);
  }

  /**
   * Returns the side of the child (0 for left, 1 for right)
   * @param index - The index of the child node
   * @returns The side of the child (0 for left, 1 for right)
   */
  public childSide(index: number): number {
    return index % 2 === 0 ? 1 : 0;
  }

  public leftChildIndex(index: number): number {
    return 2 * index + 1;
  }

  public rightChildIndex(index: number): number {
    return 2 * index + 2;
  }

  public parentIndex(index: number): number {
    return Math.floor((index - 1) / 2);
  }

  public indicesAtDepth(depth: number): number[] {
    return Array.from({ length: 2 ** depth }, (_, i) => i + 2 ** depth - 1);
  }

  public getRoot(): bigint {
    return this.getNodeValue(0);
  }

  /**
   * Returns the total number of nodes in a full tree of this depth
   */
  public getNodesCount(): number {
    return 2 ** (this.depth + 1) - 1;
  }

  /**
   * Returns the defaults array
   */
  public getDefaults(): bigint[] {
    return this.defaults;
  }

  /**
   * Returns the non-default nodes as a Map
   */
  public getNodes(): Map<number, bigint> {
    return this.nodes;
  }
  
  /**
   * Returns the non-default nodes as a record object for serialization
   */
  public getNodesObject(): Record<string, string> {
    const result: Record<string, string> = {};
    for (const [key, value] of this.nodes.entries()) {
      result[key.toString()] = value.toString();
    }
    return result;
  }
}