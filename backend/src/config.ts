export const FIELD_CHECK_MODES = {
  STRICT: 'strict',
  WARN: 'warn',
  DISABLED: 'disabled',
} as const;

export const TREE_IDS = {
  DVV: 'meika-dvv',
  ZK: 'meika-zk',
} as const;

export const TREE_DEPTH = 23;

export const MAX_BODY_SIZE = 1024 * 1024; // 1MB

export const config = {
  port: parseInt(process.env.PORT || '3000'),
  env: process.env.NODE_ENV || 'development',
  corsOrigin: process.env.CORS_ORIGIN || 'http://localhost:4000',
  fieldCheckMode: process.env.FIELD_CHECK_MODE || FIELD_CHECK_MODES.STRICT,
  dvvMerkleTreeId: process.env.DVV_MERKLE_TREE_ID || TREE_IDS.DVV,
  zkMerkleTreeId: process.env.ZK_MERKLE_TREE_ID || TREE_IDS.ZK,
  merkleDepth: parseInt(process.env.MERKLE_DEPTH || TREE_DEPTH.toString()),
  maxBodySize: parseInt(process.env.MAX_BODY_SIZE || MAX_BODY_SIZE.toString()),
};

export function validateConfig() {
  // Add validation logic
  console.log(`Server port: ${config.port}`);
  console.log(`Environment: ${config.env}`);
  console.log(`CORS origin: ${config.corsOrigin}`);
  console.log(`Field check mode: ${config.fieldCheckMode}`);
} 