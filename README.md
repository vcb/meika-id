# Meikä ID
[![Bugs](https://sonarcloud.io/api/project_badges/measure?project=vcb_meika-id&metric=bugs)](https://sonarcloud.io/summary/new_code?id=vcb_meika-id)
[![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=vcb_meika-id&metric=vulnerabilities)](https://sonarcloud.io/summary/new_code?id=vcb_meika-id)
[![Code Smells](https://sonarcloud.io/api/project_badges/measure?project=vcb_meika-id&metric=code_smells)](https://sonarcloud.io/summary/new_code?id=vcb_meika-id)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=vcb_meika-id&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=vcb_meika-id)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=vcb_meika-id&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=vcb_meika-id)

## Project Overview

Meikä ID is a privacy-preserving identity and authentication system that leverages the Finnish national electronic ID card infrastructure with zero-knowledge proofs. It allows users to prove they possess a valid Finnish ID card and authenticate to services under a consistent pseudonymous identity—without revealing any personal information.

The system consists of a registration step tied to the user’s DVV-issued RSA public key and a user-chosen BabyJubJub EdDSA key. This produces a cryptographic commitment that can be referenced in future authentications. Each login derives a unique, unlinkable identity per service while maintaining consistency within that service. Circuits are implemented with Circom, proving for both registration and login is designed to be fully local.

Key properties:
1. **ZK-based registration**: ties DVV signed RSA certificate to a user-chosen zk-friendly keypair
2. **Unlinkable logins**: per-service pseudonym, making cross-site tracking more difficult
3. **No PII leakage**: witness generation and proving is local only, only proofs and public outputs are handled via backend


This was written as a course project for `COMP.SEC.300`.

## Components

### 1. Zero-Knowledge Circuits
- **Registration circuit**: Verifies RSA signatures from the eID card and Finnish ID card authority (DVV), and Poseidon EdDSA signatures from extension
- **Login circuit**: Proves inclusion in the Merkle trees and verifies Poseidon EdDSA signatures
- Uses Groth16 zero-knowledge proofs, registration is currently not possible in-browser due to high constraint count
- Builds use trusted setup files from Privacy & Scaling Explorations team's Perpetual Powers of Tau [ceremony](https://github.com/privacy-scaling-explorations/perpetualpowersoftau)

### 2. Browser Extension (Key Manager)
- Securely stores the user's EdDSA keypair and registration proof and public signals
- Handles cryptographic operations (signing challenges over BabyJubJub)
- Stores data encrypted with AES-256-GCM at rest
- Browser's WebCrypto for randomness (CSPRNG) and AES
- Argon2id for key derivation, with params based on OWASP recommendations, using WASM implementation for efficiency

### 3. Web Frontend
- Provides user interface for registration and demonstrating the system
- Communicates with the Finnish ID card through the Atostek ID middleware
- Communicates with the browser extension via a secure protocol
- Handles witness generation for registration proof

### 4. Backend
- Verifies registration proofs
- Maintains Merkle trees of registered identities
- Provides API endpoints for registration and login
- Never sees or stores any personally identifiable information

The system follows a complete privacy-by-design approach.

## Usage

### Building and installing the extension
The extension only work on Firefox due to the use of a background script.

You can build the extension with:
```
npm run build
```

There is no signed version of the extension, so it must be loaded by going to `about:debugging` > `This Firefox` > `Load Temporary Add-on`.

### Running the frontend/backend
Both can be run in development mode with:
```
npm run dev
```

### Compiling the circuits
```
circom -l node_modules meika-id/login.circom --wasm --r1cs
circom -l node_modules meika-id/registration.circom --wasm --r1cs
```
The circuits have 34,524 and 2,175,183 constraints respectively.

Setup:
```
npx snarkjs groth16 setup login.r1cs ppot_0080_16.ptau meika-login.zkey
NODE_OPTIONS=--max-old-space-size=16000" npx snarkjs groth16 setup registration.r1cs ppot_0080_22.ptau meika-registration.zkey
````
Running the setup for registration takes around 5-15 minutes and requires a minimum of 16GB of free RAM with snarkjs. You can get the `ptau` files [from the PSE repo](https://github.com/privacy-scaling-explorations/perpetualpowersoftau).

Ready `zkey` files are available from Google Cloud:
| circuit | proving key | verification key |
| - | - | - |
| login | https://storage.googleapis.com/zkid/meika-login.zkey | https://storage.googleapis.com/zkid/meika-login-vk.json |
| registration | https://storage.googleapis.com/zkid/meika-registration.zkey | https://storage.googleapis.com/zkid/meika-registration-vk.json |

## Status
Meikä ID is currently not production-ready.

### Security Issues
- None of the components have been thoroughly reviewed
- Meikä ID circuits are not reviewed, some imported templates are not recommended to be used in production
- Login fetches direct inclusion path for commitments which leaks data

### TODO
- Testing
- Variable input size SHA-512 circuit
- Extension browser compatibility
- Improve extension cross-script communication
- Improve UX
- Better logging
- ID revocation
- Authentication process, token, cookies, etc
- Authentication lib
- Maybe: Smart contract for registration trees
