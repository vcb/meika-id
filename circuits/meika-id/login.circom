pragma circom 2.1.9;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/eddsaposeidon.circom";
include "circomlib/circuits/mux1.circom";

// Version 1
// Identity Registration message:
/*
Meika ID
Version: 1
Action: Identity Registration

SECURITY WARNING:
This signature creates a cryptographic link to your legal identity.
If you're being asked to sign this message outside of the official Meika application, extension or website, someone may be attempting to impersonate you.
Only sign this message on the official Meika platform.
*/
// Service ID prefix: "meika-id::"

template MeikaLogin() {
    signal output nullifier;         // Poseidon(pubkey || serviceId || nonce)
    signal output serviceCommitment; // Poseidon(Sig(serviceId))

    // Public inputs
    signal input rootDvv;   // Merkle root of the dvv-identity commitment tree
    signal input rootZk;    // Merkle root of the zk-identity commitment tree
    signal input serviceId; // Poseidon(prefix || domain)
    signal input challenge; // Server-supplied challenge

    // Private inputs
    signal input pk[2];         // Babyjub EdDSA public key, field elements
    signal input dvv;           // Fr
    signal input sigReg[3];     // S, Rx, Ry; over Poseidon(registration_message)
    signal input sigLogin[3];   // S, Rx, Ry; over Poseidon(serviceId || challenge)
    signal input sigService[3]; // S, Rx, Ry; over serviceId;
    signal input nonce;         // Fr
    signal input pathDvv[23];   // Fr
    signal input idxDvv[23];    // 0=left, 1=right
    signal input pathZk[23];
    signal input idxZk[23];
    

    // 1. Signature verification

    component msgLogin = Poseidon(2);
    msgLogin.inputs[0] <== serviceId;
    msgLogin.inputs[1] <== challenge;

    component verifyLogin = EdDSAPoseidonVerifier();
    verifyLogin.enabled <== 1;
    verifyLogin.Ax <== pk[0];
    verifyLogin.Ay <== pk[1];
    verifyLogin.S <== sigLogin[0];
    verifyLogin.R8x <== sigLogin[1];
    verifyLogin.R8y <== sigLogin[2];
    verifyLogin.M <== msgLogin.out;

    component msgReg = CommitmentHash();

    component verifyReg = EdDSAPoseidonVerifier();
    verifyReg.enabled <== 1;
    verifyReg.Ax <== pk[0];
    verifyReg.Ay <== pk[1];
    verifyReg.S <== sigReg[0];
    verifyReg.R8x <== sigReg[1];
    verifyReg.R8y <== sigReg[2];
    verifyReg.M <== msgReg.out;

    component verifyService = EdDSAPoseidonVerifier();
    verifyService.enabled <== 1;
    verifyService.Ax <== pk[0];
    verifyService.Ay <== pk[1];
    verifyService.S <== sigService[0];
    verifyService.R8x <== sigService[1];
    verifyService.R8y <== sigService[2];
    verifyService.M <== serviceId;


    // 2. Prove inclusions of both registration commitments

    component leafZk = Poseidon(3);
    leafZk.inputs[0] <== sigReg[0];
    leafZk.inputs[1] <== sigReg[1];
    leafZk.inputs[2] <== sigReg[2];

    component mpZk = MerkleInclusionProof(23);
    mpZk.leaf <== leafZk.out;
    mpZk.path <== pathZk;
    mpZk.indices <== idxZk;
    mpZk.root <== rootZk;

    component mpDvv = MerkleInclusionProof(23);
    mpDvv.leaf <== dvv;
    mpDvv.path <== pathDvv;
    mpDvv.indices <== idxDvv;
    mpDvv.root <== rootDvv;


    // 3. Nullifier calculation

    component hashNullifier = Poseidon(4);
    hashNullifier.inputs[0] <== pk[0];
    hashNullifier.inputs[1] <== pk[1];
    hashNullifier.inputs[2] <== serviceId;
    hashNullifier.inputs[3] <== nonce;

    hashNullifier.out ==> nullifier;

    component hashService = Poseidon(3);
    hashService.inputs[0] <== sigService[0];
    hashService.inputs[1] <== sigService[1];
    hashService.inputs[2] <== sigService[2];

    hashService.out ==> serviceCommitment;
}

template MerkleInclusionProof(depth) {
    signal input leaf;
    signal input path[depth];
    signal input indices[depth]; // 0=left, 1=right
    signal input root; 

    // TODO: Not sure if we can just skip wirings here
    var cur = leaf;
    var idx;

    component hashers[depth];
    component muxL[depth];
    component muxR[depth];
    for (var i = 0; i < depth; i++) {
        hashers[i] = Poseidon(2);

        idx = indices[i];
        idx * (idx - 1) === 0; // Ensure boolean
        
        muxL[i] = Mux1();
        muxR[i] = Mux1();

        muxL[i].c[0] <== cur;
        muxL[i].c[1] <== path[i];
        muxL[i].s <== idx;

        muxR[i].c[0] <== path[i];
        muxR[i].c[1] <== cur;
        muxR[i].s <== idx;

        hashers[i].inputs[0] <== muxL[i].out;
        hashers[i].inputs[1] <== muxR[i].out;

        cur = hashers[i].out;
    }

    root === cur;
}

// Poseidon digest of the registration message
template CommitmentHash() {
    signal output out;
    out <== 16545280559118309720992774606760969325180593643479798061564279595779287712735;
}

component main {public [rootDvv, rootZk, serviceId, challenge]} = MeikaLogin();