pragma circom 2.1.9;

// Import standard libraries
include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/eddsaposeidon.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";

include "../rarimo-rsa/rsa/rsa.circom";
include "../sha2/sha512/sha512_hash_bytes.circom";
include "../sha2/sha2_common.circom";

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


// Main circuit for verifying Finnish eID registration
template MeikaRegistration() {
    signal output zkCommitment;  // Poseidon hash of EdDSA signature over the Poseidon hash of the registration message
    signal output dvvCommitment; // Poseidon hash of RSA signature over the registration message
    signal output nullifier;     // Poseidon hash of the nonce

    // Private inputs
    signal input pkEddsa[2];    // Full field elements
    signal input pkRsa[48];     // RSA-3072 public key as 64-bit limbs
    signal input sigEddsa[3];   // S, Rx, Ry
    signal input sigRsa[48];    // RSA PKCS#1 v1.5 signature as 64-bit limbs (SHA-512)
    signal input sigCa[64];     // CA's signature over the certificate data, RSA-4096 (SHA-512)
    signal input nonce;         // Nonce for replay attack protection

    // DER-encoded personal certificate data
    // This is split into two parts to avoid parsing in-circuit; bytes before and after the RSA public key.
    // TODO: variable input SHA512 implementation
    var CERT_PRE_SIZE = 339;
    var CERT_KEY_SIZE = 384;
    var CERT_POST_SIZE = 589;
    signal input certPreKey[CERT_PRE_SIZE];
    signal input certPostKey[CERT_POST_SIZE];

    // ------------------------------------------------------------------------------------------------
    
    // Constants
    var BYTE_SIZE = 8;
    var RSA_3072_LIMBS = 48;
    var RSA_4096_LIMBS = 64;
    var RSA_LIMB_SIZE = 64;
    var RSA_EXP = 65537;
    var RSA_HASH_SIZE = 512;
    var RSA_HASH_BYTES = RSA_HASH_SIZE / BYTE_SIZE;
    
    // 1. Verify user's RSA and EdDSA signatures
    component verifyRsa = RsaVerifyPkcs1v15(RSA_LIMB_SIZE, RSA_3072_LIMBS, RSA_EXP, RSA_HASH_SIZE);

    for (var i = 0; i < RSA_3072_LIMBS; i++) {
        verifyRsa.signature[i] <== sigRsa[i];
        verifyRsa.pubkey[i] <== pkRsa[i];
    }

    component digestSha = CommitmentDigestSHA512();
    for (var i = 0; i < RSA_HASH_SIZE; i++) {
        verifyRsa.hashed[i] <== digestSha.out[i];
    }

    component digestPoseidon = CommitmentDigestPoseidon();
    component verifyEddsa = EdDSAPoseidonVerifier();
    verifyEddsa.enabled <== 1;
    verifyEddsa.Ax <== pkEddsa[0];
    verifyEddsa.Ay <== pkEddsa[1];
    verifyEddsa.S <== sigEddsa[0];
    verifyEddsa.R8x <== sigEddsa[1];
    verifyEddsa.R8y <== sigEddsa[2];
    verifyEddsa.M <== digestPoseidon.out;

    // 2. Calculate digest for certificate data
    component pkRsaBytes = ResizeChunks(RSA_3072_LIMBS, RSA_LIMB_SIZE, BYTE_SIZE);
    pkRsaBytes.in <== pkRsa;

    component certHasher = Sha512_hash_bytes(CERT_PRE_SIZE + CERT_KEY_SIZE + CERT_POST_SIZE);

    for (var i = 0; i < CERT_PRE_SIZE; i++) {
        certHasher.inp_bytes[i] <== certPreKey[i];
    }

    for (var i = 0; i < CERT_KEY_SIZE; i++) {
        certHasher.inp_bytes[CERT_PRE_SIZE + i] <== pkRsaBytes.out[CERT_KEY_SIZE - 1 - i];
    }

    for (var i = 0; i < CERT_POST_SIZE; i++) {
        certHasher.inp_bytes[CERT_PRE_SIZE + CERT_KEY_SIZE + i] <== certPostKey[i];
    }

    // 3. Verify CA's signature of the certificate data
    component pkCa = DVVCAPubkey();
    component verifyCa = RsaVerifyPkcs1v15(RSA_LIMB_SIZE, RSA_4096_LIMBS, RSA_EXP, RSA_HASH_SIZE);

    for (var i = 0; i < RSA_4096_LIMBS; i++) {
        verifyCa.signature[i] <== sigCa[i];
        verifyCa.pubkey[i] <== pkCa.key[RSA_4096_LIMBS - 1 - i]; // Hardcoded CA public key needs to be reversed
    }
    
    for (var i = 0; i < BYTE_SIZE; i++) {
        for (var j = 0; j < RSA_HASH_BYTES; j++) {
            verifyCa.hashed[i * RSA_HASH_BYTES + (RSA_HASH_BYTES - 1 - j)] <== certHasher.hash_qwords[i][j];
        }
    }

    // 4. Compute the commitments
    component hashDvv = Poseidon(16);
    component sigRsaChunks[16];
    for (var i = 0; i < 16; i++) {
        sigRsaChunks[i] = CombineLimbs3();
        for (var j = 0; j < 3; j++) {
            sigRsaChunks[i].in[j] <== sigRsa[i * 3 + j];
        }
        hashDvv.inputs[i] <== sigRsaChunks[i].out;
    }
    hashDvv.out ==> dvvCommitment;

    component hashZk = Poseidon(3);
    hashZk.inputs[0] <== sigEddsa[0];
    hashZk.inputs[1] <== sigEddsa[1];
    hashZk.inputs[2] <== sigEddsa[2];
    hashZk.out ==> zkCommitment;

    component hashNullifier = Poseidon(1);
    hashNullifier.inputs[0] <== nonce;
    hashNullifier.out ==> nullifier;
}

template CombineLimbs3() {
    signal input in[3];
    signal output out;

    out <== in[0] + in[1] + in[2];
}

// SHA-512 digest of the registration message
template CommitmentDigestSHA512() {
    signal output out[512];

    out <== [1, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0];
}

// Poseidon digest of the registration message
template CommitmentDigestPoseidon() {
    signal output out;
    out <== 16545280559118309720992774606760969325180593643479798061564279595779287712735; 
}

// Convert chunks of n bits to m bits, where n > m and n % m == 0
template ResizeChunks(fromChunks, fromBits, toBits) {
    signal input in[fromChunks];

    assert((fromBits * fromChunks) % toBits == 0);
    assert(fromBits % toBits == 0);

    var toChunks = (fromBits * fromChunks) / toBits;
    signal output out[toChunks];

    component n2b[fromChunks];
    component b2n[toChunks];

    for (var i = 0; i < fromChunks; i++) {
        n2b[i] = Num2Bits(fromBits);
        n2b[i].in <== in[i];

        for (var j = 0; j < fromBits / toBits; j++) {
            var chunk = i*fromBits/toBits + j;
            b2n[chunk] = Bits2Num(toBits);
            for (var k = 0; k < toBits; k++) {
                b2n[chunk].in[k] <== n2b[i].out[j*toBits + k];
            }
            b2n[chunk].out ==> out[chunk];
        }
    }
}

template DVVCAPubkey() {
    // Hardcoded RSA-4096 CA public key for 'DVV Citizen Certificates – G4R',
    // split into 64-bit limbs. 
    //
    // This is hardcoded for simplicity, but should be changed for production.
    //
    // The CA public key should be verified externally by the proof consumer.
    // This can be done by checking that the verification key corresponds to a circuit
    // that hardcodes the correct CA public key within the DVV certificate chain (from DVV).
    signal output key[64];
    
    key <== [12402966956184973081,
        16898347595247329034,
        8650523376736056536,
        3164646195768966501,
        12524479068993180832,
        3475531676853349859,
        2641622800740851350,
        15959502822801858640,
        478498804964221542,
        8497876464849570182,
        17630965767966917476,
        4683338045803083726,
        4456099982800183545,
        396645476913948323,
        8503401182731454081,
        5562910666411070327,
        15736374311575411648,
        9982582472787732932,
        16717000573013419194,
        13011731999268377895,
        12853568723575729286,
        16409396220059622114,
        13023718023635202511,
        11353441848908980625,
        3641247023246397634,
        16294867429003864389,
        14789554540459255407,
        2182220518032767842,
        5565204157542255731,
        9765264959164753905,
        5529025863343588421,
        7505191354834095942,
        16352980777827672183,
        6113512825473176232,
        2611701902289269202,
        13837335387942823188,
        2037708781222343260,
        16639415388268165685,
        10523584682172813879,
        6537158801495226361,
        15673214287156283971,
        10434010864309850813,
        3418784976434214862,
        11006096038977443943,
        1445500693410321534,
        18109918778518337767,
        18145512334194263528,
        13387599430611272042,
        3149530630404064477,
        482381165093098401,
        14937127787807400685,
        13154549305019216534,
        13028887889339659036,
        15152514895319622829,
        1451068796082804017,
        11193841126593592027,
        8183839534844970144,
        6285602330271202934,
        7408061321076103645,
        422326128957554794,
        15261200221552799411,
        5017808211540983473,
        2470403380171562267,
        12406786658590784091];
}

// Main component
component main = MeikaRegistration(); 