pragma circom 2.1.6;

include "./powMod.circom";
include "circomlib/circuits/bitify.circom";

// Pkcs1v15 + Sha512, e = 65537
// CHUNK_SIZE is expected to be 64.
template RsaVerifyPkcs1v15(CHUNK_SIZE, CHUNK_NUMBER, EXP, HASH_TYPE) {
    signal input signature[CHUNK_NUMBER];
    signal input pubkey[CHUNK_NUMBER]; //aka modulus

    signal input hashed[HASH_TYPE];

    // signature ** exp mod modulus
    component pm = PowerModAnyExp(CHUNK_SIZE, CHUNK_NUMBER, EXP);
    for (var i  = 0; i < CHUNK_NUMBER; i++) {
        pm.base[i] <== signature[i];
        pm.modulus[i] <== pubkey[i];
    }

    signal hashed_chunks[8];

    component bits2num[8];
    for(var i = 0; i< 8; i++){
        bits2num[7-i] = Bits2Num(64);
        for (var j = 0; j< 64; j++){
            bits2num[7-i].in[j] <== hashed[i*64 + 63 - j];
        }
        bits2num[7-i].out ==> hashed_chunks[7-i];
    } 

    //log("hashed_chunks:", hashed_chunks[0], hashed_chunks[1], hashed_chunks[2], hashed_chunks[3], hashed_chunks[4], hashed_chunks[5], hashed_chunks[6], hashed_chunks[7]);
    //log("pm.out       :", pm.out[0], pm.out[1], pm.out[2], pm.out[3], pm.out[4], pm.out[5], pm.out[6], pm.out[7]);

    // 1. Check hashed data
    for (var i = 0; i < 8; i++) {
        hashed_chunks[i] === pm.out[i];
    }

    // 2. Check that ASN.1 digestInfo is correct
    pm.out[8] === 217300894012671040; // 0x0304020305000440
    pm.out[9] === 938447882527703397; // 0x0d06096086480165

    // remain 24 bit
    component num2bits_6 = Num2Bits(CHUNK_SIZE);
    num2bits_6.in <== pm.out[10];
    var remainsBits[32] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0];
    for (var i = 0; i < 32; i++) {
        num2bits_6.out[i] === remainsBits[31 - i];
    }

    // 3. Check PS and em[1] = 1
    for (var i = 32; i < CHUNK_SIZE; i++) {
        num2bits_6.out[i] === 1;
    }

    for (var i = 11; i < CHUNK_NUMBER-1; i++) {
        pm.out[i] === 18446744073709551615; // 0b1111111111111111111111111111111111111111111111111111111111111111
    }
}

// Pkcs1v15 + Sha160, e = 65537
template RsaVerifyPkcs1v15Sha1(CHUNK_SIZE, CHUNK_NUMBER, EXP, HASH_TYPE) {
    signal input signature[CHUNK_NUMBER];
    signal input pubkey[CHUNK_NUMBER]; //aka modulus

    signal input hashed[HASH_TYPE];

    // signature ** exp mod modulus
    component pm = PowerModAnyExp(CHUNK_SIZE, CHUNK_NUMBER, EXP);
    for (var i  = 0; i < CHUNK_NUMBER; i++) {
        pm.base[i] <== signature[i];
        pm.modulus[i] <== pubkey[i];
    }

    signal hashed_chunks[2];

    component bits2num[2];
    for (var i = 0; i < 2; i++){
        bits2num[i] = Bits2Num(64);
        for (var j = 0; j < 64; j++){
            bits2num[i].in[j] <== hashed[159 - j - i * 64];
        }
    }

    component getBits = GetLastNBits(32);
    getBits.in <== pm.out[2];
    for (var i = 0; i < 32; i++){
        getBits.out[i] === hashed[31 - i];
    }
    getBits.div === 83887124; //0x5000414

    pm.out[3] === 650212878678426138;
    pm.out[4] === 18446744069417738544;
    for (var i = 5; i < CHUNK_NUMBER-1; i++) {
        pm.out[i] === 18446744073709551615; // 0b1111111111111111111111111111111111111111111111111111111111111111
    }
    pm.out[CHUNK_NUMBER - 1] === 562949953421311;
}

// TODO: research this moment https://www.youtube.com/watch?v=XfELJU1mRMg, 
// optimisation may be possible
// Deprecated
template RsaVerifyPkcs1v15Sha1E37817(CHUNK_SIZE, CHUNK_NUMBER, HASH_TYPE) {
    signal input signature[CHUNK_NUMBER];
    signal input pubkey[CHUNK_NUMBER]; //aka modulus

    signal input hashed[HASH_TYPE];

    // signature ** exp mod modulus
    component pm = PowerModAnyExp(CHUNK_SIZE, CHUNK_NUMBER, 37187);
    for (var i  = 0; i < CHUNK_NUMBER; i++) {
        pm.base[i] <== signature[i];
        pm.modulus[i] <== pubkey[i];
    }

    signal hashed_chunks[2];

    component bits2num[2];
    for (var i = 0; i < 2; i++){
        bits2num[i] = Bits2Num(64);
        for (var j = 0; j < 64; j++){
            bits2num[i].in[j] <== hashed[159 - j - i * 64];
        }
    }

    component getBits = GetLastNBits(32);
    getBits.in <== pm.out[2];
    for (var i = 0; i < 32; i++){
        getBits.out[i] === hashed[31 - i];
    }
    getBits.div === 83887124; //0x5000414

    pm.out[3] === 650212878678426138;
    pm.out[4] === 18446744069417738544;
    for (var i = 5; i < CHUNK_NUMBER-1; i++) {
        pm.out[i] === 18446744073709551615; // 0b1111111111111111111111111111111111111111111111111111111111111111
    }
    pm.out[CHUNK_NUMBER - 1] === 562949953421311;
}
