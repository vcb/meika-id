import * as snarkjs from 'snarkjs';
import { readFileSync } from 'fs';

const registrationVerificationKey = JSON.parse(readFileSync("public/meika-registration-vk.json", "utf8"));

export async function verifyRegistrationProof(proof: any, publicSignals: any) {
  try {
    const verified = await snarkjs.groth16.verify(registrationVerificationKey, publicSignals, proof);
    return verified;
  } catch (error) {
    console.error(error);
    return false;
  }
}