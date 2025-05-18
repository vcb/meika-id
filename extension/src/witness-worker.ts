import { CircuitSignals } from "snarkjs";
import * as snarkjs from "snarkjs";
import { expose } from "comlink";

/**
* Builds a witness for the login circuit.
* 
* @param input - The input signals for the circuit.
* @param wasmUrl - The URL of the WASM file for the circuit.
* @returns The witness for the circuit.
*/
export const buildWitness = async (input: CircuitSignals, wasmUrl: string): Promise<any> => {
  const wtns = {type: "mem"} as any;
  try {
    const startTime = performance.now();
    await snarkjs.wtns.calculate(input, wasmUrl, wtns);
    const endTime = performance.now();
    console.log(`Witness calculation took ${endTime - startTime} milliseconds`);
  } catch (e) {
    console.error(e);
    throw e;
  }
  if (!wtns.data || wtns.data.length === 0) {
    throw new Error("Witness data is undefined");
  }
  return wtns;
}

/**
* Proves a witness for the login circuit.
* 
* @param zkeyUrl - The zkey for the circuit.
* @param wtns - The witness for the circuit.
* @returns The proof for the circuit.
*/
export const prove = async (zkeyUrl: string, wtns: any): Promise<{ proof: snarkjs.Groth16Proof, publicSignals: snarkjs.PublicSignals }> => {
  try {
    const startTime = performance.now();
    const proof = await snarkjs.groth16.prove(zkeyUrl, wtns);
    const endTime = performance.now();
    console.log(`Proof calculation took ${endTime - startTime} milliseconds`);
    return proof;
  } catch (e) {
    console.error(e);
    throw e;
  }
}

/**
* Builds a witness and proves the login circuit.
* 
* @param inputs - The input signals for the circuit.
* @param wasmUrl - The URL of the WASM file for the circuit.
* @param zkeyUrl - The zkey for the circuit.
*/
export const fullProve = async (inputs: CircuitSignals, wasmUrl: string, zkeyUrl: string): Promise<{ proof: snarkjs.Groth16Proof, publicSignals: snarkjs.PublicSignals }> => {
  try {
    const startTime = performance.now();
    const resp = await snarkjs.groth16.fullProve(inputs, wasmUrl, zkeyUrl, null, null, {singleThread: true});
    const endTime = performance.now();
    console.log(`Witness generation + proof calculation took ${endTime - startTime} milliseconds`);
    return resp;
  } catch (e) {
    console.error(e);
    throw e;
  }
}

expose({buildWitness, prove, fullProve});