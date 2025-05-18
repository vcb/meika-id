import { CircuitSignals } from "snarkjs";
import * as snarkjs from "snarkjs";
import { expose } from "comlink";

interface WitnessObject {
  type: string;
  data: Uint8Array;
}

/**
* Builds a witness for the registration circuit.
* 
* @param input - The input signals for the circuit.
* @returns The witness for the circuit.
*/
const buildWitness = async (input: CircuitSignals, wasmUrl: string): Promise<Uint8Array> => {
  const wtns = {type: "mem"} as WitnessObject;
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
  return wtns.data;
}

expose({buildWitness});