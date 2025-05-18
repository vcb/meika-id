import { Buffer } from "buffer";
import { CircuitSignals, SignalValueType } from "snarkjs";

export const REGISTRATION_MESSAGE = `Meika ID
Version: 1
Action: Identity Registration

SECURITY WARNING:
This signature creates a cryptographic link to your legal identity.
If you're being asked to sign this message outside of the official Meika application, extension or website, someone may be attempting to impersonate you.
Only sign this message on the official Meika platform.`;


const pkEddsaLength = 2;
const pkRsaLength = 48;
const sigEddsaLength = 3;
const sigRsaLength = 48;
const sigCaLength = 64;
const certPreKeyLength = 339;
const certPostKeyLength = 589;

export interface RegistrationParams {
    pkEddsa: [bigint, bigint]; // Field elements
    pkRsa: string; // Hex or base64
    sigEddsa: [bigint, bigint, bigint]; // Field elements
    sigRsa: string; // Hex or base64
    sigCa: string; // Hex or base64
    nonce: bigint; // Field element
    certPreKey: string; // Hex or base64
    certPostKey: string; // Hex or base64
}

export interface LoginParams {
  // Public inputs
  rootDvv: bigint;
  rootZk: bigint;
  serviceId: bigint;
  challenge: bigint;
  // Private inputs
  pk: [bigint, bigint];
  dvv: bigint;
  sigReg: [bigint, bigint, bigint];
  sigLogin: [bigint, bigint, bigint];
  sigService: [bigint, bigint, bigint];
  nonce: bigint;
  pathDvv: bigint[];
  idxDvv: bigint[];
  pathZk: bigint[];
  idxZk: bigint[];
}

function decodeString(s: string): Buffer {
    if (s.startsWith("0x")) return Buffer.from(s.slice(2), "hex");
    try {
        return Buffer.from(s, "base64")
    } catch {
        throw new Error("Unknown input encoding")
    }
}

function splitToLimbs(input: Buffer | string, bits: number): bigint[] {
    const buf: Buffer = (Buffer.isBuffer(input))? input: decodeString(input);
    const limbs: bigint[] = [];
    const limbBytes = bits / 8;

    if (buf.length % limbBytes !== 0) {
        throw new Error(`Buffer size not aligned to limb size (${buf.length} % ${limbBytes} !== 0)`);
    }

    for (let i = 0; i < buf.length; i += limbBytes) {
        const slice = buf.subarray(i, i + limbBytes);
        limbs.push(BigInt("0x" + Buffer.from(slice).toString("hex")));
    }

    return limbs
}

export function buildRegistrationInputs(params: RegistrationParams, asString: boolean = false): CircuitSignals {
    const { pkEddsa, pkRsa, sigEddsa, sigRsa, sigCa, nonce, certPreKey, certPostKey } = params;


    const inputs: CircuitSignals = {
        "pkEddsa": [pkEddsa[0].toString(), pkEddsa[1].toString()],
        "pkRsa": splitToLimbs(pkRsa, 64).reverse().map(x => asString? x.toString(): x),
        "sigEddsa": [sigEddsa[0].toString(), sigEddsa[1].toString(), sigEddsa[2].toString()],
        "sigRsa": splitToLimbs(sigRsa, 64).reverse().map(x => asString? x.toString(): x),
        "sigCa": splitToLimbs(sigCa, 64).reverse().map(x => asString? x.toString(): x),
        "nonce": nonce.toString(),
        "certPreKey": splitToLimbs(certPreKey, 8).map(x => asString? x.toString(): x),
        "certPostKey": splitToLimbs(certPostKey, 8).map(x => asString? x.toString(): x)
    }

    return inputs;
}

export function buildLoginInputs(params: LoginParams): CircuitSignals {
    const { rootDvv, rootZk, serviceId, challenge, pk, dvv, sigReg, sigLogin, sigService, nonce, pathDvv, idxDvv, pathZk, idxZk } = params;

    const inputs: CircuitSignals = {
        "rootDvv": rootDvv.toString(),
        "rootZk": rootZk.toString(),
        "serviceId": serviceId.toString(),
        "challenge": challenge.toString(),
        "pk": [pk[0].toString(), pk[1].toString()],
        "dvv": dvv.toString(),
        "sigReg": [sigReg[0].toString(), sigReg[1].toString(), sigReg[2].toString()],
        "sigLogin": [sigLogin[0].toString(), sigLogin[1].toString(), sigLogin[2].toString()],
        "sigService": [sigService[0].toString(), sigService[1].toString(), sigService[2].toString()],
        "nonce": nonce.toString(),
        "pathDvv": pathDvv.map(x => x.toString()),
        "idxDvv": idxDvv.map(x => x.toString()),
        "pathZk": pathZk.map(x => x.toString()),
        "idxZk": idxZk.map(x => x.toString())
    }

    return inputs;
}