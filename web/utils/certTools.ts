import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';

/**
* Parses a certificate and returns the public key, signature and split TBS section.
* @param certBase64 - The base64 DER-encoded certificate.
* @returns An object containing the public key, signature and split TBS section.
*/
export function parseCert(certBase64: string): { pkRsa: string, certPreKey: string, certPostKey: string, sigCa: string } {
  const der = Buffer.from(certBase64, 'base64');
  const asn1 = asn1js.fromBER(der);
  if (asn1.offset === -1) {
    throw new Error('Failed to parse certificate');
  }
  
  const certData = asn1.result;
  const cert = new pkijs.Certificate({schema: certData});
  
  const pk = cert.subjectPublicKeyInfo.parsedKey;
  if (!pk || !(pk instanceof pkijs.RSAPublicKey)) {
    throw new Error('Failed to parse public key');
  }
  const pkBuf = Buffer.from(pk.modulus.valueBlock.valueHexView);
  const pkBase64 = pkBuf.toString('base64');
  
  // Split the certificate into two parts: before and after the public key (modulus only)
  const tbsBuf = Buffer.from(cert.tbsView);
  const tbsOffset = tbsBuf.indexOf(pkBuf);
  if (tbsOffset === -1) {
    throw new Error('Failed to find public key in TBS');
  }
  const certPreKey = tbsBuf.slice(0, tbsOffset).toString('base64');
  const certPostKey = tbsBuf.slice(tbsOffset + pkBuf.length).toString('base64');
  
  const sigCaBuf = Buffer.from(cert.signatureValue.valueBlock.valueHexView);
  const sigCaBase64 = sigCaBuf.toString('base64');
  
  return {
    pkRsa: pkBase64,
    certPreKey: certPreKey,
    certPostKey: certPostKey,
    sigCa: sigCaBase64
  };
}
