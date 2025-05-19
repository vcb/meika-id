import React, { useState, useRef } from 'react';
import Link from 'next/link';
import { useExtensionDetection } from '../utils/extensionDetection';
import { parseCert } from '../utils/certTools';
import { CircuitSignals } from 'snarkjs';
import { wrap } from 'comlink';
import { getRandomFr, REGISTRATION_MESSAGE, RegistrationParams, buildRegistrationInputs } from '@lib/util';
import { RegistrationProof, WebMessageType, SignatureRequest, SignatureResponseContent } from '@lib/types';

const SignatureAlgorithm = 'SHA512withRSA';

export interface AtostekResponse {
  chain:              string[];
  reasonCode:         number;
  reasonText:         string;
  signature:          string;
  signatureAlgorithm: string;
  signatureType:      string;
  status:             string;
  version:            string;
}

enum Status {
  IDLE = 'idle',
  LOADING = 'loading',
  SUCCESS = 'success',
  ERROR = 'error'
}

export async function signWithExtension(message: string | bigint[]): Promise<SignatureResponseContent> {
  return new Promise<SignatureResponseContent>((resolve, reject) => {
    const timeoutId = setTimeout(() => {
      window.removeEventListener('message', messageHandler);
      reject(new Error('Extension response timeout after 30 seconds'));
    }, 30000);
    
    const messageHandler = (event: MessageEvent) => {
      if (
        event.origin === window.origin && 
        event.data && 
        event.data.type === WebMessageType.SIGNATURE_RESPONSE
      ) {
        clearTimeout(timeoutId);
        window.removeEventListener('message', messageHandler);
        
        try {
          resolve({
            pk: event.data.content.pk,
            signature: event.data.content.signature,
            packed: event.data.content.packed,
            origin: event.data.content.origin
          });
        } catch (error) {
          reject(new Error(`Error processing extension response: ${error}`));
        }
      }
    };
    
    window.addEventListener('message', messageHandler);
    
    // Send the signature request to the content script
    window.postMessage({
      type: WebMessageType.SIGNATURE_REQUEST,
      content: {
        message: message,
        domain: window.location.hostname
      } as SignatureRequest,
    }, window.origin);
  });
} 

export default function Register() {
  const { extensionDetected } = useExtensionDetection();
  
  // Registration process state
  const [eddsaStatus, setEddsaStatus] = useState<Status>(Status.IDLE);
  const [rsaStatus, setRsaStatus] = useState<Status>(Status.IDLE);
  const [inputsJson, setInputsJson] = useState('');
  const [inputs, setInputs] = useState<CircuitSignals | null>(null);
  const [witness, setWitness] = useState<Uint8Array | null>(null);
  const [proofFile, setProofFile] = useState<File | null>(null);
  const [outputsFile, setOutputsFile] = useState<File | null>(null);
  const [witnessStatus, setWitnessStatus] = useState<Status>(Status.IDLE);
  const [proofStatus, setProofStatus] = useState<Status>(Status.IDLE);
  
  // Registration data
  const [eddsaData, setEddsaData] = useState<{
    pkEddsa: [bigint, bigint];
    sigEddsa: [bigint, bigint, bigint];
    nonce: bigint;
  } | null>(null);
  
  const [rsaData, setRsaData] = useState<{
    pkRsa: string;
    sigRsa: string;
    sigCa: string;
    certPreKey: string;
    certPostKey: string;
  } | null>(null);
  
  const proofFileInputRef = useRef<HTMLInputElement>(null);
  const outputsFileInputRef = useRef<HTMLInputElement>(null);
  
  const [showPrerequisites, setShowPrerequisites] = useState(true);
  const [showRapidsnarkInfo, setShowRapidsnarkInfo] = useState(false);

  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Generate inputs.json after both steps are complete
  React.useEffect(() => {
    if (eddsaData && rsaData) {
      try {
        // Combine the data from both steps
        const params: RegistrationParams = {
          ...eddsaData,
          ...rsaData
        };
        
        // Build the circuit inputs
        const inputs = buildRegistrationInputs(params, true);
        setInputsJson(JSON.stringify(inputs, null, 2));
        setInputs(inputs);
      } catch (error) {
        console.error('Error building inputs:', error);
        setInputsJson("Error generating inputs");
      }
    }
  }, [eddsaData, rsaData]);

  async function handleSignWithExtension() {
    setEddsaStatus(Status.LOADING);
    
    const values: {
      pkEddsa: [bigint, bigint];
      sigEddsa: [bigint, bigint, bigint];
      sigNonce: [bigint, bigint, bigint];
      nonce: bigint;
    } = {
      pkEddsa: [0n, 0n],
      sigEddsa: [0n, 0n, 0n],
      sigNonce: [0n, 0n, 0n],
      nonce: 0n
    };

    values.nonce = getRandomFr();

    try {
      const extensionResponse = await signWithExtension(REGISTRATION_MESSAGE);
      values.pkEddsa = extensionResponse.pk;
      values.sigEddsa = extensionResponse.signature;
    } catch (error) {
      console.log('Error during extension signing:', error);
      setEddsaStatus(Status.ERROR);
      return;
    }

    setEddsaData(values);
    setEddsaStatus(Status.SUCCESS);
  }
  
  async function handleSignWithCard() {
    setRsaStatus(Status.LOADING);

    const msg = REGISTRATION_MESSAGE;
    const msgB64 = btoa(msg);

    try {
      const res = await fetch('https://localhost:53952/sign', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          version: '1.1',
          content: msgB64,
          contentType: 'data',
          hashAlgorithm: 'SHA512',
          signatureType: 'signature',
          signatureAlgorithm: 'rsa',
          selector: {
            keyalgorithms: ['RSA'],
            issuers: ["CN=DVV Citizen Certificates - G4R, OU=Valtion kansalaisvarmenteet, O=Digi- ja vaestotietovirasto CA, C=FI"]
          }
        }),
      });
      if (!res || !res.ok) {
        console.log('Error signing with card:', res);
        setRsaStatus(Status.ERROR);
        return;
      }

      const body: AtostekResponse = await res.json();
      const { signature, signatureAlgorithm,chain } = body;
      if (!signature || !chain || chain.length !== 3) {
        console.error('Signature or chain length mismatch:', signature, chain);
        setRsaStatus(Status.ERROR);
        return;
      }
      if (signatureAlgorithm !== SignatureAlgorithm) {
        console.error('Signature algorithm mismatch:', signatureAlgorithm);
        setRsaStatus(Status.ERROR);
        return;
      }

      // Parse inputs from personal certificate
      const { pkRsa, certPreKey, certPostKey, sigCa } = parseCert(chain[0]);
      
      // Store RSA data
      setRsaData({
        pkRsa: pkRsa,
        sigRsa: signature,
        sigCa: sigCa,
        certPreKey: certPreKey,
        certPostKey: certPostKey
      });
      
      setRsaStatus(Status.SUCCESS);
    } catch (error) {
      console.error('Error signing with card:', error);
      setRsaStatus(Status.ERROR);
    }
  }
  
  async function handleDownloadWitness() {
    if (!inputs) return;
    
    let witnessData: Uint8Array;
    if (!witness) {
      try {
        setWitnessStatus(Status.LOADING);
        
        // Offload to a web worker for better UX
        const worker = new Worker(new URL('../utils/witnessWorker.ts', import.meta.url));
        const witnessAPI = wrap<{
          buildWitness(input: CircuitSignals, wasmUrl: string): Promise<Uint8Array>;
        }>(worker);
        witnessData = await witnessAPI.buildWitness(inputs, new URL('/wasm/registration.wasm', window.location.origin).toString());

        setWitness(witnessData);
        setWitnessStatus(Status.SUCCESS);
      } catch (error) {
        console.error('Error building witness:', error);
        setWitnessStatus(Status.ERROR);
        return;
      }
    } else {
      witnessData = witness;
    }
    const buffer = witnessData.buffer as ArrayBuffer;
    const blob = new Blob([buffer], { type: 'application/octet-stream' });

    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = 'meika-registration.wtns';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(link.href);
  }
  
  function handleProofFileChange(e: React.ChangeEvent<HTMLInputElement>) {
    if (e.target.files && e.target.files[0]) {
      setProofFile(e.target.files[0]);
    }
  }
  
  function handleOutputsFileChange(e: React.ChangeEvent<HTMLInputElement>) {
    if (e.target.files && e.target.files[0]) {
      setOutputsFile(e.target.files[0]);
    }
  }
  
  async function handleSubmit() {
    if (!proofFile || !outputsFile) {
      alert('Please upload both proof.json and outputs.json files');
      return;
    }
  
    setProofStatus(Status.LOADING);
    setErrorMessage(null); // Clear previous error messages
    
    const proofText = await proofFile.text();
    const outputsText = await outputsFile.text();
    
    const proofTextCleaned = proofText.substring(0, proofText.lastIndexOf('}') + 1);
    const outputsTextCleaned = outputsText.substring(0, outputsText.lastIndexOf(']') + 1);

    try {
      const proof = JSON.parse(proofTextCleaned);
      const publicSignals = JSON.parse(outputsTextCleaned);
    
      const response = await fetch('/api/submit_proof', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          proof,
          publicSignals
        })
      });
      
      const result = await response.json();
      
      if (!response.ok) {
        setProofStatus(Status.ERROR);
        setErrorMessage(result.message || 'Error submitting proof');
        return;
      }
      
      const obj: RegistrationProof = {
        proof: proof,
        publicSignals: {
          zkCommitment: publicSignals[0],
          dvvCommitment: publicSignals[1],
          nullifier: publicSignals[2]
        },
        dvvIndex: result.data.dvvIndex,
        zkIndex: result.data.zkIndex
      }

      // Send message to content script to open popup
      window.postMessage({
        type: WebMessageType.SUBMIT_PROOF,
        content: JSON.stringify(obj)
      }, '*');
      setProofStatus(Status.SUCCESS);
    } catch (error) {
      console.log('Error parsing proof or outputs:', error);
      setProofStatus(Status.ERROR);
      setErrorMessage(error instanceof Error ? error.message : 'Error parsing proof files');
      return;
    }
  }

  const buttonStyle = {
    padding: '10px 20px',
    background: '#0070f3',
    color: 'white',
    border: 'none',
    borderRadius: '5px',
    cursor: 'pointer',
    fontSize: '16px',
    fontWeight: 'bold',
    width: '180px',
    textAlign: 'center' as const
  };
  
  const disabledButtonStyle = {
    ...buttonStyle,
    background: '#ccc',
    cursor: 'not-allowed',
    opacity: 0.7
  };

  const bothStepsComplete = eddsaStatus === Status.SUCCESS && rsaStatus === Status.SUCCESS;

  return (
    <main style={{ padding: '2rem', maxWidth: '800px', margin: '0 auto' }}>
      <h1>meikä id — Smartcard Registration</h1>
      
      <div style={{ marginTop: '1rem', marginBottom: '2rem' }}>
        <Link href="/" style={{ 
          display: 'inline-flex',
          alignItems: 'center',
          color: '#0070f3',
          textDecoration: 'none',
          fontSize: '16px'
        }}>
          ← Back to Home
        </Link>
      </div>

      {extensionDetected === false && (
        <div style={{
          padding: '10px 15px',
          marginBottom: '30px',
          borderRadius: '5px',
          backgroundColor: '#f8d7da',
          color: '#721c24',
          display: 'flex',
          alignItems: 'center',
          gap: '8px'
        }}>
          <span style={{ fontSize: '20px' }}>🗝️</span>
          <span>
            Meikä ID extension not detected. <a href="#" style={{ color: 'inherit', fontWeight: 'bold' }}>Install the extension</a> to use Meikä ID.
          </span>
        </div>
      )}
      
      {/* Prerequisites section */}
      <div 
        style={{
          marginTop: '20px',
          marginBottom: '40px',
          position: 'relative',
          backgroundColor: 'rgb(244, 244, 244)',
          borderRadius: '8px',
          padding: '20px',
          overflow: 'hidden'
        }}
      >
        {/* Card image */}
        <div style={{
          position: 'absolute',
          width: '40%',
          height: '150%',
          top: '-10%',
          right: '-5%',
          backgroundImage: 'url("/img/card.png")',
          backgroundSize: 'contain',
          backgroundPosition: 'top right',
          backgroundRepeat: 'no-repeat',
          transform: 'rotate(14deg)',
          opacity: 0.45,
          zIndex: 0
        }} />
        
        {/* Prerequisites */}
        <div style={{ position: 'relative', zIndex: 1 }}>
          <div 
            onClick={() => setShowPrerequisites(!showPrerequisites)}
            style={{ 
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              fontWeight: 'bold',
              marginBottom: '8px'
            }}
          >
            <span style={{ marginRight: '5px' }}>
              {showPrerequisites ? '▼' : '►'}
            </span>
            Prerequisites
          </div>
          
          {showPrerequisites && (
            <ul style={{ 
              listStyleType: 'none', 
              padding: '15px',
              margin: '0',
              borderRadius: '5px',
            }}>
              <li style={{ marginBottom: '15px', display: 'flex', alignItems: 'flex-start' }}>
                <span style={{ marginRight: '10px', fontSize: '18px', marginTop: '-4px', minWidth: '24px', textAlign: 'center' }}>🪪</span>
                <span>Finnish ID card, activated</span>
              </li>
              <li style={{ marginBottom: '15px', display: 'flex', alignItems: 'flex-start' }}>
                <span style={{ marginRight: '10px', fontSize: '18px', marginTop: '-4px', minWidth: '24px', textAlign: 'center' }}>⏏️</span>
                <span>Card reader connected to your computer</span>
              </li>
              <li style={{ marginBottom: '15px', display: 'flex', alignItems: 'flex-start' }}>
                <span style={{ marginRight: '10px', fontSize: '18px', marginTop: '-4px', minWidth: '24px', textAlign: 'center' }}>💻</span>
                <span><a href="https://dvv.fi/en/card-reader-software" target="_blank" rel="noopener noreferrer">Atostek ID</a> installed and running</span>
              </li>
              <li style={{ marginBottom: '15px', display: 'flex', alignItems: 'flex-start' }}>
                <span style={{ marginRight: '10px', fontSize: '18px', marginTop: '-4px', minWidth: '24px', textAlign: 'center' }}>⚡</span>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center' }}>
                    <span><a href="https://github.com/iden3/rapidsnark" target="_blank" rel="noopener noreferrer">rapidsnark</a> for generating the registration proof</span>
                    <span 
                      onClick={(e) => {
                        e.stopPropagation();
                        setShowRapidsnarkInfo(!showRapidsnarkInfo);
                      }}
                      style={{ 
                        cursor: 'pointer', 
                        fontSize: '12px',
                        position: 'relative',
                        top: '-5px',
                        marginLeft: '2px'
                      }}
                    >
                      ℹ️
                    </span>
                  </div>
                  {showRapidsnarkInfo && (
                    <div style={{ 
                      fontSize: '14px', 
                      color: '#666', 
                      marginTop: '5px',
                      padding: '8px',
                      backgroundColor: '#f0f0f0',
                      borderRadius: '4px'
                    }}>
                      You can use rapidsnark with WSL on Windows 10/11 or install it directly on Ubuntu or other Linux distributions.
                    </div>
                  )}
                </div>
              </li>
              <li style={{ display: 'flex', alignItems: 'flex-start' }}>
                <span style={{ marginRight: '10px', fontSize: '18px', marginTop: '-4px', minWidth: '24px', textAlign: 'center' }}>🔑</span>
                <span>Proving key, download from <a href="https://storage.googleapis.com/zkid/meika-registration.zkey" target="_blank" rel="noopener noreferrer">here</a> (<code>meika-registration.zkey</code>, 1.3GB)</span>
              </li>
            </ul>
          )}
        </div>
      </div>
      
      {/* Registration process steps */}
      <div style={{
        border: '1px solid #e1e1e1',
        borderRadius: '8px',
        display: 'flex',
        flexDirection: 'column',
        marginBottom: '40px',
      }}>
        {/* Step 1: Sign with Extension */}
        <div style={{
          border: '1px solid rgba(180, 180, 180, 0.35)',
          borderRadius: '8px 8px 0 0',
          backgroundColor: '#f9f9f9',
          padding: '20px 20px 32px 20px',
          marginBottom: '-12px',
          height: '180px',
          position: 'relative',
          zIndex: 0
        }}>
          <div style={{ marginBottom: '15px' }}>
            <div style={{ fontWeight: 'bold', fontSize: '18px', marginBottom: '4px' }}>Step 1: Sign with Extension</div>
            <div style={{ color: '#555', fontSize: '14px' }}>Sign the registration message using the browser extension.</div>
          </div>
          
          <div style={{ 
            display: 'flex', 
            justifyContent: 'space-between', 
            alignItems: 'center' 
          }}>
            <div>
              {eddsaStatus === 'idle' && <div>Not started</div>}
              {eddsaStatus === 'loading' && (
                <div style={{ display: 'flex', alignItems: 'center' }}>
                  <div style={{
                    display: 'inline-block',
                    width: '16px',
                    height: '16px',
                    borderRadius: '50%',
                    border: '2px solid #0070f3',
                    borderTopColor: 'transparent',
                    animation: 'spin 1s linear infinite',
                    marginRight: '10px'
                  }}></div>
                  Processing...
                </div>
              )}
              {eddsaStatus === 'success' && <div style={{ color: '#0f5132' }}>✓ Signature created successfully</div>}
              {eddsaStatus === 'error' && <div style={{ color: '#842029' }}>✗ Error fetching signature</div>}
            </div>
            
            <button 
              onClick={handleSignWithExtension}
              disabled={eddsaStatus === 'loading' || eddsaStatus === 'success'}
              style={eddsaStatus === 'loading' || eddsaStatus === 'success' ? disabledButtonStyle : buttonStyle}
            >
              {eddsaStatus === 'loading' ? 'Processing...' : eddsaStatus === 'success' ? 'Completed' : 'Sign with Extension'}
            </button>
          </div>
        </div>
        
        {/* Step 2: Sign with ID Card */}
        <div style={{
          border: '1px solid rgba(180, 180, 180, 0.35)',
          borderRadius: '8px 8px 0 0',
          backgroundColor: '#f9f9f9',
          padding: '20px 20px 32px 20px',
          marginBottom: '-12px',
          position: 'relative',
          zIndex: 1,
          height: '180px'
        }}>
          <div style={{ marginBottom: '15px' }}>
            <div style={{ fontWeight: 'bold', fontSize: '18px', marginBottom: '4px' }}>Step 2: Sign with ID Card</div>
            <div style={{ color: '#555', fontSize: '14px' }}>Sign the registration message using your ID card to verify your identity.</div>
          </div>
          
          <div style={{ 
            display: 'flex', 
            justifyContent: 'space-between', 
            alignItems: 'center' 
          }}>
            <div>
              {rsaStatus === 'idle' && <div>Not started</div>}
              {rsaStatus === 'loading' && (
                <div style={{ display: 'flex', alignItems: 'center' }}>
                  <div style={{
                    display: 'inline-block',
                    width: '16px',
                    height: '16px',
                    borderRadius: '50%',
                    border: '2px solid #0070f3',
                    borderTopColor: 'transparent',
                    animation: 'spin 1s linear infinite',
                    marginRight: '10px'
                  }}></div>
                  Connecting to card reader...
                </div>
              )}
              {rsaStatus === 'success' && <div style={{ color: '#0f5132' }}>✓ ID card signature successful</div>}
              {rsaStatus === 'error' && <div style={{ color: '#842029' }}>✗ Error signing with ID card</div>}
            </div>
            
            <button 
              onClick={handleSignWithCard}
              disabled={eddsaStatus !== 'success' || rsaStatus === 'loading' || rsaStatus === 'success'}
              style={eddsaStatus !== 'success' || rsaStatus === 'loading' || rsaStatus === 'success' ? disabledButtonStyle : buttonStyle}
            >
              {rsaStatus === 'loading' ? 'Processing...' : rsaStatus === 'success' ? 'Completed' : 'Sign with ID Card'}
            </button>
          </div>
        </div>
        
        {/* Download Inputs */}
        <div style={{
          border: '1px solid rgba(180, 180, 180, 0.35)',
          borderRadius: '8px 8px 0 0',
          backgroundColor: '#f9f9f9',
          padding: '20px 20px 32px 20px',
          marginBottom: '-12px',
          position: 'relative',
          zIndex: 2,
          height: '180px'
        }}>
          <div style={{ marginBottom: '15px' }}>
            <div style={{ fontWeight: 'bold', fontSize: '18px', marginBottom: '4px' }}>Download Witness</div>
            <div style={{ color: '#555', fontSize: '14px' }}>Generate and download the witness file for your proof. This will take a few minutes.</div>
          </div>
          
          <div style={{ 
            display: 'flex', 
            justifyContent: 'space-between', 
            alignItems: 'flex-start',
            gap: '20px'
          }}>
            {bothStepsComplete ? (
              <div style={{ 
                flex: 1,
                border: '1px solid #ddd', 
                borderRadius: '5px',
                padding: '10px',
                backgroundColor: '#f0f0f0',
                maxHeight: '80px',
                overflowY: 'auto',
                fontFamily: 'monospace',
                whiteSpace: 'pre',
                fontSize: '12px'
              }}>
                {inputsJson || 'Generating inputs...'}
              </div>
            ) : (
              <div>
                Complete both steps above to generate witness
              </div>
            )}
            
            <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', width: '180px', height: '100%' }}>
              <button 
                onClick={handleDownloadWitness}
                disabled={!bothStepsComplete || !inputs || witnessStatus === Status.LOADING}
                style={!bothStepsComplete || !inputs || witnessStatus === Status.LOADING ? disabledButtonStyle : buttonStyle}
              >
                {witnessStatus === Status.LOADING ? (
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <div style={{
                      display: 'inline-block',
                      width: '16px',
                      height: '16px',
                      borderRadius: '50%',
                      border: '2px solid #fff',
                      borderTopColor: 'transparent',
                      animation: 'spin 1s linear infinite'
                    }}></div>
                    Calculating...
                  </div>
                ) : witnessStatus === Status.SUCCESS ? 'Download Witness' : 'Generate Witness'}
              </button>
            </div>
          </div>
        </div>
        
        {/* Warning */}
        <div style={{
          border: '1px solid rgba(180, 180, 180, 0.35)',
          borderRadius: '8px 8px 0 0',
          color: 'rgb(255, 255, 255)',
          backgroundColor: 'rgb(188, 17, 17)',
          padding: '20px 20px 32px 20px',
          marginBottom: '-12px',
          position: 'relative',
          zIndex: 2,
          height: '90px'
        }}>
          <div style={{ marginBottom: '15px' }}>
            <div style={{ fontWeight: 'bold', fontSize: '18px', marginBottom: '4px', textAlign: 'center' }}>Warning</div>
            <div style={{ color: 'rgb(255, 255, 255)', fontWeight: 'bold', fontSize: '14px', textAlign: 'center' }}>Do not share the inputs or witness file with anyone. They contain encoded personal data.</div>
          </div>
        </div>

        {/* Upload and Submit */}
        <div style={{
          border: '1px solid rgba(180, 180, 180, 0.35)',
          borderRadius: '8px',
          padding: '20px',
          backgroundColor: 'rgb(255, 255, 255)',
          marginBottom: '-12px',
          position: 'relative',
          zIndex: 3
        }}>
          <div style={{ marginBottom: '15px' }}>
            <div style={{ fontWeight: 'bold', fontSize: '18px', marginBottom: '4px' }}>Generate Proof & Submit</div>
            <div style={{ color: '#555', fontSize: '14px' }}>Generate proof with rapidsnark, then upload files to complete registration</div>
          </div>
          
          <div style={{ marginBottom: '20px', backgroundColor: '#1e1e1e', color: '#f8f8f8', padding: '12px', borderRadius: '5px', fontFamily: 'monospace', fontSize: '14px' }}>
            ./rapidsnark/build-prover/src/prover meika-registration.zkey meika-registration.wtns proof.json outputs.json
          </div>
          
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '20px', gap: '20px' }}>
            <div style={{ flex: 1 }}>
              <div style={{ marginBottom: '10px', fontWeight: 'bold' }}>proof.json</div>
              <div 
                onClick={() => proofFileInputRef.current?.click()}
                style={{
                  border: '2px dashed #ccc',
                  borderRadius: '5px',
                  padding: '15px',
                  textAlign: 'center',
                  backgroundColor: '#f8f8f8',
                  cursor: 'pointer',
                  height: '60px',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center'
                }}
              >
                {proofFile ? proofFile.name : 'Click to select file'}
                <input 
                  type="file" 
                  ref={proofFileInputRef}
                  onChange={handleProofFileChange}
                  accept=".json"
                  style={{ display: 'none' }}
                />
              </div>
            </div>
            
            <div style={{ flex: 1 }}>
              <div style={{ marginBottom: '10px', fontWeight: 'bold' }}>outputs.json</div>
              <div 
                onClick={() => outputsFileInputRef.current?.click()}
                style={{
                  border: '2px dashed #ccc',
                  borderRadius: '5px',
                  padding: '15px',
                  textAlign: 'center',
                  backgroundColor: '#f8f8f8',
                  cursor: 'pointer',
                  height: '60px',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center'
                }}
              >
                {outputsFile ? outputsFile.name : 'Click to select file'}
                <input 
                  type="file" 
                  ref={outputsFileInputRef}
                  onChange={handleOutputsFileChange}
                  accept=".json"
                  style={{ display: 'none' }}
                />
              </div>
            </div>
          </div>
          
          <div style={{ display: 'flex', justifyContent: 'center' }}>
            <button 
              onClick={handleSubmit}
              disabled={!proofFile || !outputsFile || proofStatus === Status.LOADING}
              style={!proofFile || !outputsFile || proofStatus === Status.LOADING ? disabledButtonStyle : {...buttonStyle, background: '#28a745', width: '200px'}}
            >
              {proofStatus === Status.LOADING ? (
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <div style={{
                    display: 'inline-block',
                    width: '16px',
                    height: '16px',
                    borderRadius: '50%',
                    border: '2px solid #fff',
                    borderTopColor: 'transparent',
                    animation: 'spin 1s linear infinite'
                  }}></div>
                  Submitting...
                </div>
              ) : proofStatus === Status.SUCCESS ? 'Registration Complete!' : 'Submit Registration'}
            </button>
          </div>
          
          {proofStatus === Status.ERROR && (
            <div style={{ 
              color: '#721c24', 
              backgroundColor: '#f8d7da',
              padding: '10px',
              borderRadius: '5px',
              marginTop: '15px',
              textAlign: 'center'
            }}>
              {errorMessage ? String(errorMessage) : 'Error submitting registration. Please try again.'}
            </div>
          )}
          
          {proofStatus === Status.SUCCESS && (
            <div style={{ 
              color: '#155724', 
              backgroundColor: '#d4edda',
              padding: '10px',
              borderRadius: '5px',
              marginTop: '15px',
              textAlign: 'center'
            }}>
              Registration submitted successfully!
            </div>
          )}
        </div>
      </div>
      
      <div style={{ marginTop: '30px', borderTop: '1px solid #eaeaea', paddingTop: '20px', fontSize: '14px' }}>
        <p>
          <a href="https://dvv.fi/kansalaisvarmenne-henkilokortilla" target="_blank" rel="noopener noreferrer" style={{ marginRight: '10px', textDecoration: 'none' }}>
            🇫🇮 Finnish eID info
          </a>
          <a href="https://dvv.fi/en/citizen-certificate-on-id-card" target="_blank" rel="noopener noreferrer" style={{ textDecoration: 'none' }}>
            🇬🇧 English eID info
          </a>
        </p>        
      </div>
      
      <style jsx>{`
        @keyframes spin {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }
      `}</style>
    </main>
  );
} 