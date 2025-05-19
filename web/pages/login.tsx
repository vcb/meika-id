import React, { useState } from 'react';
import Link from 'next/link';
import { useExtensionDetection } from '../utils/extensionDetection';
import { LoginRequest, LoginResponseContent, WebMessageType } from '@lib/types';
import { generateChallenge } from '@lib/auth';
import * as snarkjs from 'snarkjs';

export async function loginWithExtension(request: LoginRequest): Promise<LoginResponseContent> {
  return new Promise<LoginResponseContent>((resolve, reject) => {
    const timeoutId = setTimeout(() => {
      window.removeEventListener('message', messageHandler);
      reject(new Error('Extension response timeout after 30 seconds'));
    }, 30000);
    
    const messageHandler = (event: MessageEvent) => {
      if (
        event.origin === window.origin && 
        event.data && 
        event.data.type === WebMessageType.LOGIN_RESPONSE
      ) {
        clearTimeout(timeoutId);
        window.removeEventListener('message', messageHandler);
        
        try {
          resolve(event.data.content);
        } catch (error) {
          reject(new Error(`Error processing extension response: ${error}`));
        }
      }
    };
    
    window.addEventListener('message', messageHandler);
    
    // Send the signature request to the content script
    window.postMessage({
      type: WebMessageType.LOGIN_REQUEST,
      content: request
    }, window.origin);
  });
} 


export default function Login() {
  const { extensionDetected } = useExtensionDetection();
  const [status, setStatus] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  const handleLogin = async () => {
    try {
      setIsLoading(true);
      setStatus('Continue sign in with Meikä ID Vault');
      
      const challenge = generateChallenge();

      const loginRequest: LoginRequest = {
        domain: window.location.hostname,
        challenge: challenge,
        origin: window.location.origin
      };

      const response = await loginWithExtension(loginRequest);

      setStatus('Verifying proof...');
      const { proof, publicSignals } = response;

      if (!proof || !publicSignals) {
        setStatus('❌ Error: Invalid response from extension');
        setIsLoading(false);
        return;
      }

      const vkJson = await fetch('/keys/meika-login-vk.json');
      const vk = JSON.parse(await vkJson.text());

      const verified = await snarkjs.groth16.verify(vk, publicSignals, proof);
      if (!verified) {
        setStatus('❌ Error: Invalid proof');
        setIsLoading(false);
        return;
      }

      // Check merkle roots
      const dvvRootResponse = await fetch('/api/root/meika-dvv');
      const dvvRoot = await dvvRootResponse.json();

      const zkRootResponse = await fetch('/api/root/meika-zk');
      const zkRoot = await zkRootResponse.json();

      if (BigInt(dvvRoot.data.root) !== BigInt(publicSignals[2])) {
        setStatus('❌ Error: Invalid DVV root');
        setIsLoading(false);
        return;
      }

      if (BigInt(zkRoot.data.root) !== BigInt(publicSignals[3])) {
        setStatus('❌ Error: Invalid ZK root');
        setIsLoading(false);
        return;
      }      
      
      setStatus('✅ Identity verified!');
      setIsLoading(false);
      
    } catch (error) {
      setStatus(`❌ Error: ${error instanceof Error ? error.message : 'Unknown error occurred'}`);
      setIsLoading(false);
    }
  };

  return (
    <main style={{ padding: '2rem', maxWidth: '800px', margin: '0 auto' }}>
      <h1>meikä id — Login</h1>

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

      <p style={{marginBottom: '40px' }}>
        Authenticate with your Meikä ID
      </p>
      
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
      
      <div style={{ 
        display: 'flex', 
        flexDirection: 'column', 
        alignItems: 'flex-start',
        gap: '15px',
        marginBottom: '40px' 
      }}>
        <button 
          onClick={handleLogin}
          disabled={isLoading || extensionDetected === false}
          style={{ 
            padding: '12px 24px',
            background: '#28a745',
            color: 'white',
            border: 'none',
            borderRadius: '5px',
            cursor: (isLoading || extensionDetected === false) ? 'not-allowed' : 'pointer',
            fontSize: '16px',
            fontWeight: 'bold',
            width: '200px',
            opacity: (isLoading || extensionDetected === false) ? 0.7 : 1
          }}
        >
          {isLoading ? 'Processing...' : '🔑 Verify Identity'}
        </button>
      </div>
      
      {status && (
        <div style={{ 
          padding: '15px', 
          borderRadius: '5px', 
          backgroundColor: '#f8f8f8',
          maxWidth: '500px',
          marginBottom: '30px'
        }}>
          <p style={{ whiteSpace: 'pre-wrap' }}>{status}</p>
        </div>
      )}
      
      <div style={{ 
        marginTop: '40px', 
        borderRadius: '8px',
        textAlign: 'left'
      }}>
        <h3>How Meikä ID Login Works</h3>
        <p>
          Meikä uses zero-knowledge proofs to verify your identity without revealing personal information.
          The login process is secure, private, and cryptographically verifiable.
        </p>
        <p>
          When you click &quot;Verify Identity&quot;, the application will:
        </p>
        <ol style={{ paddingLeft: '20px' }}>
          <li>Generate a proof using your cryptographic keys</li>
          <li>Verify the proof against the public registry</li>
          <li>Authenticate you without exposing personal details</li>
        </ol>
      </div>
    </main>
  );
} 