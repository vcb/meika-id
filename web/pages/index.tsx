import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import Image from 'next/image';
import { useExtensionDetection } from '../utils/extensionDetection';

declare global {
  interface Window {
    meikaExtensionPresent: boolean;
  }
}

export default function Home() {
  const { extensionDetected } = useExtensionDetection();
  const [warningAcknowledged, setWarningAcknowledged] = useState(true);
  
  useEffect(() => {
    // Check if user has previously acknowledged the warning
    const acknowledged = document.cookie.split(';').some(item => item.trim().startsWith('meika_warning_acknowledged='));
    if (acknowledged) {
      setWarningAcknowledged(true);
    } else {
      setWarningAcknowledged(false);
    }
  }, []);

  const buttonStyle = {
    padding: '12px 24px',
    background: '#0070f3',
    color: 'white',
    border: 'none',
    borderRadius: '5px',
    cursor: 'pointer',
    fontSize: '16px',
    fontWeight: 'bold',
    margin: '10px 0',
    textDecoration: 'none',
    display: 'inline-block',
    textAlign: 'center' as const,
    width: '200px'
  };

  // Effect to handle highlighting footnotes when targeted
  useEffect(() => {
    const hashHandler = () => {
      const hash = window.location.hash;
      if (hash && hash.startsWith('#footnote-')) {
        const footnoteEl = document.querySelector(hash);
        if (footnoteEl) {
          footnoteEl.classList.add('footnote-highlighted');
          
          setTimeout(() => {
            footnoteEl.classList.remove('footnote-highlighted');
          }, 3000);
        }
      }
    };
    
    hashHandler();
    window.addEventListener('hashchange', hashHandler);
    
    return () => {
      window.removeEventListener('hashchange', hashHandler);
    };
  }, []);

  const acknowledgeWarning = () => {
    const expiryDate = new Date();
    expiryDate.setDate(expiryDate.getDate() + 30);
    document.cookie = `meika_warning_acknowledged=true; expires=${expiryDate.toUTCString()}; path=/`;
    setWarningAcknowledged(true);
  };

  // TODO: clean up the css !!
  return (
    <main style={{ padding: '2rem', maxWidth: '800px', margin: '0 auto' }}>
      <style jsx>{`
        /* Footnotes */
        .footnote-link {
          font-size: 0.7rem;
          vertical-align: super;
          margin-left: 2px;
          text-decoration: none;
          background-color: #0070f3;
          color: white;
          padding: 1px 2px;
          border-radius: 3px;
        }
        
        .footnote {
          margin-top: 1.5rem;
          font-size: 0.85rem;
          border-top: 1px solid #ddd;
          padding-top: 0.75rem;
          transition: background-color 0.3s;
        }
        
        .footnote::before {
          content: attr(data-footnote-number) ". ";
          font-weight: bold;
        }
        
        .footnote-highlighted, 
        .footnote:target {
          background-color: #fffbcc;
          padding: 0.5rem;
          border-radius: 4px;
        }

        .warning-box {
          background-color: #fff3cd;
          color: #856404;
          padding: 20px;
          margin-bottom: 25px;
          border: 2px solid #ffeeba;
          border-radius: 5px;
          font-weight: bold;
          box-shadow: 0 2px 5px rgba(0,0,0,0.15);
        }

        .warning-button {
          background-color: #dc3545;
          color: white;
          padding: 10px 16px;
          border: none;
          border-radius: 4px;
          margin-top: 15px;
          cursor: pointer;
          font-weight: bold;
          transition: background-color 0.2s;
        }

        .warning-button:hover {
          background-color: #bd2130;
        }
      `}</style>
      
      <h1 style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
        <Image src="/img/meika.png" alt="Meikä ID logo" width={40} height={40} />
        <a href="/" style={{ textDecoration: 'none', color: 'inherit' }}>meikä id</a>
      </h1>
      <p style={{ fontSize: '18px', marginBottom: '40px' }}>
        Zero-knowledge identity system for Finland
      </p>
      
      {!warningAcknowledged ? (
        <div className="warning-box">
          <div style={{ fontSize: '1.5rem', marginBottom: '10px' }}>⚠️ Warning</div>
          <p>This is a prototype only and not recommended for use unless you fully understand how everything works. Use at your own risk.</p>
          <p>By proceeding, you acknowledge that:</p>
          <ul>
            <li>This software is experimental and may contain security vulnerabilities</li>
            <li>No guarantees are provided about privacy, security, or functionality</li>
          </ul>
          <button 
            className="warning-button" 
            onClick={acknowledgeWarning}
          >
            I understand the risks and want to proceed
          </button>
        </div>
      ) : (
        <>
          <div style={{
            backgroundColor: '#fff3cd',
            color: '#856404',
            padding: '12px 16px',
            marginBottom: '25px',
            border: '1px solid #ffeeba',
            borderRadius: '5px',
            fontWeight: 'bold',
            boxShadow: '0 1px 3px rgba(0,0,0,0.1)'
          }}>
            ⚠️ <strong>Warning:</strong> This is a prototype only. Use at own risk. See the <a href="https://github.com/vcb/meika-id/blob/main/README.md" target="_blank" rel="noopener noreferrer">README</a> for more details.
          </div>
          
          <div style={{ 
            display: 'flex', 
            flexDirection: 'row', 
            justifyContent: 'flex-start',
            gap: '20px',
            marginBottom: '20px' 
          }}>
            <Link href="/register" style={buttonStyle}>
              🔐 Register
            </Link>
            <Link href="/login" style={{...buttonStyle, background: '#28a745'}}>
              🚪 Login
            </Link>
          </div>
          
          {extensionDetected !== null && (
            <div style={{
              padding: '10px 15px',
              marginBottom: '30px',
              borderRadius: '5px',
              backgroundColor: extensionDetected ? '#d4edda' : '#f8d7da',
              color: extensionDetected ? '#155724' : '#721c24',
              display: 'flex',
              alignItems: 'center',
              gap: '8px'
            }}>
              {extensionDetected ? (
                <>
                  <span style={{ fontSize: '20px' }}>✅</span>
                  <span>Meikä ID extension detected</span>
                </>
              ) : (
                <>
                  <span style={{ fontSize: '20px' }}>🗝️</span>
                  <span>
                    Meikä ID extension not detected. <a href="#" style={{ color: 'inherit', fontWeight: 'bold' }}>Install the extension</a> to use Meikä ID.
                  </span>
                </>
              )}
            </div>
          )}
        </>
      )}
      
      <div style={{ 
        marginTop: '3rem', 
        borderRadius: '8px',
      }}>
        <h2>About Meikä ID</h2>
        <p>
          Meikä - short for meikäläinen - is a zero-knowledge identity system for Finland.
          <br />
          <br />
          Meikä ID allows you to prove you're a unique Finnish ID card holder without revealing your personal details.
          Using advanced cryptography, you can verify your identity status 
          online while maintaining your privacy. 
          <br />
          <br />
          You demonstrate that you're a legitimate, unique 
          Finnish ID card holder (available to citizens and permanent residents) without exposing who specifically you are. 
          None of your personal information ever leaves your device.
        </p>
        <p>
        <span style={{color: 'rgb(0, 0, 0)', fontWeight: 'bold', borderRadius: '4px' }}>With Meikä ID, everyone is just a meikäläinen</span>

        </p>
        
        <h3 style={{ marginTop: '2rem' }}>How it works</h3>
        <h4>Registration</h4>
        <ol>
          <li>Create a new keypair for your Meikä identity with the extension</li>
          <li>
            Generate the proof of ownership of the ID card locally
            <a href="#footnote-1" className="footnote-link">1</a>
          </li>
          <li>
            Send the proof and its outputs to the Meikä ID server
            <a href="#footnote-2" className="footnote-link">2</a>
          </li>
          <li>
            The server verifies the proof and stores it in a public register, along with the outputs. These outputs are used to prove your identity when logging in and cannot be used to identify you.
          </li>
        </ol>
        <h4>Login</h4>
        <ol>
          <li>Prove ownership of your Meikä identity key and inclusion in the register in browser</li>
          <li>Proof is sent to the Meikä ID server for verification</li>
          <li>Server verifies the proof and returns the result</li>
        </ol>
        
        <p id="footnote-1" className="footnote" data-footnote-number="1">
          Due to complexity of the registration proof, this is recommended to be done on a PC with <code>rapidsnark</code> (linux/WSL only). It is possible to generate the proof with <code>snarkjs</code>, but it requires a high-end PC. With <code>rapidsnark</code>, only ~3GB of RAM is required and proof generation should only take some seconds.
        </p>
        <p id="footnote-2" className="footnote" data-footnote-number="2">
          Only your proof and its public outputs are store.
        </p>
      </div>
    </main>
  );
}
