import React, { useState, useEffect, useRef } from 'react';
import { logError, logInfo } from '../../logger';
import { withBackgroundAPI } from '../../api-wrapper';
import { VaultStatus } from 'src/types';
import { RegistrationProof, SignatureRequest, LoginRequest } from '@lib/types';

const toHexString = (str: string): string => {
  return Array.from(str)
    .map(c => c.charCodeAt(0).toString(16).padStart(2, '0'))
    .join(' ');
};

const truncateNumber = (num: string): string => {
  if (!num || num.length <= 15) return num;
  return `${num.substring(0, 6)}...${num.substring(num.length - 6)}`;
};

const displayWithSpecialChars = (str: string): React.ReactElement => {
  const elements: React.ReactNode[] = [];

  for (let i = 0; i < str.length; i++) {
    const codeUnit = str.charCodeAt(i);
    const char = str[i];

    const isSpecial =
      codeUnit < 32 ||
      (codeUnit >= 127 && codeUnit <= 159) ||
      (codeUnit >= 0x200B && codeUnit <= 0x200F) ||
      (codeUnit >= 0x2028 && codeUnit <= 0x202F) ||
      codeUnit === 0xFEFF ||
      (codeUnit >= 0x2060 && codeUnit <= 0x206F) ||
      (codeUnit >= 0x180B && codeUnit <= 0x180E) ||
      (codeUnit >= 0xFFF9 && codeUnit <= 0xFFFC) ||
      (codeUnit >= 0x2000 && codeUnit <= 0x200A) ||
      codeUnit === 0x00A0 ||
      codeUnit === 0x00AD ||
      (codeUnit >= 0x0300 && codeUnit <= 0x036F) ||
      (codeUnit >= 0xFFF0 && codeUnit <= 0xFFFF) ||
      (codeUnit >= 0xD800 && codeUnit <= 0xDFFF); // catch all surrogates

    if (isSpecial) {
      elements.push(
        <span key={i} className="special-char">
          U+{codeUnit.toString(16).toUpperCase().padStart(4, '0')}
        </span>
      );
    } else {
      elements.push(<span key={i}>{char}</span>);
    }
  }

  return <>{elements}</>;
};

interface MainScreenProps {
  onLock: () => void;
}

// Lock button component that can be used independently
export const LockButton: React.FC<{ onLock: () => void }> = ({ onLock }) => {
  const handleLock = async () => {
    try {
      const response = await withBackgroundAPI(async (api) => {
        return await api.lock();
      });

      logInfo('Popup', 'Lock response:', response);
      
      if (response.success) {
        onLock();
      }
    } catch (err) {
      logError('Popup', 'Error locking vault:', err);
    }
  };

  return (
    <div className="lock-button" onClick={handleLock}>
      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="24" height="24">
        <path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-6 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1 1.71 0 3.1 1.39 3.1 3.1v2z" fill="currentColor"/>
      </svg>
    </div>
  );
};

enum Screen {
  MAIN = 'main',
  SIGN = 'sign',
  REGISTER = 'register'
}

const MainScreen: React.FC<MainScreenProps> = ({ onLock }) => {
  const [currentScreen, setCurrentScreen] = useState<Screen>(Screen.MAIN);
  const [signatureRequests, setSignatureRequests] = useState<Map<number, SignatureRequest>>(new Map());
  const requestsRef = useRef<Map<number, SignatureRequest>>(new Map());
  const [registrationData, setRegistrationData] = useState<RegistrationProof>();
  const registrationDataRef = useRef<RegistrationProof | null>(null);
  const [vaultStatus, setVaultStatus] = useState<VaultStatus>();
  const vaultStatusRef = useRef<VaultStatus | null>(null);
  const [loginRequest, setLoginRequest] = useState<LoginRequest | null>(null);
  const loginRequestRef = useRef<LoginRequest | null>(null);
  const [debugInput, setDebugInput] = useState<string>('');
  const [hashResult, setHashResult] = useState<string>('');


  const fetchSignatureRequests = async () => {
    const response = await withBackgroundAPI(async (api) => {
      return await api.getSignatureRequests();
    });

    if (response.success) {
      const requests = response.requests || new Map();
      requestsRef.current = requests;
      setSignatureRequests(requests);
    }
  };

  const fetchRegistrationData = async () => {
    const response = await withBackgroundAPI(async (api) => {
      return await api.getRegistrationData();
    });

    if (response.success && response.registrationData) {
      let parsedData: RegistrationProof;
      
      // Check if the data is a string and needs parsing
      if (typeof response.registrationData === 'string') {
        try {
          parsedData = JSON.parse(response.registrationData);
        } catch (e) {
          logError('MainScreen', 'Failed to parse registration data:', e);
          return;
        }
      } else {
        parsedData = response.registrationData;
      }
      
      setRegistrationData(parsedData);
      registrationDataRef.current = parsedData;
    }
  };

  const fetchLoginRequest = async () => {
    const response = await withBackgroundAPI(async (api) => {
      return await api.getLoginRequest();
    });

    if (response.success && response.loginRequest) {
      logInfo('Popup', 'Received login request');
      setLoginRequest(response.loginRequest);
      loginRequestRef.current = response.loginRequest;
    }
  };

  useEffect(() => {
    const fetchVaultStatus = async () => {
      const status = await withBackgroundAPI(async (api) => {
        return await api.getStatus();
      });
      
      setVaultStatus(status);
      vaultStatusRef.current = status;

      fetchLoginRequest();
      if (status.registered) {
        return;
      }
      fetchRegistrationData();
    };

    fetchVaultStatus();
    fetchSignatureRequests();
  }, []);

  const handleReview = () => {
    setCurrentScreen(Screen.SIGN);
  }

  const handleSign = async (id: number) => {
    const response = await withBackgroundAPI(async (api) => {
      return await api.signSignatureRequest(id);
    });

    if (response.success) {
      await fetchSignatureRequests();
      if (requestsRef.current.size === 0) {
        setCurrentScreen(Screen.MAIN);
      }
    } else {
      // TODO: indicate error to user
      logError('Popup', 'Error signing signature request');
    }
  }

  const handleRejectSignature = async (id: number) => {
    const response = await withBackgroundAPI(async (api) => {
      return await api.rejectSignatureRequest(id);
    });

    if (response.success) {
      await fetchSignatureRequests();
      if (requestsRef.current.size === 0) {
        setCurrentScreen(Screen.MAIN);
      }
    }
  }

  const handleRegister = () => {
    setCurrentScreen(Screen.REGISTER);
  }

  const handleSubmitRegistration = async () => {
    const data = registrationDataRef.current;
    if (!data) {
      // TODO: indicate error to user
      logError('Popup', 'No registration data found');
      return;
    }

    const response = await withBackgroundAPI(async (api) => {
      return await api.register({
        proof: data.proof,
        publicSignals: data.publicSignals,
        dvvIndex: data.dvvIndex,
        zkIndex: data.zkIndex
      });
    });

    if (response.success) {
      // Clear registration data
      setRegistrationData(undefined);
      registrationDataRef.current = null;

      // Refresh vault status
      const updatedStatus = await withBackgroundAPI(async (api) => {
        return await api.getStatus();
      });
      setVaultStatus(updatedStatus);
      vaultStatusRef.current = updatedStatus;
      
      setCurrentScreen(Screen.MAIN);
    } else {
      // TODO: indicate error to user
      logError('Popup', 'Error registering vault:', response.error);
    }
  }

  // Open login page in a new popup
  const handleLoginConfirm = async () => {
    browser.tabs.create({
      url: browser.runtime.getURL('build/login.html')
    });
    window.close();
  };

  const handleLoginReject = async () => {
    const response = await withBackgroundAPI(async (api) => {
      return await api.rejectLoginRequest();
    });

    if (response.success) {
      setLoginRequest(null);
    }
  };

  return (
    <div className="screen">
      {currentScreen === Screen.MAIN && (
      <div className="status-section">
        <div className="section-card">
          <div className="section-title">Vault Status</div>
          <div className="status-indicators">
            <div className="status-indicator">
              <span className={`status-dot ${vaultStatusRef.current?.unlocked ? 'active' : 'inactive'}`}></span>
              <span>{vaultStatusRef.current?.unlocked ? 'Unlocked' : 'Locked'}</span>
            </div>
            <div className="status-indicator">
              <span className={`status-dot ${vaultStatusRef.current?.registered ? 'active' : 'inactive'}`}></span>
              <span>{vaultStatusRef.current?.registered ? 'Registered' : 'Not registered'}</span>
            </div>
          </div>
        </div>

        {signatureRequests.size > 0 && (
          <div className="section-card signature-section">
            <div className="section-title">Signature Requests</div>
            <div className="signature-row">
              <div className="badge-button-group">
                <div className="badge">{signatureRequests.size}</div>
                <button onClick={handleReview} className="review-button">Review & Sign</button>
              </div>
            </div>
          </div>
        )}

        {loginRequest && (
          <div className="section-card">
            <div className="section-title">Login Request</div>
            <div className="login-request-container">
              <div className="login-request-domain">
                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="#5f6368" style={{ marginRight: '8px', flexShrink: 0 }}>
                  <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z"/>
                </svg>
                {loginRequest.domain}
              </div>
              <div className="login-request-button-row">
                <button className="login-request-button" onClick={handleLoginConfirm}>Login</button>
                <button className="login-request-button reject" onClick={handleLoginReject}>Reject</button>
              </div>
            </div>
          </div>
        )}

        {registrationDataRef.current && (
          <div className="section-card">
            <div className="section-title">Registration</div>
            <div className="registration-container">
              <button className="registration-button" onClick={handleRegister}>Register your proof</button>
            </div>
          </div>
        )}
      </div>
      )}

      {currentScreen === Screen.SIGN && (
        <div className="status-section">
          <div className="section-card signature-request">
            <div className="section-title">Signature Request</div>
            
            {signatureRequests.size > 0 && (
              function() {
                // Get the first available key from the Map
                const firstKey = Array.from(signatureRequests.keys())[0];
                const request = signatureRequests.get(firstKey);
                
                return (
                  <>
                    <div className="signature-domain">
                      {request?.domain}
                    </div>
                    
                    <div className="signature-content-section">
                      <div className="signature-label">Message (Plaintext):</div>
                      <div className="signature-text-box">
                        {typeof request?.message === 'string' ? displayWithSpecialChars(request?.message) : request?.message.join(' ')}
                      </div>
                    </div>
                    
                    {typeof request?.message === 'string' && (
                      <div className="signature-content-section">
                        <div className="signature-label">Hexadecimal:</div>
                        <div className="signature-text-box hex">
                          {toHexString(request?.message || '')}
                        </div>
                      </div>
                    )}
                    
                    <div className="button-row">
                      <button onClick={() => handleRejectSignature(firstKey)} className="action-button reject-button">Reject</button>
                      <button onClick={() => handleSign(firstKey)} className="action-button sign-button">Sign</button>
                    </div>
                  </>
                );
              }()
            )}
          </div>
        </div>
      )}

      {currentScreen === Screen.REGISTER && (
        <div className="status-section">
          <div className="section-card">
            <div className="section-title">Registration Data</div>
            
            <div className="section-subtitle">Public Signals</div>
            <div className="compact-signal-list">
              {registrationDataRef.current && (
                <>
                  <div key={0} className="compact-signal-item" title={registrationDataRef.current?.publicSignals.zkCommitment.toString() || ''}>
                    {registrationDataRef.current.publicSignals.zkCommitment ? truncateNumber(registrationDataRef.current.publicSignals.zkCommitment.toString()) : 'Not available'}
                  </div>
                  <div key={1} className="compact-signal-item" title={registrationDataRef.current?.publicSignals.dvvCommitment.toString() || ''}>
                    {registrationDataRef.current.publicSignals.dvvCommitment ? truncateNumber(registrationDataRef.current.publicSignals.dvvCommitment.toString()) : 'Not available'}
                  </div>
                  <div key={2} className="compact-signal-item" title={registrationDataRef.current?.publicSignals.nullifier.toString() || ''}>
                    {registrationDataRef.current.publicSignals.nullifier ? truncateNumber(registrationDataRef.current.publicSignals.nullifier.toString() || '') : 'Not available'}
                  </div>
                </>
              )}
            </div>
            
            <div className="section-subtitle">Merkle Tree Indices</div>
            <div className="compact-indices">
              <div className="index-row">
                <span className="index-label">DVV Commitment:</span>
                <span className="index-value">{registrationDataRef.current?.dvvIndex != null ? registrationDataRef.current.dvvIndex : 'Not available'}</span>
              </div>
              <div className="index-row">
                <span className="index-label">Meikä ID Commitment:</span>
                <span className="index-value">{registrationDataRef.current?.zkIndex != null ? registrationDataRef.current.zkIndex : 'Not available'}</span>
              </div>
            </div>
            
            <button 
              className="action-button register-button" 
              onClick={handleSubmitRegistration}
            >
              Submit Registration
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

export default MainScreen;
