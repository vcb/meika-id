import React, { useState, useEffect, useRef } from 'react';
import { logError, logInfo } from '../../logger';
import * as bip39 from 'bip39';
import { withBackgroundAPI } from '../../api-wrapper';

interface SetupScreenProps {
  onSetupComplete: (privateKey: string) => void;
}

enum SetupStep {
  PASSWORD_ENTRY = 'password_entry',
  GENERATING_KEYS = 'generating_keys'
}

const PASSWORD_MIN_LENGTH = 10;

const SetupScreen: React.FC<SetupScreenProps> = ({ onSetupComplete }) => {
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [isPasswordValid, setIsPasswordValid] = useState(false);
  const [isPasswordLengthValid, setIsPasswordLengthValid] = useState(false);
  const [currentStep, setCurrentStep] = useState<SetupStep>(SetupStep.PASSWORD_ENTRY);

  useEffect(() => {
    if (confirmPassword !== '' && password !== confirmPassword) {
      setIsPasswordValid(false);
      return;
    }

    setIsPasswordValid(true);
  }, [password,confirmPassword]);

  useEffect(() => {
    if (password.length < PASSWORD_MIN_LENGTH) {
      setIsPasswordLengthValid(false);
      return;
    }
    setIsPasswordLengthValid(true);
  }, [password]);

  const handleCreateKey = async () => {
    if (password !== confirmPassword) {
      alert('Passwords do not match!');
      return;
    }
    
    if (password.length < PASSWORD_MIN_LENGTH) {
      alert(`Password must be at least ${PASSWORD_MIN_LENGTH} characters.`);
      return;
    }

    // Move to generating keys step
    setCurrentStep(SetupStep.GENERATING_KEYS);
    setIsLoading(true);
    
    try {
      const response = await withBackgroundAPI(async (api) => {
        return await api.init(password);
      });
      
      if (response.success && response.key) {
        // Convert private key to bip39 mnemonic for display
        const privateKeyBip39 = bip39.entropyToMnemonic(Buffer.from(response.key).toString('hex'));
        
        // Pass control directly to parent component
        onSetupComplete(privateKeyBip39);
      } else {
        throw new Error(response.error || 'Unknown error');
      }
    } catch (error: unknown) {
      logError('Setup', 'Error generating keypair:', error);
      // TODO: indicate error to user instead of going back
      setCurrentStep(SetupStep.PASSWORD_ENTRY);
    } finally {
      setIsLoading(false);
    }
  };
  
  // Render different content based on current step
  const renderStepContent = () => {
    switch (currentStep) {
      case SetupStep.PASSWORD_ENTRY:
        return (
          <>
            <h2>Set Up Your Vault</h2>
            <p>Create a password to secure your keys</p>
            
            <div className="input-container">
              <input 
                type="password" 
                placeholder="Password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                disabled={isLoading}
                className={password.length > 0 && !isPasswordLengthValid ? "input-error" : ""}
              />
              {password.length > 0 && !isPasswordLengthValid && (
                <div className="error-message">Password must be at least {PASSWORD_MIN_LENGTH} characters</div>
              )}
            </div>
            
            <div className="input-container">
              <input 
                type="password" 
                placeholder="Confirm Password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                disabled={isLoading}
                style={{ marginTop: '10px' }}
                className={confirmPassword.length > 0 && !isPasswordValid ? "input-error" : ""}
              />
              {confirmPassword.length > 0 && !isPasswordValid && (
                <div className="error-message" style={{ marginBottom: '10px' }}>Passwords do not match</div>
              )}
            </div>
            
            <button 
              onClick={handleCreateKey} 
              disabled={isLoading || !isPasswordValid || !isPasswordLengthValid || password.length === 0}
            >
              Create Key
            </button>
          </>
        );
        
      case SetupStep.GENERATING_KEYS:
        return (
          <>
            <h2>Preparing Your Keys</h2>
            <div className="loading-spinner"></div>
            <p>Please wait while your keys are generated...</p>
          </>
        );
    }
  };
  
  return (
    <div className="screen">
      {renderStepContent()}
    </div>
  );
};

export default SetupScreen;