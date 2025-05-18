import React, { useState } from 'react';
import { logError, logInfo } from '../../logger';
import { withBackgroundAPI } from '../../api-wrapper';

interface LockedScreenProps {
  onUnlock: () => void;
}

const LockedScreen: React.FC<LockedScreenProps> = ({ onUnlock }) => {
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  const handleUnlock = async () => {
    setIsLoading(true);
    setError('');
    
    try {
      const response = await withBackgroundAPI(async (api) => {
        return await api.unlock(password);
      });
      
      if (response.success) {
        onUnlock();
      } else {
        logError('Popup', 'Error unlocking vault:', response.error);
        setError(response.error || 'Failed to unlock vault');
      }
    } catch (err) {
      logError('Popup', 'Exception unlocking vault:', err);
      setError('Failed to unlock vault');
    } finally {
      setIsLoading(false);
    }
  }

  return (
    <div className="screen">
      <div className="status-section">
        <div className="status-indicator">
          <span className="status-dot inactive"></span>
          <span>Vault Locked</span>
        </div>
        
        <div className="input-container">
          <input 
            type="password" 
            placeholder="Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            disabled={isLoading}
          />
          {error && <div className="error-message">{error}</div>}
        </div>
        <div className="actions">
          {isLoading ? (
            <div className="loading-spinner"></div>
          ) : (
            <button 
              className="action-button"
              onClick={handleUnlock}
              disabled={!password.trim()}
            >
              Unlock Vault
            </button>
          )}
        </div>
      </div>
    </div>
  );
};

export default LockedScreen;
