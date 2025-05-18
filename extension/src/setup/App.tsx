import React, { useState, useEffect, createContext, useContext } from 'react';
import SetupScreen from './components/SetupScreen';
import KeyScreen from './components/KeyScreen';
import { logInfo, logError } from '../logger';
import { withBackgroundAPI } from '../api-wrapper';


const App: React.FC = () => {
  const [privateKeyBip39, setPrivateKeyBip39] = useState<string | null>(null);
  const [setupComplete, setSetupComplete] = useState(false);

  const handleSetupComplete = (key: string) => {
    setPrivateKeyBip39(key);
  };

  const handleKeySaved = async () => {
    setPrivateKeyBip39(null);

    await withBackgroundAPI(async (api) => {
      const resp = await api.finishInit();
      if (!resp.success) {
        logError('Setup', 'Failed to finish setup:', resp.error);
        // TODO: Show error to user
      }
      return;
    });

    setSetupComplete(true);
    logInfo('Setup', '✅ Setup complete, closing');
    window.close();
  };

  return (
      <div className="setup-container">
        {privateKeyBip39 ? (
          <KeyScreen 
            privateKeyBip39={privateKeyBip39} 
            onKeySaved={handleKeySaved} 
          />
        ) : (
          <SetupScreen onSetupComplete={handleSetupComplete} />
        )}
      </div>
  );
};

export default App;
