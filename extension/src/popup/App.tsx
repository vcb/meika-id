import React, { useState, useEffect, createContext, useContext } from 'react';
import browser from 'webextension-polyfill';
import MainScreen from './components/MainScreen';
import { LockButton } from './components/MainScreen';
import LockedScreen from './components/LockedScreen';
import { withBackgroundAPI } from '../api-wrapper';

const openSetupPage = () => {
  browser.tabs.create({
    url: browser.runtime.getURL('build/setup.html')
  });
};

enum Screen {
  SETUP = 'setup',
  LOCKED = 'locked',
  MAIN = 'main'
}


const App: React.FC = () => {
  const [currentScreen, setCurrentScreen] = useState<Screen>(Screen.SETUP);
  
  const checkStatus = async () => {
    const status = await withBackgroundAPI(async (api) => {
      return await api.getStatus();
    });
    if (!status.initialized) { setCurrentScreen(Screen.SETUP); return};
    if (!status.unlocked) { setCurrentScreen(Screen.LOCKED); return};
    if (status.initialized && status.unlocked) { setCurrentScreen(Screen.MAIN); return};
  }

  // Check status when the popup is opened
  useEffect(() => {
    checkStatus();
  }, []);
  
  const handleUnlock = (): void => {
    checkStatus();
  };
  
  const handleLock = (): void => {
    checkStatus();
  };

  return (
    <div className="container">
      <div className="header">
        <div className="header-title">
          <h1>Meikä ID Vault</h1>
        </div>
        {currentScreen === Screen.MAIN && (
          <div className="header-actions">
            <LockButton onLock={handleLock} />
          </div>
        )}
      </div>
      
      {currentScreen === Screen.SETUP && (
        <div className="setup-container">
          <div className="setup-header">
            <h2>Initialize Vault</h2>
            <button onClick={openSetupPage}>Create New Vault</button>
            <button onClick={() => {}}>Use Recovery Phrase</button> {/* TODO: implement */}
          </div>
        </div>
      )}
      
      {currentScreen === Screen.LOCKED && (
        <LockedScreen 
          onUnlock={handleUnlock}
        />
      )}
      
      {currentScreen === Screen.MAIN && (
        <MainScreen 
          onLock={handleLock}
        />
      )}
    </div>
  );
};

export default App;