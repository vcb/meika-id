import React from 'react';

interface KeyScreenProps {
  privateKeyBip39: string;
  onKeySaved: () => void;
}

const KeyScreen: React.FC<KeyScreenProps> = ({ privateKeyBip39, onKeySaved }) => {
  // Split the mnemonic phrase into individual words for display
  const words = privateKeyBip39.trim().split(/\s+/);

  return (
    <div className="screen">
    <h2>Your Recovery Phrase</h2>
    <p>
      This allows you to recover your Meikä identity if you reinstall or switch devices.
    </p>
    <p className="technical-note">
      This is the bip39 mnemonic for your private key (BabyJub EdDSA). It is used for logging in with your Meikä ID after registration.
    </p>

      <div className="mnemonic-grid">
        {words.map((word, index) => (
          <div key={index} className="word-box">
            <span className="word-index">{index + 1}</span>
            <span className="word">{word}</span>
          </div>
        ))}
      </div>
      
      <p className="warning">
        Write it down and store it in a secure location. Never share it with anyone.
      </p>
      <button onClick={onKeySaved}>
        I've Saved My Key
      </button>
    </div>
  );
};

export default KeyScreen; 