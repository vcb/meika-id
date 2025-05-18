import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import './setup.css';
import { logError } from '../logger';

document.addEventListener('DOMContentLoaded', () => {
  const rootElement = document.getElementById('root');
  
  if (rootElement) {
    const root = ReactDOM.createRoot(rootElement);
    root.render(<App />);
  } else {
    logError('Setup', 'Root element not found');
  }
});

// Log any uncaught errors
window.addEventListener('error', (event) => {
  logError('Setup', 'Uncaught error:', event.error);
});