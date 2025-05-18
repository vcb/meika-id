import { useState, useEffect, useRef } from 'react';

declare global {
  interface Window {
    meikaExtensionPresent: boolean;
  }
}

/**
 * Hook to detect if the Meikä ID browser extension is installed
 * @returns An object containing the detection state and a function to manually trigger detection
 */
export function useExtensionDetection() {
  const [extensionDetected, setExtensionDetected] = useState<boolean | null>(null);
  const detectionRef = useRef<boolean | null>(null);

  const detectExtension = () => {
    console.log('Website: Checking for Meikä ID extension...');
    
    // Reset the detection state
    detectionRef.current = null;
    setExtensionDetected(null);
    
    window.postMessage({
      type: 'MEIKA_PING',
    }, window.location.origin);
    
    const timer = setTimeout(() => {
      if (detectionRef.current === null) {
        console.log('Website: Extension detection timeout - not found');
        setExtensionDetected(false);
      }
    }, 2000);
    
    return timer;
  };

  useEffect(() => {
    // Listen for extension detection event
    const extensionDetectedHandler = (event: MessageEvent) => {
      if (event.origin !== window.location.origin || event.source !== window) {
        console.log('🔍 Meikä ID extension: Ignoring message from unknown origin or source');
        return;
      }

      if (event.data.type === 'MEIKA_PONG') {
        console.log('Website: Meikä ID extension detected!', event.data);
        detectionRef.current = true;
        setExtensionDetected(true);
      }
    };
    
    window.addEventListener('message', extensionDetectedHandler as EventListener);

    const timer = detectExtension();
    return () => {
      clearTimeout(timer);
      window.removeEventListener('message', extensionDetectedHandler as EventListener);
    };
  }, []); // Only run once when component mounts

  return {
    extensionDetected,
    detectExtension
  };
} 