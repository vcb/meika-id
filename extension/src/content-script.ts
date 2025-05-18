// Content script to communicate with the website
import browser from 'webextension-polyfill';
import { WebMessage, WebMessageType, RegistrationProof, SignatureRequest, SignatureResponseContent, LoginRequest, LoginResponseContent } from '@lib/types';

const manifest = browser.runtime.getManifest();
const version = manifest.version;

console.log('Meika extension content script loaded on:', window.location.href);

const port = browser.runtime.connect({ name: 'meika-content-script' });

port.onMessage.addListener(message => {
  const msg = message as WebMessage;
  switch (msg.type) {
    case WebMessageType.SIGNATURE_RESPONSE:
    console.log('✅ Meika extension: received signature response from extension, forwarding...');
    console.log(msg.content);
    
    const data = msg.content as SignatureResponseContent;
    const { signature, packed, pk, origin } = data;
    
    if (origin == undefined || origin !== window.location.origin) {  
      return;
    }
    
    // Send the signature response to the website
    window.postMessage({
      type: WebMessageType.SIGNATURE_RESPONSE,
      content: {
        signature: signature,
        packed: packed,
        pk: pk
      }
    }, window.location.origin);
    break;
    
    case WebMessageType.LOGIN_RESPONSE:
    console.log('✅ Meika extension: received login response from extension, forwarding...');
    console.log(msg.content);

    const { proof, publicSignals, origin: loginOrigin } = msg.content as LoginResponseContent;
    if (loginOrigin == undefined || loginOrigin !== window.location.origin) {
      return;
    }
    
    // Send the login response to the website
    window.postMessage({
      type: WebMessageType.LOGIN_RESPONSE,
      content: {
        proof: proof,
        publicSignals: publicSignals
      }
    }, window.location.origin);
    break;
    
    default:
    break;
  }
});

// Function to notify the website that the extension is installed
function notifyWebsiteOfExtension() {
  console.log('🔔 Meika extension: Notifying website of presence');
  
  window.postMessage({
    type: WebMessageType.PONG,
    fromExtension: true,
    data: {
      version: version,
      extensionInstalled: true
    }
  }, window.location.origin);
}

window.addEventListener('message', (event) => {
  if (event.origin !== window.location.origin || event.source !== window) {
    return;
  }
  if (event.data.fromExtension) {
    return;
  }

  console.log('Meika extension: received message from:', event.origin);
  
  switch (event.data.type) {
    case WebMessageType.PING:
    notifyWebsiteOfExtension();
    break;
    
    case WebMessageType.SIGNATURE_REQUEST:
    
    port.postMessage({
      type: WebMessageType.SIGNATURE_REQUEST,
      content: event.data.content as SignatureRequest,
      origin: event.origin
    });
    break;

    case WebMessageType.SUBMIT_PROOF:
    port.postMessage({
      type: WebMessageType.SUBMIT_PROOF,
      content: event.data.content as RegistrationProof,
      origin: event.origin
    });
    break;

    case WebMessageType.LOGIN_REQUEST:
    port.postMessage({
      type: WebMessageType.LOGIN_REQUEST,
      content: event.data.content as LoginRequest,
      origin: event.origin
    });
    break;
    
    default:
    break;
  }
});