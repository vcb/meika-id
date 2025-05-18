import { browser as browser2 } from 'webextension-polyfill-ts';
import * as Comlink from 'comlink';
import { createEndpoint } from 'comlink-extension';
import { logError } from './logger';
import { BackgroundAPI } from './background';

export type RemoteBackgroundAPI = Comlink.Remote<BackgroundAPI>;

export async function createBackgroundAPI(): Promise<{api: RemoteBackgroundAPI, disconnect: () => void}> {
  try {
    const port = browser2.runtime.connect({ name: `popup-background-${Date.now()}` });
    const api = Comlink.wrap<BackgroundAPI>(createEndpoint(port));
    return {api, disconnect: () => {
      // Release the proxy and disconnect port
      api[Comlink.releaseProxy]();
      port.disconnect()
    }};
  } catch (error) {
    logError('App', 'Failed to create background API:', error);
    throw error;
  }
}

export async function withBackgroundAPI<T>(cb: (api: RemoteBackgroundAPI) => Promise<T>): Promise<T> {
  const { api, disconnect } = await createBackgroundAPI();
  try {
    return await cb(api);
  } finally {
    disconnect();
  }
}