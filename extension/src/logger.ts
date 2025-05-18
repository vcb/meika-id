export function logInfo(module: string, ...args: any[]) {
    console.log(`[${module}]`, ...args);
  }
  
  export function logError(module: string, ...args: any[]) {
    console.error(`[${module}]`, ...args);
  }
  
export function logWarn(module: string, ...args: any[]) {
    console.warn(`[${module}]`, ...args);
}

export function logDebug(module: string, ...args: any[]) {
    console.debug(`[${module}]`, ...args);
}