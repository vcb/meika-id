import { getRandomFr } from "../util/field";

export const SERVICE_ID_PREFIX = "meika-id::";

const localHostRegex = /^(https?):\/\/(localhost|127\.0\.0\.1):(\d{4})(\/.*)?/;

/**
 * Checks if a domain is localhost.
 * 
 * @param domain - The domain to check.
 * @returns True if the domain is localhost, false otherwise.
 */
function isLocalhost(domain: string): boolean {
  if (domain === "localhost") {
    return true;
  }
  return localHostRegex.test(domain);
}

/**
 * Converts a domain to a service ID, prefix + hostname.
 * If the domain is localhost, returns prefix + "localhost".
 * 
 * @param domain - The domain to convert.
 * @returns The service ID.
 */
export function domainToServiceId(domain: string): string {
  if (isLocalhost(domain)) {
    return SERVICE_ID_PREFIX + "localhost";
  }
  const url = new URL(domain);
  return SERVICE_ID_PREFIX + url.hostname;
}

/**
 * Generates a random challenge. Single field element.
 * 
 * @returns The challenge.
 */
export function generateChallenge(): string {
  return getRandomFr().toString();
}