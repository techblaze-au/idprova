import bs58 from 'bs58';

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/** Base64url encode (no padding) — matches Rust URL_SAFE_NO_PAD. */
export function base64urlEncode(data: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < data.length; i++) {
    binary += String.fromCharCode(data[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Base64url decode (no padding). */
export function base64urlDecode(str: string): Uint8Array {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4 !== 0) base64 += '=';
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/** Encode a string to Uint8Array (UTF-8). */
export function stringToBytes(str: string): Uint8Array {
  return encoder.encode(str);
}

/** Decode Uint8Array to string (UTF-8). */
export function bytesToString(bytes: Uint8Array): string {
  return decoder.decode(bytes);
}

/** Convert bytes to hex string. */
export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

/** Convert hex string to bytes. */
export function fromHex(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

/** Encode raw 32-byte public key to multibase (Base58Btc with 'z' prefix). */
export function toMultibase(publicKey: Uint8Array): string {
  return 'z' + bs58.encode(publicKey);
}

/** Decode multibase (Base58Btc, 'z' prefix) to raw bytes. */
export function fromMultibase(multibase: string): Uint8Array {
  if (!multibase.startsWith('z')) {
    throw new Error('expected multibase with z (Base58Btc) prefix');
  }
  return bs58.decode(multibase.slice(1));
}
