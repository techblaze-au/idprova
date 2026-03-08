import React, { createContext, useContext, useState, useCallback, type ReactNode } from 'react';
import { generateKeypair } from '../crypto/ed25519';
import { toHex, toMultibase } from '../crypto/encoding';
import type { StoredKey } from '../types';

interface KeyStore {
  keys: StoredKey[];
  addKey: (label: string) => StoredKey;
  removeKey: (label: string) => void;
  getKey: (label: string) => StoredKey | undefined;
}

const KeyContext = createContext<KeyStore | null>(null);

export function KeyProvider({ children }: { children: ReactNode }) {
  const [keys, setKeys] = useState<StoredKey[]>([]);

  const addKey = useCallback((label: string): StoredKey => {
    const { privateKey, publicKey } = generateKeypair();
    const key: StoredKey = {
      label,
      publicKeyHex: toHex(publicKey),
      publicKeyMultibase: toMultibase(publicKey),
      privateKeyHex: toHex(privateKey),
      createdAt: new Date().toISOString(),
    };
    setKeys(prev => [...prev, key]);
    return key;
  }, []);

  const removeKey = useCallback((label: string) => {
    setKeys(prev => prev.filter(k => k.label !== label));
  }, []);

  const getKey = useCallback((label: string) => {
    return keys.find(k => k.label === label);
  }, [keys]);

  return React.createElement(
    KeyContext.Provider,
    { value: { keys, addKey, removeKey, getKey } },
    children
  );
}

export function useKeys(): KeyStore {
  const ctx = useContext(KeyContext);
  if (!ctx) throw new Error('useKeys must be used within a KeyProvider');
  return ctx;
}
