import React, { createContext, useContext, useState, useCallback, type ReactNode } from 'react';

// The most recently issued permission (DAT), shared across panels so the Revocation
// step can target the exact token granted on the DATs step — no JTI copy/paste.
export interface IssuedPermission {
  token: string;
  jti: string;
  issuerDid: string;
  subjectDid: string;
  scopes: string[];
  expiresInSeconds: number;
  issuerKeyLabel: string;
}

interface IssuedDatStore {
  issued: IssuedPermission | null;
  setIssued: (p: IssuedPermission | null) => void;
}

const IssuedDatContext = createContext<IssuedDatStore | null>(null);

export function IssuedDatProvider({ children }: { children: ReactNode }) {
  const [issued, setIssuedState] = useState<IssuedPermission | null>(null);
  const setIssued = useCallback((p: IssuedPermission | null) => setIssuedState(p), []);
  return React.createElement(
    IssuedDatContext.Provider,
    { value: { issued, setIssued } },
    children
  );
}

export function useIssuedDat(): IssuedDatStore {
  const ctx = useContext(IssuedDatContext);
  if (!ctx) throw new Error('useIssuedDat must be used within an IssuedDatProvider');
  return ctx;
}
