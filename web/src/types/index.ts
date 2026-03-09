// ── Key types ─────────────────────────────────────────────────────────────

export interface StoredKey {
  label: string;
  publicKeyHex: string;
  publicKeyMultibase: string;
  privateKeyHex: string;
  createdAt: string;
}

// ── AID types ─────────────────────────────────────────────────────────────

export interface VerificationMethod {
  id: string;
  type: string;
  controller: string;
  publicKeyMultibase: string;
}

export interface AgentMetadata {
  name: string;
  description?: string;
  model?: string;
  runtime?: string;
  configAttestation?: string;
}

export interface AidService {
  id: string;
  type: string;
  serviceEndpoint: AgentMetadata | Record<string, unknown>;
}

export interface AidDocument {
  '@context': string[];
  id: string;
  controller: string;
  verificationMethod: VerificationMethod[];
  authentication: string[];
  service?: AidService[];
  trustLevel?: string;
  version?: number;
  created?: string;
  updated?: string;
  proof?: AidProof;
}

export interface AidProof {
  type: string;
  created: string;
  verificationMethod: string;
  proofValue: string;
}

// ── DAT types ─────────────────────────────────────────────────────────────

export interface DatHeader {
  alg: string;
  typ: string;
  kid: string;
}

export interface DatConstraints {
  maxActions?: number;
  allowedServers?: string[];
  requireReceipt?: boolean;
  maxCallsPerHour?: number;
  maxCallsPerDay?: number;
  maxConcurrent?: number;
  allowedIPs?: string[];
  deniedIPs?: string[];
  requiredTrustLevel?: string;
  maxDelegationDepth?: number;
  geofence?: string[];
  timeWindows?: TimeWindow[];
  requiredConfigAttestation?: string;
}

export interface TimeWindow {
  days: number[];
  start_hour: number;
  end_hour: number;
}

export interface DatClaims {
  iss: string;
  sub: string;
  iat: number;
  exp: number;
  nbf: number;
  jti: string;
  scope: string[];
  constraints?: DatConstraints;
  configAttestation?: string;
  delegationChain?: string[];
}

// ── Scope types ───────────────────────────────────────────────────────────

export interface ParsedScope {
  namespace: string;
  protocol: string;
  resource: string;
  action: string;
}

// ── Receipt types ─────────────────────────────────────────────────────────

export interface ActionDetails {
  type: string;
  server?: string;
  tool?: string;
  inputHash: string;
  outputHash?: string;
  status: string;
  durationMs?: number;
}

export interface ReceiptContext {
  sessionId?: string;
  parentReceiptId?: string;
  requestId?: string;
}

export interface ChainLink {
  previousHash: string;
  sequenceNumber: number;
}

export interface Receipt {
  id: string;
  timestamp: string;
  agent: string;
  dat: string;
  action: ActionDetails;
  context?: ReceiptContext;
  chain: ChainLink;
  signature: string;
}

// ── Registry API types ────────────────────────────────────────────────────

export interface HealthResponse {
  status: string;
  version: string;
  protocol: string;
}

export interface MetaResponse {
  protocolVersion: string;
  registryVersion: string;
  didMethod: string;
  supportedAlgorithms: string[];
  supportedHashAlgorithms: string[];
}

export interface DatVerifyRequest {
  token: string;
  scope?: string;
  request_ip?: string;
  trust_level?: number;
  delegation_depth?: number;
  actions_in_window?: number;
  country_code?: string;
  agent_config_hash?: string;
}

export interface DatVerifyResponse {
  valid: boolean;
  issuer?: string;
  subject?: string;
  scopes?: string[];
  jti?: string;
  error?: string;
}

export interface RevokeRequest {
  jti: string;
  reason: string;
  revoked_by: string;
  token?: string;
}

export interface RevocationRecord {
  jti: string;
  reason: string;
  revoked_by: string;
  revoked_at: string;
}

export interface RevocationListResponse {
  revocations: RevocationRecord[];
  count: number;
  limit: number;
  offset: number;
}

export interface RevocationCheckResponse {
  revoked: boolean;
  jti: string;
  reason?: string;
  revoked_by?: string;
  revoked_at?: string;
}

// ── AID list types (Track V-2) ────────────────────────────────────────────

export interface AidListEntry {
  id: string;
  version?: number;
}

export interface AidListResponse {
  total: number;
  aids: AidListEntry[];
}
