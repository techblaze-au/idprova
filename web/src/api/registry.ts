import type {
  AidDocument, HealthResponse, MetaResponse,
  DatVerifyRequest, DatVerifyResponse,
  RevokeRequest, RevocationListResponse, RevocationCheckResponse,
} from '../types';

export class RegistryClient {
  constructor(private baseUrl: string) {}

  setBaseUrl(url: string) {
    this.baseUrl = url;
  }

  private async request<T>(path: string, init?: RequestInit): Promise<T> {
    const res = await fetch(`${this.baseUrl}${path}`, {
      ...init,
      headers: { 'Content-Type': 'application/json', ...init?.headers },
    });
    if (!res.ok) {
      const body = await res.text();
      throw new Error(`${res.status}: ${body}`);
    }
    return res.json();
  }

  // Health & meta
  health(): Promise<HealthResponse> { return this.request('/health'); }
  ready(): Promise<{ status: string; db: string }> { return this.request('/ready'); }
  meta(): Promise<MetaResponse> { return this.request('/v1/meta'); }

  // AID operations
  registerAid(id: string, doc: AidDocument): Promise<{ id: string; status: string }> {
    return this.request(`/v1/aid/${id}`, {
      method: 'PUT',
      body: JSON.stringify(doc),
    });
  }

  resolveAid(id: string): Promise<AidDocument> {
    return this.request(`/v1/aid/${id}`);
  }

  deactivateAid(id: string): Promise<{ id: string; status: string }> {
    return this.request(`/v1/aid/${id}`, { method: 'DELETE' });
  }

  getPublicKey(id: string): Promise<{ id: string; keys: Array<{ id: string; type: string; publicKeyMultibase: string }> }> {
    return this.request(`/v1/aid/${id}/key`);
  }

  // DAT operations
  verifyDat(req: DatVerifyRequest): Promise<DatVerifyResponse> {
    return this.request('/v1/dat/verify', {
      method: 'POST',
      body: JSON.stringify(req),
    });
  }

  revokeDat(req: RevokeRequest): Promise<{ jti: string; status: string; reason?: string }> {
    return this.request('/v1/dat/revoke', {
      method: 'POST',
      body: JSON.stringify(req),
    });
  }

  listRevocations(limit = 50, offset = 0): Promise<RevocationListResponse> {
    return this.request(`/v1/dat/revocations?limit=${limit}&offset=${offset}`);
  }

  checkRevocation(jti: string): Promise<RevocationCheckResponse> {
    return this.request(`/v1/dat/revoked/${encodeURIComponent(jti)}`);
  }
}
