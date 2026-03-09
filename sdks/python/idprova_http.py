"""IDProva HTTP client — pure Python, no Rust bindings required."""
import httpx
from typing import Optional


class IDProvaClient:
    """HTTP client for the IDProva registry."""

    def __init__(self, registry_url: str = "http://localhost:3000"):
        self.base = registry_url.rstrip("/")

    def register_aid(self, aid_doc: dict) -> dict:
        """Register an AID document. Raises ValueError on error."""
        r = httpx.post(f"{self.base}/v1/aids", json=aid_doc)
        if r.status_code not in (200, 201):
            raise ValueError(f"register_aid failed: {r.status_code} {r.text}")
        return r.json()

    def resolve_aid(self, aid_id: str) -> dict:
        """Resolve an AID by ID."""
        r = httpx.get(f"{self.base}/v1/aids/{aid_id}")
        if r.status_code != 200:
            raise ValueError(f"resolve_aid failed: {r.status_code} {r.text}")
        return r.json()

    def verify_dat(self, dat_token: str) -> dict:
        """Verify a DAT token. Returns claims if valid."""
        r = httpx.post(f"{self.base}/v1/dat/verify", json={"token": dat_token})
        if r.status_code != 200:
            raise ValueError(f"verify_dat failed: {r.status_code} {r.text}")
        return r.json()

    def revoke_dat(self, jti: str, admin_dat: str) -> dict:
        """Revoke a DAT by JTI. Requires admin DAT."""
        r = httpx.post(
            f"{self.base}/v1/dat/revoke",
            json={"jti": jti},
            headers={"Authorization": f"Bearer {admin_dat}"},
        )
        if r.status_code != 200:
            raise ValueError(f"revoke_dat failed: {r.status_code} {r.text}")
        return r.json()

    def list_aids(self, limit: int = 50, offset: int = 0) -> dict:
        """List registered AIDs."""
        r = httpx.get(f"{self.base}/v1/aids", params={"limit": limit, "offset": offset})
        if r.status_code != 200:
            raise ValueError(f"list_aids failed: {r.status_code} {r.text}")
        return r.json()
