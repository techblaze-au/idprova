"""IDProva Python SDK — Type stubs for IDE support."""

from typing import List, Optional

__version__: str

class KeyPair:
    """An Ed25519 key pair for signing and verification."""

    @staticmethod
    def generate() -> KeyPair:
        """Generate a new random Ed25519 key pair."""
        ...

    @staticmethod
    def from_secret_bytes(secret: bytes) -> KeyPair:
        """Create a key pair from secret key bytes (32 bytes)."""
        ...

    def sign(self, message: bytes) -> bytes:
        """Sign a message and return the signature as bytes."""
        ...

    def verify(self, message: bytes, signature: bytes) -> bool:
        """Verify a signature against a message."""
        ...

    @property
    def public_key_multibase(self) -> str:
        """Get the public key in multibase encoding."""
        ...

    @property
    def public_key_bytes(self) -> bytes:
        """Get the raw public key bytes (32 bytes)."""
        ...

class AID:
    """An IDProva Agent Identity Document (W3C DID Document)."""

    @property
    def did(self) -> str:
        """Get the DID identifier."""
        ...

    @property
    def controller(self) -> str:
        """Get the controller DID."""
        ...

    @property
    def trust_level(self) -> Optional[str]:
        """Get the trust level string."""
        ...

    def to_json(self) -> str:
        """Serialize to JSON string."""
        ...

    @staticmethod
    def from_json(json: str) -> AID:
        """Parse from JSON string."""
        ...

    def validate(self) -> None:
        """Validate the document structure."""
        ...

class AIDBuilder:
    """Fluent builder for creating Agent Identity Documents."""

    def __init__(self) -> None: ...
    def id(self, id: str) -> None: ...
    def controller(self, controller: str) -> None: ...
    def name(self, name: str) -> None: ...
    def description(self, desc: str) -> None: ...
    def model(self, model: str) -> None: ...
    def runtime(self, runtime: str) -> None: ...
    def trust_level(self, level: str) -> None: ...
    def add_ed25519_key(self, keypair: KeyPair) -> None: ...
    def build(self) -> AID: ...

class DAT:
    """A Delegation Attestation Token — signed, scoped permission grant."""

    @staticmethod
    def issue(
        issuer_did: str,
        subject_did: str,
        scope: List[str],
        expires_in_seconds: int,
        signing_key: KeyPair,
        max_actions: Optional[int] = None,
        require_receipt: Optional[bool] = None,
    ) -> DAT:
        """Issue a new DAT signed by the issuer's key pair."""
        ...

    def to_compact(self) -> str:
        """Serialize to compact JWS format (header.payload.signature)."""
        ...

    @staticmethod
    def from_compact(compact: str) -> DAT:
        """Parse from compact JWS string."""
        ...

    def verify_signature(self, public_key_bytes: bytes) -> bool:
        """Verify the DAT signature against a public key."""
        ...

    def validate_timing(self) -> None:
        """Validate timing constraints (not expired, not before valid)."""
        ...

    @property
    def is_expired(self) -> bool:
        """Check if the DAT is expired."""
        ...

    @property
    def issuer(self) -> str:
        """Get the issuer DID."""
        ...

    @property
    def subject(self) -> str:
        """Get the subject DID."""
        ...

    @property
    def jti(self) -> str:
        """Get the token ID."""
        ...

    @property
    def scope(self) -> List[str]:
        """Get the granted scopes."""
        ...

    @property
    def expires_at(self) -> int:
        """Get the expiration timestamp (Unix seconds)."""
        ...

class Scope:
    """A permission scope in namespace:resource:action format."""

    def __init__(self, scope_str: str) -> None: ...
    def covers(self, requested: Scope) -> bool:
        """Check if this scope covers the requested scope."""
        ...

class TrustLevel:
    """Trust level for an agent identity (L0 through L4)."""

    def __init__(self, level: str) -> None: ...
    def meets_minimum(self, required: TrustLevel) -> bool:
        """Check if this trust level meets the required minimum."""
        ...

    @property
    def description(self) -> str:
        """Get a human-readable description."""
        ...

class ReceiptLog:
    """An append-only, hash-chained audit receipt log."""

    def __init__(self) -> None: ...
    def verify_integrity(self) -> None:
        """Verify the integrity of the entire receipt chain."""
        ...

    @property
    def last_hash(self) -> str:
        """Get the hash of the last receipt."""
        ...

    @property
    def next_sequence(self) -> int:
        """Get the next sequence number."""
        ...

    def to_json(self) -> str:
        """Serialize the log to JSON string."""
        ...

    def __len__(self) -> int: ...

class AgentIdentity:
    """High-level convenience class for creating agent identities."""

    did: str

    @staticmethod
    def create(
        name: str,
        domain: str = "local.dev",
        controller: Optional[str] = None,
    ) -> AgentIdentity:
        """Create a new agent identity with a generated key pair."""
        ...

    def aid(self) -> AID:
        """Get the AID document."""
        ...

    def keypair(self) -> KeyPair:
        """Get the key pair."""
        ...

    def issue_dat(
        self,
        subject_did: str,
        scope: List[str],
        expires_in_seconds: int = 3600,
    ) -> DAT:
        """Issue a delegation token to another agent."""
        ...

    @property
    def public_key_bytes(self) -> bytes:
        """Get the public key bytes."""
        ...
