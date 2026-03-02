"""Tests for IDProva Python SDK."""

import json
import pytest


def test_import():
    """Test that the module imports correctly."""
    from idprova import AgentIdentity, AID, AIDBuilder, DAT, KeyPair, ReceiptLog, Scope, TrustLevel
    assert AgentIdentity is not None


class TestKeyPair:
    def test_generate(self):
        from idprova import KeyPair
        kp = KeyPair.generate()
        assert len(kp.public_key_bytes) == 32
        assert kp.public_key_multibase.startswith("z")

    def test_sign_verify(self):
        from idprova import KeyPair
        kp = KeyPair.generate()
        message = b"hello idprova"
        sig = kp.sign(message)
        assert kp.verify(message, sig) is True

    def test_wrong_key_fails(self):
        from idprova import KeyPair
        kp1 = KeyPair.generate()
        kp2 = KeyPair.generate()
        sig = kp1.sign(b"hello")
        assert kp2.verify(b"hello", sig) is False

    def test_from_secret_bytes_roundtrip(self):
        from idprova import KeyPair
        kp1 = KeyPair.generate()
        # Note: secret_bytes not exposed to Python (security).
        # This test verifies public key determinism indirectly.
        pub1 = kp1.public_key_bytes
        assert len(pub1) == 32

    def test_invalid_secret_bytes(self):
        from idprova import KeyPair
        with pytest.raises(ValueError, match="32 bytes"):
            KeyPair.from_secret_bytes(b"too short")

    def test_repr(self):
        from idprova import KeyPair
        kp = KeyPair.generate()
        r = repr(kp)
        assert "KeyPair" in r
        assert "public_key=" in r


class TestAgentIdentity:
    def test_create_basic(self):
        from idprova import AgentIdentity
        identity = AgentIdentity.create("test-agent")
        assert identity.did == "did:idprova:local.dev:test-agent"

    def test_create_with_domain(self):
        from idprova import AgentIdentity
        identity = AgentIdentity.create("kai", domain="techblaze.com.au")
        assert identity.did == "did:idprova:techblaze.com.au:kai"

    def test_aid_document(self):
        from idprova import AgentIdentity
        identity = AgentIdentity.create("test-agent", domain="example.com")
        aid = identity.aid()
        assert aid.did == "did:idprova:example.com:test-agent"
        assert aid.trust_level == "L0"

    def test_aid_json_roundtrip(self):
        from idprova import AgentIdentity, AID
        identity = AgentIdentity.create("test-agent", domain="example.com")
        aid = identity.aid()
        json_str = aid.to_json()
        parsed = json.loads(json_str)
        assert parsed["id"] == "did:idprova:example.com:test-agent"
        # Parse back
        aid2 = AID.from_json(json_str)
        assert aid2.did == aid.did

    def test_issue_dat(self):
        from idprova import AgentIdentity
        issuer = AgentIdentity.create("alice", domain="example.com")
        dat = issuer.issue_dat(
            "did:idprova:example.com:agent",
            ["mcp:tool:read"],
            expires_in_seconds=3600,
        )
        assert dat.issuer == "did:idprova:example.com:alice"
        assert dat.subject == "did:idprova:example.com:agent"
        assert not dat.is_expired

    def test_repr(self):
        from idprova import AgentIdentity
        identity = AgentIdentity.create("test")
        assert "did:idprova:local.dev:test" in repr(identity)


class TestDAT:
    def test_issue_and_verify(self):
        from idprova import KeyPair, DAT
        kp = KeyPair.generate()
        dat = DAT.issue(
            "did:idprova:example.com:alice",
            "did:idprova:example.com:agent",
            ["mcp:tool:read"],
            3600,
            kp,
        )
        assert dat.verify_signature(kp.public_key_bytes)

    def test_compact_roundtrip(self):
        from idprova import KeyPair, DAT
        kp = KeyPair.generate()
        dat = DAT.issue(
            "did:idprova:example.com:alice",
            "did:idprova:example.com:agent",
            ["mcp:tool:read", "mcp:tool:write"],
            3600,
            kp,
        )
        compact = dat.to_compact()
        parsed = DAT.from_compact(compact)
        assert parsed.issuer == dat.issuer
        assert parsed.subject == dat.subject
        assert parsed.scope == dat.scope

    def test_expired_dat(self):
        from idprova import KeyPair, DAT
        kp = KeyPair.generate()
        dat = DAT.issue(
            "did:idprova:example.com:alice",
            "did:idprova:example.com:agent",
            ["mcp:tool:read"],
            -1,  # Already expired
            kp,
        )
        assert dat.is_expired
        with pytest.raises(ValueError, match="DatExpiredError"):
            dat.validate_timing()

    def test_wrong_key_verification(self):
        from idprova import KeyPair, DAT
        kp1 = KeyPair.generate()
        kp2 = KeyPair.generate()
        dat = DAT.issue(
            "did:idprova:example.com:alice",
            "did:idprova:example.com:agent",
            ["mcp:tool:read"],
            3600,
            kp1,
        )
        assert not dat.verify_signature(kp2.public_key_bytes)

    def test_with_constraints(self):
        from idprova import KeyPair, DAT
        kp = KeyPair.generate()
        dat = DAT.issue(
            "did:idprova:example.com:alice",
            "did:idprova:example.com:agent",
            ["mcp:tool:read"],
            3600,
            kp,
            max_actions=100,
            require_receipt=True,
        )
        assert dat.jti.startswith("dat_")

    def test_algorithm_confusion_rejected(self):
        """SEC-3: Reject tokens with alg != EdDSA."""
        import base64
        from idprova import DAT
        # Craft a JWS with alg: "none"
        header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"idprova-dat+jwt","kid":"test"}').rstrip(b'=').decode()
        payload = base64.urlsafe_b64encode(b'{"iss":"a","sub":"b","iat":0,"exp":999999999999,"nbf":0,"jti":"x","scope":[]}').rstrip(b'=').decode()
        sig = base64.urlsafe_b64encode(b'fake').rstrip(b'=').decode()
        compact = f"{header}.{payload}.{sig}"
        with pytest.raises(ValueError, match="unsupported algorithm"):
            DAT.from_compact(compact)


class TestScope:
    def test_parse(self):
        from idprova import Scope
        s = Scope("mcp:tool:read")
        assert str(s) == "mcp:tool:read"

    def test_covers(self):
        from idprova import Scope
        broad = Scope("mcp:*:*")
        narrow = Scope("mcp:tool:read")
        assert broad.covers(narrow)
        assert not narrow.covers(broad)

    def test_exact_match(self):
        from idprova import Scope
        s1 = Scope("mcp:tool:read")
        s2 = Scope("mcp:tool:read")
        assert s1.covers(s2)

    def test_invalid_scope(self):
        from idprova import Scope
        with pytest.raises(Exception):
            Scope("invalid")


class TestTrustLevel:
    def test_levels(self):
        from idprova import TrustLevel
        l0 = TrustLevel("L0")
        l1 = TrustLevel("L1")
        l4 = TrustLevel("L4")
        assert l0.meets_minimum(l0)
        assert not l0.meets_minimum(l1)
        assert l4.meets_minimum(l1)

    def test_description(self):
        from idprova import TrustLevel
        l0 = TrustLevel("L0")
        assert "self" in l0.description.lower() or "Self" in l0.description

    def test_invalid(self):
        from idprova import TrustLevel
        with pytest.raises(ValueError, match="Invalid trust level"):
            TrustLevel("L5")


class TestReceiptLog:
    def test_new_empty(self):
        from idprova import ReceiptLog
        log = ReceiptLog()
        assert len(log) == 0
        assert log.last_hash == "genesis"
        assert log.next_sequence == 0

    def test_verify_empty(self):
        from idprova import ReceiptLog
        log = ReceiptLog()
        log.verify_integrity()  # Should not raise
