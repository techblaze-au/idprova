#!/usr/bin/env python3
"""
Generate branded PDF for NCCoE Feedback Submission.
Tech Blaze Consulting — IDProva Protocol.

Usage: python generate-nccoe-pdf.py
Output: NCCoE-Feedback-TechBlaze.pdf
"""

import os
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm, cm
from reportlab.lib.colors import HexColor, white, black
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, Image, KeepTogether, HRFlowable
)
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

# ── Brand Colors ──
NAVY = HexColor("#1E3A5F")
BLUE = HexColor("#2563EB")
GREEN = HexColor("#10B981")
LIGHT_GRAY = HexColor("#F1F5F9")
MED_GRAY = HexColor("#94A3B8")
DARK_TEXT = HexColor("#0F172A")
BODY_TEXT = HexColor("#1E293B")
WHITE = white

# ── Paths ──
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_PDF = os.path.join(SCRIPT_DIR, "NCCoE-Feedback-TechBlaze.pdf")
LOGO_PATH = r"C:\Users\praty\OneDrive\Documents\Biz docs\Techblaze logo.png"

# ── Page Setup ──
PAGE_W, PAGE_H = A4
LEFT_MARGIN = 20 * mm
RIGHT_MARGIN = 20 * mm
TOP_MARGIN = 25 * mm
BOTTOM_MARGIN = 20 * mm


def get_styles():
    """Define all paragraph styles."""
    styles = {}

    styles["title"] = ParagraphStyle(
        "Title",
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=26,
        textColor=NAVY,
        spaceAfter=6,
        alignment=TA_LEFT,
    )
    styles["subtitle"] = ParagraphStyle(
        "Subtitle",
        fontName="Helvetica",
        fontSize=11,
        leading=15,
        textColor=MED_GRAY,
        spaceAfter=4,
        alignment=TA_LEFT,
    )
    styles["h1"] = ParagraphStyle(
        "H1",
        fontName="Helvetica-Bold",
        fontSize=15,
        leading=20,
        textColor=NAVY,
        spaceBefore=18,
        spaceAfter=8,
        alignment=TA_LEFT,
    )
    styles["h2"] = ParagraphStyle(
        "H2",
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=16,
        textColor=BLUE,
        spaceBefore=12,
        spaceAfter=6,
        alignment=TA_LEFT,
    )
    styles["body"] = ParagraphStyle(
        "Body",
        fontName="Helvetica",
        fontSize=9.5,
        leading=13.5,
        textColor=BODY_TEXT,
        spaceAfter=6,
        alignment=TA_JUSTIFY,
    )
    styles["body_bold"] = ParagraphStyle(
        "BodyBold",
        fontName="Helvetica-Bold",
        fontSize=9.5,
        leading=13.5,
        textColor=BODY_TEXT,
        spaceAfter=6,
        alignment=TA_JUSTIFY,
    )
    styles["bullet"] = ParagraphStyle(
        "Bullet",
        fontName="Helvetica",
        fontSize=9.5,
        leading=13.5,
        textColor=BODY_TEXT,
        spaceAfter=3,
        leftIndent=15,
        bulletIndent=5,
        alignment=TA_LEFT,
    )
    styles["code"] = ParagraphStyle(
        "Code",
        fontName="Courier",
        fontSize=8,
        leading=11,
        textColor=DARK_TEXT,
        backColor=LIGHT_GRAY,
        spaceAfter=6,
        leftIndent=10,
        rightIndent=10,
        borderPadding=(4, 6, 4, 6),
    )
    styles["note"] = ParagraphStyle(
        "Note",
        fontName="Helvetica-Oblique",
        fontSize=9,
        leading=12.5,
        textColor=MED_GRAY,
        spaceAfter=6,
        leftIndent=10,
        borderPadding=(4, 6, 4, 6),
    )
    styles["footer"] = ParagraphStyle(
        "Footer",
        fontName="Helvetica",
        fontSize=7.5,
        leading=10,
        textColor=MED_GRAY,
        alignment=TA_CENTER,
    )
    styles["table_header"] = ParagraphStyle(
        "TableHeader",
        fontName="Helvetica-Bold",
        fontSize=8.5,
        leading=11,
        textColor=WHITE,
        alignment=TA_LEFT,
    )
    styles["table_cell"] = ParagraphStyle(
        "TableCell",
        fontName="Helvetica",
        fontSize=8.5,
        leading=11,
        textColor=BODY_TEXT,
        alignment=TA_LEFT,
    )
    return styles


def make_table(headers, rows, col_widths=None, styles=None):
    """Create a branded table."""
    s = styles or get_styles()
    data = [[Paragraph(h, s["table_header"]) for h in headers]]
    for row in rows:
        data.append([Paragraph(str(c), s["table_cell"]) for c in row])

    avail_w = PAGE_W - LEFT_MARGIN - RIGHT_MARGIN
    if col_widths is None:
        col_widths = [avail_w / len(headers)] * len(headers)

    t = Table(data, colWidths=col_widths, repeatRows=1)
    style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 8.5),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 6),
        ("TOPPADDING", (0, 0), (-1, 0), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.5, MED_GRAY),
    ]
    # Alternating row colors
    for i in range(1, len(data)):
        if i % 2 == 0:
            style_cmds.append(("BACKGROUND", (0, i), (-1, i), LIGHT_GRAY))
    style_cmds.append(("TOPPADDING", (0, 1), (-1, -1), 4))
    style_cmds.append(("BOTTOMPADDING", (0, 1), (-1, -1), 4))

    t.setStyle(TableStyle(style_cmds))
    return t


def header_footer(canvas, doc):
    """Draw header bar and footer on every page."""
    canvas.saveState()

    # Top navy bar
    canvas.setFillColor(NAVY)
    canvas.rect(0, PAGE_H - 8 * mm, PAGE_W, 8 * mm, fill=1, stroke=0)

    # Footer line
    canvas.setStrokeColor(MED_GRAY)
    canvas.setLineWidth(0.5)
    canvas.line(LEFT_MARGIN, BOTTOM_MARGIN - 2 * mm,
                PAGE_W - RIGHT_MARGIN, BOTTOM_MARGIN - 2 * mm)

    # Footer text
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(MED_GRAY)
    canvas.drawString(LEFT_MARGIN, BOTTOM_MARGIN - 8 * mm,
                      "Tech Blaze Consulting Pty Ltd  |  techblaze.com.au  |  Canberra, ACT, Australia")
    canvas.drawRightString(PAGE_W - RIGHT_MARGIN, BOTTOM_MARGIN - 8 * mm,
                           f"Page {doc.page}")

    canvas.restoreState()


def first_page(canvas, doc):
    """Title page header with logo."""
    canvas.saveState()

    # Top navy bar (thicker for title page)
    canvas.setFillColor(NAVY)
    canvas.rect(0, PAGE_H - 12 * mm, PAGE_W, 12 * mm, fill=1, stroke=0)

    # Logo
    if os.path.exists(LOGO_PATH):
        try:
            canvas.drawImage(LOGO_PATH, LEFT_MARGIN, PAGE_H - 45 * mm,
                             width=65 * mm, height=22 * mm,
                             preserveAspectRatio=True, mask="auto")
        except Exception:
            pass  # Skip if image fails

    # Footer
    canvas.setStrokeColor(MED_GRAY)
    canvas.setLineWidth(0.5)
    canvas.line(LEFT_MARGIN, BOTTOM_MARGIN - 2 * mm,
                PAGE_W - RIGHT_MARGIN, BOTTOM_MARGIN - 2 * mm)
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(MED_GRAY)
    canvas.drawString(LEFT_MARGIN, BOTTOM_MARGIN - 8 * mm,
                      "Tech Blaze Consulting Pty Ltd  |  techblaze.com.au  |  Canberra, ACT, Australia")
    canvas.drawRightString(PAGE_W - RIGHT_MARGIN, BOTTOM_MARGIN - 8 * mm,
                           f"Page {doc.page}")

    canvas.restoreState()


def hr():
    """Horizontal rule."""
    return HRFlowable(
        width="100%", thickness=0.5, color=MED_GRAY,
        spaceBefore=8, spaceAfter=8
    )


def build_content(s):
    """Build all PDF content as a list of flowables."""
    story = []
    avail_w = PAGE_W - LEFT_MARGIN - RIGHT_MARGIN

    # ── Title Page ──
    story.append(Spacer(1, 38 * mm))  # Space for logo

    story.append(Paragraph(
        "Response to NCCoE Concept Paper",
        s["title"]
    ))
    story.append(Paragraph(
        "Software and AI Agent Identity and Authorization",
        ParagraphStyle("TitleSub", parent=s["title"], fontSize=14, leading=18, textColor=BLUE)
    ))
    story.append(Spacer(1, 6 * mm))
    story.append(Paragraph(
        "Submitted to: AI-Identity@nist.gov",
        s["subtitle"]
    ))
    story.append(Paragraph(
        "Reference: NCCoE Concept Paper (Published February 5, 2026)",
        s["subtitle"]
    ))
    story.append(Paragraph(
        "Prior Engagement: NIST-2025-0035 (Collaborative AI Security Initiative RFI)",
        s["subtitle"]
    ))
    story.append(Paragraph(
        "Date: March 2026  |  Deadline: April 2, 2026",
        s["subtitle"]
    ))
    story.append(Spacer(1, 8 * mm))

    # Green accent bar
    story.append(HRFlowable(width="40%", thickness=2, color=GREEN, spaceBefore=0, spaceAfter=6))

    story.append(Paragraph(
        "<b>Prepared by:</b> Pratyush Sood, Principal Consultant",
        s["body"]
    ))
    story.append(Paragraph(
        "<b>Organisation:</b> Tech Blaze Consulting Pty Ltd, Canberra, ACT, Australia",
        s["body"]
    ))
    story.append(Paragraph(
        "<b>Certifications:</b> CISM, CISA, IRAP, TOGAF, Azure Solutions Architect Expert",
        s["body"]
    ))
    story.append(Paragraph(
        "<b>Protocol:</b> IDProva — Open protocol for AI agent identity (Apache 2.0)",
        s["body"]
    ))
    story.append(Paragraph(
        "<b>Website:</b> https://idprova.dev",
        s["body"]
    ))

    story.append(PageBreak())

    # ── Section 1: Executive Summary ──
    story.append(Paragraph("1. Executive Summary", s["h1"]))
    story.append(hr())

    story.append(Paragraph(
        "<b>Tech Blaze Consulting Pty Ltd</b> is an Australian cybersecurity consultancy based in "
        "Canberra, ACT. The principal consultant holds CISM (ISACA), CISA (ISACA), IRAP (Australian "
        "Cyber Security Centre), TOGAF Enterprise Architecture Practitioner (The Open Group), and "
        "Microsoft Azure Solutions Architect Expert certifications, with over 20 years of experience "
        "in IT security assessment, compliance, and enterprise architecture.",
        s["body"]
    ))
    story.append(Paragraph(
        "<b>IDProva</b> is an open protocol for verifiable AI agent identity, licensed under Apache 2.0 "
        "and launching April 7, 2026. IDProva provides three protocol primitives — Agent Identity "
        "Documents (AIDs), Delegation Attestation Tokens (DATs), and Action Receipts — that collectively "
        "address the agent identity, authorization, auditing, and credential lifecycle challenges "
        "described in the NCCoE concept paper.",
        s["body"]
    ))
    story.append(Paragraph(
        "This response demonstrates how IDProva addresses all six NCCoE focus areas:",
        s["body"]
    ))

    story.append(make_table(
        ["NCCoE Focus Area", "IDProva Coverage", "Primary Primitive"],
        [
            ["Agent Identification", "Full", "W3C DIDs (AIDs), metadata, configAttestation"],
            ["Authorization &amp; Scoping", "Full", "DATs, scope narrowing, constraints, revocation"],
            ["Auditing &amp; Non-Repudiation", "Full", "Hash-chained Action Receipts, delegation correlation"],
            ["Prompt Injection Mitigation", "Partial — active development", "Config attestation / drift detection"],
            ["Credential Management", "Full", "Short-lived DATs, cascading revocation, key rotation"],
            ["Multi-System Authorization", "Full", "Protocol bindings (MCP, A2A, HTTP) outside LLM"],
        ],
        col_widths=[avail_w * 0.28, avail_w * 0.22, avail_w * 0.50],
        styles=s,
    ))
    story.append(Spacer(1, 4))
    story.append(Paragraph(
        "Tech Blaze Consulting offers IDProva for independent NCCoE evaluation and expresses interest "
        "in participating in the demonstration project as a technology contributor and subject matter expert.",
        s["body"]
    ))

    # ── Section 2: Use Cases ──
    story.append(Paragraph("2. Use Cases", s["h1"]))
    story.append(hr())

    use_cases = [
        ("<b>Enterprise agent delegation chains</b> — A human principal authorises an orchestrator agent, "
         "which delegates subsets of authority to worker agents. Each delegation is cryptographically "
         "scoped and auditable. The scope narrowing rule prevents privilege escalation at every link."),
        ("<b>MCP tool call authorization for sensitive resources</b> — An MCP server validates a DAT "
         "before executing any tool call (filesystem read/write, database query, API invocation). "
         "Authorization is enforced at the protocol binding layer, outside the LLM reasoning boundary."),
        ("<b>Multi-agent compliance audit for regulated environments</b> — Hash-chained Action Receipts "
         "provide a tamper-evident audit trail mapping directly to NIST 800-53 (AU-2 through AU-12), "
         "Australian ISM, and SOC 2 Trust Services Criteria."),
        ("<b>Agent identity lifecycle in CI/CD pipelines</b> — Agents deployed in CI/CD workflows receive "
         "time-bounded DATs (24 hours maximum for L0–L1 agents). DATs expire automatically, eliminating "
         "stale credentials. Key rotation and AID deactivation are first-class operations."),
        ("<b>Cross-organisational agent delegation</b> — When agents from different organisations interact, "
         "both resolve each other's DID Documents, verify trust levels, and apply independent trust policies. "
         "The interaction proceeds at the lower of the two trust levels."),
    ]
    for uc in use_cases:
        story.append(Paragraph(uc, s["body"]))

    # ── Section 3: Agent Identification ──
    story.append(Paragraph("3. Agent Identification", s["h1"]))
    story.append(hr())

    story.append(Paragraph("DID-Based Agent Identity", s["h2"]))
    story.append(Paragraph(
        "IDProva agents are identified by W3C Decentralized Identifiers using the did:aid: method:",
        s["body"]
    ))
    story.append(Paragraph("did:aid:&lt;authority&gt;:&lt;agent-name&gt;", s["code"]))
    story.append(Paragraph(
        "The <b>authority</b> is the namespace owner — for domain-verified agents (L1+), the controller "
        "proves domain ownership via DNS TXT records. The <b>agent-name</b> is locally unique within the authority.",
        s["body"]
    ))

    story.append(Paragraph("Agent Metadata", s["h2"]))
    story.append(make_table(
        ["Field", "Description"],
        [
            ["name", "Human-readable agent name"],
            ["model", "AI model identifier (e.g., anthropic/claude-opus-4)"],
            ["runtime", "Runtime platform (e.g., openclaw/v2.1)"],
            ["configAttestation", "BLAKE3 hash of agent configuration"],
            ["trustLevel", "Current trust level: L0 (Unverified) through L4 (Continuously Monitored)"],
            ["capabilities", "Declared capability strings (e.g., mcp:tool-call, idprova:delegate)"],
            ["maxDelegationDepth", "Maximum delegation chain depth"],
        ],
        col_widths=[avail_w * 0.25, avail_w * 0.75],
        styles=s,
    ))

    story.append(Paragraph("Configuration Drift Detection", s["h2"]))
    story.append(Paragraph(
        "The configAttestation field contains a BLAKE3 hash of the agent's active configuration — system "
        "prompt, tool definitions, model identifier, and runtime parameters. If any component changes, the "
        "hash changes, and verifiers can detect drift and make trust decisions accordingly.",
        s["body"]
    ))

    story.append(Paragraph("Resolution", s["h2"]))
    story.append(Paragraph("DID Document resolution follows a layered strategy:", s["body"]))
    for item in [
        "1. Local cache (respecting TTL)",
        "2. Well-known endpoint: https://{authority}/.well-known/did/idprova/{agent-name}/did.json",
        "3. Registry lookup: GET /v1/identities/{did}",
        "4. Universal resolver (fallback)",
    ]:
        story.append(Paragraph(item, s["bullet"]))

    story.append(Paragraph("Distinct from Human Users", s["h2"]))
    story.append(Paragraph(
        "Agent DIDs are structurally distinct from human user identifiers. The did:aid: method is "
        "agent-specific — it carries agent metadata (model, runtime, config attestation, trust level) that "
        "has no analogue in human identity systems. Agents are not users with API keys; they are autonomous "
        "entities requiring purpose-built identity semantics.",
        s["body"]
    ))

    # ── Section 4: Authorization & Scoped Delegation ──
    story.append(Paragraph("4. Authorization &amp; Scoped Delegation", s["h1"]))
    story.append(hr())

    story.append(Paragraph(
        "Delegation Attestation Tokens (DATs) are JWS-encoded tokens (RFC 7515) that grant scoped authority "
        'from one DID to another. They answer: "What is this agent authorised to do, and who authorised it?"',
        s["body"]
    ))

    story.append(Paragraph("Scope Grammar", s["h2"]))
    story.append(Paragraph("scope = namespace : resource : action", s["code"]))
    story.append(Paragraph("Examples:", s["body"]))
    for ex in [
        "mcp:tool:filesystem:read — Read via filesystem MCP tool",
        "mcp:tool:database:write — Write via database MCP tool",
        "a2a:agent:*:communicate — Communicate with any A2A agent",
        "idprova:delegate — Issue sub-delegations",
    ]:
        story.append(Paragraph(f"• {ex}", s["bullet"]))

    story.append(Paragraph("Scope Narrowing Rule", s["h2"]))
    story.append(Paragraph(
        "Each child delegation MUST be a subset of its parent scope. This is enforced structurally — "
        "Agent B cannot grant Agent C permissions that exceed Agent B's own authority. This prevents "
        "privilege escalation at every delegation step.",
        s["body"]
    ))

    story.append(Paragraph("Constraints", s["h2"]))
    story.append(make_table(
        ["Constraint", "Description"],
        [
            ["maxActions", "Maximum actions per token lifetime"],
            ["rateLimit", "Actions per time window"],
            ["ipRange", "Restrict to specific IP/CIDR ranges"],
            ["geoRestriction", "Limit to specific jurisdictions"],
            ["maxRedelegationDepth", "Maximum further delegation depth"],
            ["requiredConfigAttestation", "Reject if agent config hash drifts"],
        ],
        col_widths=[avail_w * 0.30, avail_w * 0.70],
        styles=s,
    ))
    story.append(Paragraph(
        "Constraints inherit and narrow through delegation chains — a child cannot weaken a parent's constraint.",
        s["body"]
    ))

    story.append(Paragraph("Revocation", s["h2"]))
    story.append(Paragraph(
        "DATs can be revoked before expiry. Revocation cascades: when a parent DAT is revoked, all child DATs "
        "in the delegation chain become invalid. Verifiers check revocation status for every DAT in the chain. "
        "Real-time status checks via GET /v1/delegations/{jti}/status.",
        s["body"]
    ))

    # ── Section 5: Auditing & Non-Repudiation ──
    story.append(Paragraph("5. Auditing &amp; Non-Repudiation", s["h1"]))
    story.append(hr())

    story.append(Paragraph("Hash-Chained Action Receipts", s["h2"]))
    story.append(Paragraph(
        "Every agent action produces a signed Action Receipt — a tamper-evident audit record. Receipts form "
        "a hash chain using BLAKE3. Each receipt is signed by the agent's private Ed25519 key (with optional "
        "ML-DSA-65 co-signature). The corresponding public key is published in the agent's AID Document.",
        s["body"]
    ))

    story.append(Paragraph("Receipt Content", s["h2"]))
    for item in [
        "<b>Who</b> — agent (DID), delegation (DAT jti → issuer → human principal)",
        "<b>What</b> — action.type (structured taxonomy), action.target, action.parameters",
        "<b>When</b> — timestamp (ISO 8601, millisecond precision, UTC, in signed payload)",
        "<b>Where</b> — context.environment, context.sessionId",
        "<b>Outcome</b> — action.result.status (success, failure, error)",
    ]:
        story.append(Paragraph(f"• {item}", s["bullet"]))

    story.append(Paragraph("Delegation Correlation", s["h2"]))
    story.append(Paragraph(
        "The delegation field in each receipt references the DAT jti that authorised the action. Walking "
        "the delegation chain traces authority from any action back to the authorising human principal — "
        "complete attribution from action to identity to authority.",
        s["body"]
    ))

    story.append(Paragraph("Tamper Evidence", s["h2"]))
    for item in [
        "chain.previousHash — cryptographic link to prior receipt (BLAKE3)",
        "chain.sequenceNumber — detects insertions and deletions",
        "signature — Ed25519 (+ optional ML-DSA-65) over the entire receipt payload",
    ]:
        story.append(Paragraph(f"• {item}", s["bullet"]))

    story.append(Paragraph("Compliance Control Mapping — NIST 800-53 Rev. 5", s["h2"]))
    story.append(make_table(
        ["Control", "Description", "Receipt Evidence"],
        [
            ["AU-2", "Auditable Events", "action.type taxonomy — every action produces a receipt"],
            ["AU-3", "Content of Audit Records", "Who, what, when, where, outcome in every receipt"],
            ["AU-8", "Time Stamps", "ISO 8601 UTC with milliseconds in signed payload"],
            ["AU-9", "Protection of Audit Information", "Hash chain + Ed25519 signatures"],
            ["AU-10", "Non-repudiation", "Per-receipt Ed25519 signature + delegation chain"],
            ["AU-12", "Audit Record Generation", "Protocol-native, requireReceipt constraint in DATs"],
            ["IA-2", "Identification &amp; Authentication", "DID-based identity in every receipt"],
            ["AC-6", "Least Privilege", "Delegation scope + constraints"],
        ],
        col_widths=[avail_w * 0.10, avail_w * 0.28, avail_w * 0.62],
        styles=s,
    ))
    story.append(Spacer(1, 4))
    story.append(Paragraph(
        "<b>Australian ISM:</b> ISM-0585 (process identification), ISM-0988 (privileged action logging), "
        "ISM-0580 (audit log integrity), ISM-1405 (centralised event logging)",
        s["body"]
    ))
    story.append(Paragraph(
        "<b>SOC 2:</b> CC6.1 (logical access security), CC6.2 (authorised access scope), "
        "CC6.3 (audit trail integrity), CC7.2 (system operation monitoring)",
        s["body"]
    ))

    # ── Section 6: Prompt Injection Mitigation ──
    story.append(Paragraph("6. Prompt Injection Mitigation", s["h1"]))
    story.append(hr())

    story.append(Paragraph(
        "IDProva addresses prompt injection from the identity and attestation layer — specifically, "
        "detecting when an agent's configuration has been tampered with.",
        s["body"]
    ))

    story.append(Paragraph("Configuration Attestation", s["h2"]))
    story.append(Paragraph(
        "The configAttestation field in AID Documents stores a BLAKE3 hash of the agent's configuration "
        "at deployment time (system prompt, tool definitions, model identifier, runtime parameters).",
        s["body"]
    ))

    story.append(Paragraph("DAT-Level Enforcement", s["h2"]))
    for item in [
        "If the agent's current config hash does not match the attestation in the DAT, validation fails.",
        "The MCP server rejects the request with idprova:config-mismatch.",
        "This detects prompt injection attacks that modify the agent's system prompt or tool definitions.",
    ]:
        story.append(Paragraph(f"• {item}", s["bullet"]))

    story.append(Paragraph("Trust Level Demotion", s["h2"]))
    story.append(Paragraph(
        "Agents operating at L4 (Continuously Monitored) can be automatically demoted to a lower trust level "
        "if monitoring detects policy violations — including configuration drift that may indicate injection.",
        s["body"]
    ))

    story.append(Paragraph("Current Scope &amp; Roadmap", s["h2"]))
    story.append(Paragraph(
        "<b>What IDProva does:</b> Detects when an agent's configuration has drifted from its attested baseline. "
        "Rejects DATs when config attestation mismatches. Provides trust demotion on policy violations.",
        s["body"]
    ))
    story.append(Paragraph(
        "<b>What IDProva does not yet do:</b> Runtime input filtering, output sanitization, or LLM-layer "
        "defenses against adversarial prompts injected via user input or tool results.",
        s["body"]
    ))
    story.append(Paragraph(
        "The team is actively working to extend prompt injection coverage, including tighter integration "
        "between config attestation and runtime monitoring, and exploring partnerships with LLM-layer "
        "defense providers to deliver a more comprehensive solution.",
        s["body_bold"]
    ))

    # ── Section 7: Credential Lifecycle Management ──
    story.append(Paragraph("7. Credential Lifecycle Management", s["h1"]))
    story.append(hr())

    story.append(Paragraph("Short-Lived Delegation Tokens", s["h2"]))
    story.append(make_table(
        ["Trust Level", "Maximum DAT Lifetime"],
        [
            ["L0 (Unverified)", "24 hours"],
            ["L1 (Domain-Verified)", "24 hours"],
            ["L2 (Org-Verified)", "7 days"],
            ["L3 (Third-Party Attested)", "7 days"],
            ["L4 (Continuously Monitored)", "7 days"],
        ],
        col_widths=[avail_w * 0.40, avail_w * 0.60],
        styles=s,
    ))
    story.append(Paragraph(
        "DATs expire automatically — no manual revocation needed for time-bounded tokens.",
        s["body"]
    ))

    story.append(Paragraph("Revocation", s["h2"]))
    for item in [
        "Per-token revocation via POST /v1/delegations/{jti}/revoke",
        "Cascading revocation: parent DAT revoked → all child DATs in the chain become invalid",
        "AID deactivation: deactivating an agent's AID invalidates all DATs where that agent is the subject",
    ]:
        story.append(Paragraph(f"• {item}", s["bullet"]))

    story.append(Paragraph("Key Rotation", s["h2"]))
    story.append(make_table(
        ["Algorithm", "Rotation Period", "Mechanism"],
        [
            ["Ed25519", "Every 90 days", "DID Document update — add new key, transition, remove old key"],
            ["ML-DSA-65", "Every 180 days", "Same mechanism — old and new keys coexist during transition"],
            ["Emergency", "Immediate", "Upon suspected compromise — immediate key revocation"],
        ],
        col_widths=[avail_w * 0.18, avail_w * 0.18, avail_w * 0.64],
        styles=s,
    ))

    story.append(Paragraph("Key Storage Hierarchy", s["h2"]))
    for i, item in enumerate([
        "HSM — FIPS 140-2 Level 2+ certified hardware security modules",
        "TPM — Trusted Platform Module for device-bound agents",
        "OS Keychain — macOS Keychain, Windows DPAPI, Linux Secret Service",
        "Encrypted File — AES-256-GCM with Argon2id key derivation",
    ], 1):
        story.append(Paragraph(f"{i}. {item}", s["bullet"]))

    # ── Section 8: Multi-System Authorization Enforcement ──
    story.append(Paragraph("8. Multi-System Authorization Enforcement", s["h1"]))
    story.append(hr())

    story.append(Paragraph(
        "IDProva's protocol bindings enforce authorization outside the LLM reasoning boundary. The LLM "
        "never decides whether an action is authorized — cryptographic verification at the binding layer "
        "makes that determination before the action executes.",
        s["body"]
    ))

    story.append(Paragraph("MCP Binding", s["h2"]))
    for i, item in enumerate([
        "Agent presents DAT in the initialize request",
        "Server decodes the JWS, verifies signature(s), resolves the issuer's DID Document",
        "Server verifies the delegation chain (signature + scope narrowing at each step)",
        "Server extracts effective scopes and constraints",
        "On each tools/call, server checks the required scope against the DAT",
        "If receiptRequested is true, server generates an Action Receipt",
    ], 1):
        story.append(Paragraph(f"{i}. {item}", s["bullet"]))
    story.append(Paragraph(
        "The LLM cannot bypass this — scope validation is cryptographic (JWS signature verification), not prompt-based.",
        s["body_bold"]
    ))

    story.append(Paragraph("A2A Binding", s["h2"]))
    story.append(Paragraph(
        "For agent-to-agent communication, the sending agent includes its DAT in the task metadata. "
        "The receiving agent validates the DAT and checks the appropriate scope before proceeding.",
        s["body"]
    ))

    story.append(Paragraph("HTTP Binding", s["h2"]))
    story.append(Paragraph(
        "For direct HTTP interactions, the DAT is carried in the Authorization header. The HTTP endpoint "
        "validates the DAT before processing the request. IDProva-specific error codes provide clear "
        "rejection reasons (invalid-dat, insufficient-scope, constraint-violation, delegation-revoked).",
        s["body"]
    ))

    story.append(Paragraph("Why This Matters", s["h2"]))
    for item in [
        "<b>Cryptographic</b> — JWS signature verification, not LLM reasoning",
        "<b>External</b> — Validated at the transport/binding layer, not inside the agent",
        "<b>Auditable</b> — Every authorized action can produce a signed receipt",
        "<b>Non-bypassable</b> — The agent's LLM cannot override a failed DAT validation",
    ]:
        story.append(Paragraph(f"• {item}", s["bullet"]))

    # ── Section 9: Standards & Interoperability ──
    story.append(Paragraph("9. Standards &amp; Interoperability", s["h1"]))
    story.append(hr())

    story.append(make_table(
        ["Standard", "Usage in IDProva"],
        [
            ["W3C DIDs", "Agent identity (AID Documents)"],
            ["JWS (RFC 7515)", "DAT encoding and signature"],
            ["FIPS 186-5", "Ed25519 signatures (classical)"],
            ["FIPS 204", "ML-DSA-65 signatures (post-quantum)"],
            ["BLAKE3", "Receipt hash chains, config attestation"],
            ["RFC 8785 (JCS)", "Canonical serialization for hash input"],
        ],
        col_widths=[avail_w * 0.25, avail_w * 0.75],
        styles=s,
    ))

    story.append(Paragraph("Relationship to Existing Systems", s["h2"]))
    story.append(Paragraph(
        "<b>Complementary to OAuth 2.0/OIDC</b> — IDProva is not a replacement for OAuth. OAuth handles "
        "human-to-service authorization. IDProva adds agent-specific semantics: delegation chains, scope "
        "narrowing, config attestation, trust levels, and hash-chained audit.",
        s["body"]
    ))
    story.append(Paragraph(
        "<b>Complementary to SPIFFE/SPIRE</b> — SPIFFE provides workload identity in infrastructure. "
        "IDProva adds delegation chains, scoped permissions, and tamper-evident audit trails.",
        s["body"]
    ))
    story.append(Paragraph(
        "<b>MCP-native</b> — IDProva includes a full MCP protocol binding specification. DATs are validated "
        "at the MCP server before tool execution. Receipts are returned in MCP responses.",
        s["body"]
    ))

    story.append(Paragraph("Post-Quantum Ready", s["h2"]))
    story.append(Paragraph(
        "IDProva uses a hybrid Ed25519 + ML-DSA-65 signature scheme from day one. An attacker must break "
        "both algorithms to forge a signature.",
        s["body"]
    ))
    story.append(make_table(
        ["Phase", "Timeline", "Action"],
        [
            ["Phase 0 (Current)", "2026", "Hybrid Ed25519 + ML-DSA-65; classical-only fallback permitted"],
            ["Phase 1", "2027", "Classical-only mode deprecated (advisory)"],
            ["Phase 2", "2028", "Classical-only mode deprecated (warning)"],
            ["Phase 3", "2029+", "Evaluate ML-DSA-87 as default PQC algorithm"],
        ],
        col_widths=[avail_w * 0.22, avail_w * 0.12, avail_w * 0.66],
        styles=s,
    ))

    # ── Section 10: Technology Collaboration Interest ──
    story.append(Paragraph("10. Technology Collaboration Interest", s["h1"]))
    story.append(hr())

    story.append(Paragraph(
        "Tech Blaze Consulting offers IDProva for independent NCCoE evaluation and expresses interest "
        "in contributing to the demonstration project through the following mechanisms.",
        s["body"]
    ))

    story.append(Paragraph("Open Source Technology Contribution", s["h2"]))
    story.append(Paragraph(
        "IDProva is licensed under Apache 2.0 — NCCoE can freely evaluate, integrate, and demonstrate "
        "the protocol without licensing agreements.",
        s["body"]
    ))
    story.append(make_table(
        ["Component", "Description", "Status"],
        [
            ["Rust SDK", "Reference implementation (idprova-core crate)", "33 tests passing"],
            ["Python SDK", "PyO3 bindings (pip install idprova)", "Built from Rust core"],
            ["TypeScript SDK", "napi-rs bindings (@idprova/core)", "Built from Rust core"],
            ["CLI Tool", "9 commands covering full agent lifecycle", "Ready for integration"],
            ["Self-Hosted Registry", "Docker image for AID registration and DAT management", "Final testing"],
        ],
        col_widths=[avail_w * 0.20, avail_w * 0.50, avail_w * 0.30],
        styles=s,
    ))

    story.append(Paragraph("Community of Interest Participation", s["h2"]))
    story.append(Paragraph(
        "Tech Blaze Consulting requests membership in the NCCoE Community of Interest (CoI) for this project. "
        "As an international technology contributor, we can provide:",
        s["body"]
    ))
    for item in [
        "Protocol author perspective — deep understanding of design decisions, trade-offs, and edge cases",
        "Multi-framework compliance mapping — existing mappings to NIST 800-53, Australian ISM, and SOC 2",
        "Cross-jurisdictional insight — experience with both US (NIST) and Australian (ISM/ACSC) frameworks",
    ]:
        story.append(Paragraph(f"• {item}", s["bullet"]))

    story.append(Paragraph("Subject Matter Expert Availability", s["h2"]))
    story.append(Paragraph(
        "The principal consultant is available for consulting engagements, presentations, or technical "
        "workshops with the NCCoE team. Areas of expertise:",
        s["body"]
    ))
    for item in [
        "AI agent identity protocol design and cryptographic architecture",
        "Compliance assessment methodology for autonomous AI systems (CISM, CISA, IRAP, TOGAF)",
        "Enterprise architecture for agent delegation and authorization (Azure Solutions Architect Expert)",
        "Multi-framework security control mapping (NIST 800-53, ISM, SOC 2)",
    ]:
        story.append(Paragraph(f"• {item}", s["bullet"]))

    story.append(Paragraph("CAISI Listening Sessions", s["h2"]))
    story.append(Paragraph(
        "Tech Blaze Consulting will request attendance at the April 2026 CAISI Listening Sessions "
        "(via caisi-events@nist.gov by March 20) and is available to present IDProva's approach to "
        "the six NCCoE focus areas.",
        s["body"]
    ))

    story.append(Spacer(1, 10 * mm))
    story.append(HRFlowable(width="100%", thickness=1.5, color=NAVY, spaceBefore=6, spaceAfter=8))

    story.append(Paragraph("Contact", s["h2"]))
    story.append(Paragraph(
        "<b>Pratyush Sood</b><br/>"
        "Principal Consultant — CISM, CISA, IRAP, TOGAF, Azure Solutions Architect<br/>"
        "Tech Blaze Consulting Pty Ltd<br/>"
        "techblaze.com.au  |  https://idprova.dev",
        s["body"]
    ))

    return story


def main():
    doc = SimpleDocTemplate(
        OUTPUT_PDF,
        pagesize=A4,
        leftMargin=LEFT_MARGIN,
        rightMargin=RIGHT_MARGIN,
        topMargin=TOP_MARGIN,
        bottomMargin=BOTTOM_MARGIN,
        title="Response to NCCoE Concept Paper: Software and AI Agent Identity and Authorization",
        author="Pratyush Sood, Tech Blaze Consulting Pty Ltd",
        subject="NCCoE Feedback — AI Agent Identity and Authorization",
        creator="Tech Blaze Consulting",
    )

    styles = get_styles()
    story = build_content(styles)

    doc.build(story, onFirstPage=first_page, onLaterPages=header_footer)
    print(f"PDF generated: {OUTPUT_PDF}")


if __name__ == "__main__":
    main()
