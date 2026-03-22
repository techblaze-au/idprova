"""
Generate branded PDF for NIST RFI Response
Tech Blaze Consulting Pty Ltd
"""
import os
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm, cm
from reportlab.lib.colors import HexColor, white, black
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Image, Table, TableStyle,
    PageBreak, HRFlowable, KeepTogether
)
from reportlab.platypus.doctemplate import PageTemplate, BaseDocTemplate, Frame
from reportlab.lib.utils import ImageReader

# Brand colors
NAVY = HexColor('#1E3A5F')
BLUE = HexColor('#2563EB')
GREEN = HexColor('#10B981')
DARK_GREEN = HexColor('#059669')
LIGHT_GRAY = HexColor('#F3F4F6')
MEDIUM_GRAY = HexColor('#6B7280')
DARK_GRAY = HexColor('#374151')

# Paths
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOGO_PATH = os.path.join(
    os.path.dirname(SCRIPT_DIR), '..', 'Tech Blaze website', 'tech-blaze-web',
    'public', 'images', 'branding', 'logo.png'
)
# Fallback logo path
if not os.path.exists(LOGO_PATH):
    LOGO_PATH = r"c:\Users\praty\toon_conversations\Tech Blaze website\tech-blaze-web\public\images\branding\logo.png"

OUTPUT_PATH = os.path.join(SCRIPT_DIR, 'NIST-RFI-Response-TechBlaze.pdf')


def create_styles():
    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        'DocTitle',
        parent=styles['Title'],
        fontName='Helvetica-Bold',
        fontSize=16,
        textColor=NAVY,
        spaceAfter=6*mm,
        alignment=TA_CENTER,
        leading=20,
    ))

    styles.add(ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        textColor=MEDIUM_GRAY,
        alignment=TA_CENTER,
        spaceAfter=2*mm,
    ))

    styles.add(ParagraphStyle(
        'SectionHeader',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=14,
        textColor=NAVY,
        spaceBefore=8*mm,
        spaceAfter=4*mm,
        borderWidth=0,
        borderPadding=0,
    ))

    styles.add(ParagraphStyle(
        'SubsectionHeader',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=11,
        textColor=BLUE,
        spaceBefore=6*mm,
        spaceAfter=3*mm,
    ))

    styles.add(ParagraphStyle(
        'SubsubHeader',
        parent=styles['Heading3'],
        fontName='Helvetica-Bold',
        fontSize=10,
        textColor=DARK_GRAY,
        spaceBefore=4*mm,
        spaceAfter=2*mm,
    ))

    styles.add(ParagraphStyle(
        'BodyText2',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9.5,
        textColor=DARK_GRAY,
        alignment=TA_JUSTIFY,
        spaceAfter=3*mm,
        leading=14,
    ))

    styles.add(ParagraphStyle(
        'BulletText',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9.5,
        textColor=DARK_GRAY,
        alignment=TA_LEFT,
        leftIndent=8*mm,
        spaceAfter=1.5*mm,
        leading=13,
        bulletIndent=3*mm,
    ))

    styles.add(ParagraphStyle(
        'CertText',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9.5,
        textColor=DARK_GRAY,
        leftIndent=8*mm,
        spaceAfter=1*mm,
        leading=13,
    ))

    styles.add(ParagraphStyle(
        'RecommendationText',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9.5,
        textColor=DARK_GRAY,
        alignment=TA_JUSTIFY,
        leftIndent=8*mm,
        spaceAfter=3*mm,
        leading=14,
    ))

    styles.add(ParagraphStyle(
        'FooterStyle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8,
        textColor=MEDIUM_GRAY,
        alignment=TA_CENTER,
    ))

    return styles


def header_footer(canvas, doc):
    """Draw header bar and footer on each page."""
    canvas.saveState()
    width, height = A4

    # Header — navy bar
    canvas.setFillColor(NAVY)
    canvas.rect(0, height - 12*mm, width, 12*mm, fill=1, stroke=0)

    # Header text
    canvas.setFillColor(white)
    canvas.setFont('Helvetica-Bold', 8)
    canvas.drawString(15*mm, height - 8.5*mm, 'NIST-2025-0035  |  Security Considerations for AI Agents')
    canvas.drawRightString(width - 15*mm, height - 8.5*mm, 'Tech Blaze Consulting Pty Ltd')

    # Green accent line under header
    canvas.setStrokeColor(GREEN)
    canvas.setLineWidth(1.5)
    canvas.line(0, height - 12*mm, width, height - 12*mm)

    # Footer
    canvas.setFillColor(MEDIUM_GRAY)
    canvas.setFont('Helvetica', 7)
    canvas.drawCentredString(width / 2, 10*mm,
        f'Tech Blaze Consulting Pty Ltd  |  hello@techblaze.com.au  |  techblaze.com.au  |  Page {doc.page}')

    # Footer line
    canvas.setStrokeColor(LIGHT_GRAY)
    canvas.setLineWidth(0.5)
    canvas.line(15*mm, 14*mm, width - 15*mm, 14*mm)

    canvas.restoreState()


def build_pdf():
    styles = create_styles()

    doc = SimpleDocTemplate(
        OUTPUT_PATH,
        pagesize=A4,
        topMargin=20*mm,
        bottomMargin=20*mm,
        leftMargin=20*mm,
        rightMargin=20*mm,
    )

    story = []

    # === COVER / TITLE SECTION ===

    # Logo
    if os.path.exists(LOGO_PATH):
        logo = Image(LOGO_PATH, width=50*mm, height=50*mm * 0.4)
        logo.hAlign = 'CENTER'
        story.append(Spacer(1, 5*mm))
        story.append(logo)
        story.append(Spacer(1, 8*mm))
    else:
        story.append(Spacer(1, 15*mm))

    story.append(Paragraph(
        'Response to NIST Request for Information:<br/>'
        'Security Considerations for Artificial Intelligence Agents',
        styles['DocTitle']
    ))

    story.append(Spacer(1, 2*mm))

    # Metadata table
    meta_data = [
        ['Docket Number:', 'NIST-2025-0035'],
        ['Federal Register:', '2026-00206'],
        ['Submitted by:', 'Pratyush Sood, Principal Consultant & IRAP Assessor'],
        ['Organisation:', 'Tech Blaze Consulting Pty Ltd, Canberra, Australia'],
        ['Date:', 'March 2026'],
    ]
    meta_table = Table(meta_data, colWidths=[45*mm, 110*mm])
    meta_table.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('TEXTCOLOR', (0, 0), (0, -1), NAVY),
        ('TEXTCOLOR', (1, 0), (1, -1), DARK_GRAY),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 2),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
    ]))
    story.append(meta_table)

    story.append(Spacer(1, 4*mm))
    story.append(HRFlowable(width="100%", thickness=1, color=GREEN))

    # === ABOUT THE RESPONDENT ===
    story.append(Paragraph('About the Respondent', styles['SectionHeader']))

    story.append(Paragraph(
        'Pratyush Sood is an ASD-endorsed IRAP (Information Security Registered Assessors Program) '
        'Assessor with decades of experience in IT security and cybersecurity. He holds the following '
        'professional certifications:',
        styles['BodyText2']
    ))

    certs = [
        '<b>CISA</b> \u2014 Certified Information Systems Auditor (ISACA)',
        '<b>CISM</b> \u2014 Certified Information Security Manager (ISACA)',
        '<b>IRAP Assessor</b> \u2014 ASD-endorsed, Information Security Registered Assessors Program',
        '<b>Microsoft Certified: Azure Solutions Architect Expert</b>',
        '<b>TOGAF 10 Enterprise Architecture Practitioner</b> \u2014 The Open Group',
    ]
    for cert in certs:
        story.append(Paragraph(f'\u2022  {cert}', styles['CertText']))

    story.append(Spacer(1, 2*mm))
    story.append(Paragraph(
        'Pratyush has extensive experience assessing systems against the Australian Information Security '
        'Manual (ISM), NIST 800-53, and SOC 2 frameworks. Tech Blaze Consulting provides cybersecurity '
        'advisory services across government and enterprise sectors and is actively developing open-source '
        'tooling for AI agent identity and delegation management.',
        styles['BodyText2']
    ))
    story.append(Paragraph(
        'This response draws on direct operational experience deploying autonomous AI agent systems in '
        'enterprise environments, as well as extensive compliance assessment experience mapping security '
        'controls to multiple international frameworks.',
        styles['BodyText2']
    ))

    # === SECTION 1 ===
    story.append(HRFlowable(width="100%", thickness=0.5, color=LIGHT_GRAY))
    story.append(Paragraph('Section 1 \u2014 Threat Landscape', styles['SectionHeader']))

    story.append(Paragraph(
        '1(a): Unique security threats, risks, or vulnerabilities affecting AI agent systems',
        styles['SubsectionHeader']
    ))
    story.append(Paragraph(
        'AI agent systems introduce a fundamentally new class of security challenges that have no direct '
        'parallel in traditional software systems. The core issue is that agents combine <b>autonomous '
        'decision-making</b> with <b>real-world action authority</b> \u2014 a combination that existing '
        'security models were not designed to handle.',
        styles['BodyText2']
    ))

    # Threat 1
    story.append(Paragraph('1. The Identity Gap', styles['SubsubHeader']))
    story.append(Paragraph(
        'Traditional software authenticates using API keys, OAuth tokens, or service accounts \u2014 '
        'mechanisms designed for applications operated by humans. AI agents are neither human users nor '
        'traditional applications. They are autonomous entities that:',
        styles['BodyText2']
    ))
    bullets = [
        'Act on behalf of principals (humans or organisations) without real-time human oversight',
        'Spawn sub-agents that inherit and further delegate authority',
        'Operate across organisational boundaries with varying trust relationships',
        'Change behaviour based on their model, configuration, and prompt context',
    ]
    for b in bullets:
        story.append(Paragraph(f'\u2022  {b}', styles['BulletText']))
    story.append(Spacer(1, 1*mm))
    story.append(Paragraph(
        'Current identity mechanisms provide no standard way for an agent to cryptographically prove '
        '<i>who it is</i>, <i>what it is authorised to do</i>, or <i>on whose behalf it acts</i>. '
        'This creates an identity vacuum where agents operate with implicit trust rather than '
        'verifiable credentials.',
        styles['BodyText2']
    ))

    # Threat 2
    story.append(Paragraph('2. Delegation Chain Opacity', styles['SubsubHeader']))
    story.append(Paragraph(
        'In multi-agent systems, authority flows through delegation chains: a human authorises Agent A, '
        'which delegates to Agent B, which sub-delegates to Agent C. Today, these chains are typically '
        'opaque \u2014 there is no standard mechanism to:',
        styles['BodyText2']
    ))
    bullets = [
        'Trace the full delegation path from a leaf agent back to the authorising human',
        'Verify that each delegation step preserved or narrowed the scope of authority',
        'Detect privilege escalation where a sub-agent acquires broader permissions than its parent',
        'Revoke a delegation mid-chain without invalidating the entire hierarchy',
    ]
    for b in bullets:
        story.append(Paragraph(f'\u2022  {b}', styles['BulletText']))
    story.append(Spacer(1, 1*mm))
    story.append(Paragraph(
        'This opacity means that when an agent takes a harmful action, organisations cannot reliably '
        'determine who authorised it, through what chain of delegation, or whether the delegation was '
        'within scope.',
        styles['BodyText2']
    ))

    # Threat 3
    story.append(Paragraph('3. Audit Trail Fragmentation', styles['SubsubHeader']))
    story.append(Paragraph(
        'Agent actions span multiple systems, tools, and services. Each system may log the action '
        'differently (or not at all), creating fragmented audit trails that are:',
        styles['BodyText2']
    ))
    bullets = [
        'Difficult to correlate across systems',
        'Susceptible to tampering (standard logs lack cryptographic integrity)',
        'Insufficient for regulatory compliance (ISM, SOC 2, NIST 800-53 all require attributable, tamper-evident audit records)',
        'Unable to link actions back to the specific delegation that authorised them',
    ]
    for b in bullets:
        story.append(Paragraph(f'\u2022  {b}', styles['BulletText']))

    # Threat 4
    story.append(Paragraph('4. Configuration Drift as a Security Vector', styles['SubsubHeader']))
    story.append(Paragraph(
        'Unlike traditional software with deterministic behaviour, an AI agent\'s behaviour is a function '
        'of its model weights, system prompt, tool definitions, and runtime configuration. A change to '
        'any of these \u2014 even without changing the agent\'s code \u2014 can fundamentally alter its '
        'behaviour. Current systems have no mechanism to:',
        styles['BodyText2']
    ))
    bullets = [
        'Attest to an agent\'s configuration at the time of an interaction',
        'Detect when an agent\'s configuration has drifted from its assessed baseline',
        'Tie trust decisions to a specific, verified configuration state',
    ]
    for b in bullets:
        story.append(Paragraph(f'\u2022  {b}', styles['BulletText']))

    # Threat 5
    story.append(Paragraph('5. Trust Bootstrap Problem', styles['SubsubHeader']))
    story.append(Paragraph(
        'When two agents encounter each other for the first time \u2014 particularly across organisational '
        'boundaries \u2014 there is no standard mechanism to establish baseline trust. Unlike human-to-human '
        'interactions (where identity documents, organisational affiliations, and reputation provide trust '
        'signals), agent-to-agent interactions currently begin from a position of either blind trust or '
        'complete rejection.',
        styles['BodyText2']
    ))

    # 1(d)
    story.append(Paragraph(
        '1(d): Emerging risks as agent capabilities expand',
        styles['SubsectionHeader']
    ))
    story.append(Paragraph(
        'As agent systems become more capable, several risks are escalating:',
        styles['BodyText2']
    ))

    story.append(Paragraph(
        '<b>Autonomous Agent Proliferation:</b> The barrier to deploying AI agents is dropping rapidly. '
        'We are approaching an environment where hundreds of millions of agents will operate across '
        'enterprise and consumer environments. Without standardised identity, this creates a landscape '
        'where impersonation is trivial \u2014 any agent can claim to be any other agent.',
        styles['BodyText2']
    ))
    story.append(Paragraph(
        '<b>Cross-Boundary Agent Communication:</b> Protocols like the Model Context Protocol (MCP) '
        'and Agent-to-Agent (A2A) protocol are enabling agents to discover and communicate with other '
        'agents across organisational boundaries. This dramatically expands the attack surface for agent '
        'impersonation, scope escalation, and lateral movement.',
        styles['BodyText2']
    ))
    story.append(Paragraph(
        '<b>Post-Quantum Threat to Agent Credentials:</b> Agent credentials created today using classical '
        'cryptography may be vulnerable to future quantum computing attacks. Agents with long-lived '
        'identities (months to years) face a "harvest now, decrypt later" risk where adversaries capture '
        'signed delegation tokens and audit records for future cryptanalysis. Agent identity systems need '
        'to incorporate post-quantum cryptographic readiness from day one.',
        styles['BodyText2']
    ))

    # === SECTION 2 ===
    story.append(HRFlowable(width="100%", thickness=0.5, color=LIGHT_GRAY))
    story.append(Paragraph('Section 2 \u2014 Development Security', styles['SectionHeader']))

    story.append(Paragraph(
        '2(a): Methods for improving security during creation and deployment',
        styles['SubsectionHeader']
    ))
    story.append(Paragraph(
        'Based on our experience building and deploying agent systems, we recommend the following '
        'development-phase security practices:',
        styles['BodyText2']
    ))

    story.append(Paragraph('1. Cryptographic Identity from Creation', styles['SubsubHeader']))
    story.append(Paragraph(
        'Every agent should be assigned a cryptographically verifiable identity at the moment of '
        'creation \u2014 not as an afterthought during deployment. This identity should:',
        styles['BodyText2']
    ))
    bullets = [
        'Be based on established standards (W3C Decentralized Identifiers provide a strong foundation)',
        'Include at minimum an Ed25519 key pair, with a post-quantum key pair (ML-DSA-65 per FIPS 204) strongly recommended',
        'Be bound to the creating principal through a signed proof of controller relationship',
        'Carry agent-specific metadata (model, runtime, configuration attestation, trust level)',
    ]
    for b in bullets:
        story.append(Paragraph(f'\u2022  {b}', styles['BulletText']))

    story.append(Paragraph('2. Principle of Least Privilege via Scoped Delegation', styles['SubsubHeader']))
    story.append(Paragraph(
        'Authority should flow to agents through explicit, scoped, time-bounded delegation tokens '
        'rather than broad API keys or role-based access. Each delegation should specify:',
        styles['BodyText2']
    ))
    bullets = [
        'Exactly which actions the agent may perform (using a structured scope grammar)',
        'Temporal bounds (issued-at, not-before, expiry)',
        'Contextual constraints (IP ranges, rate limits, geographic restrictions)',
        'Maximum re-delegation depth (preventing unbounded delegation chains)',
    ]
    for b in bullets:
        story.append(Paragraph(f'\u2022  {b}', styles['BulletText']))

    story.append(Paragraph('3. Configuration Attestation', styles['SubsubHeader']))
    story.append(Paragraph(
        'Agent configurations should be hashed at deployment time and included in the agent\'s identity '
        'document. This enables verifiers to detect configuration drift between interactions. The hash '
        'should cover the agent\'s system prompt, tool definitions, model identifier, and any runtime '
        'parameters that affect behaviour.',
        styles['BodyText2']
    ))

    story.append(Paragraph('4. Hybrid Post-Quantum Cryptography', styles['SubsubHeader']))
    story.append(Paragraph(
        'New agent identity systems should adopt a hybrid signature scheme combining Ed25519 (classical) '
        'with ML-DSA-65 (post-quantum) from the initial deployment. This provides defence in depth without '
        'waiting for full PQC standardisation adoption. The performance overhead of hybrid signatures is '
        'minimal for the signing frequencies typical in agent delegation scenarios.',
        styles['BodyText2']
    ))

    # 2(e)
    story.append(Paragraph(
        '2(e): Security considerations specific to multi-agent architectures',
        styles['SubsectionHeader']
    ))
    story.append(Paragraph(
        'Multi-agent systems introduce unique development-phase security requirements:',
        styles['BodyText2']
    ))
    story.append(Paragraph(
        '<b>Delegation Chain Validation:</b> Systems should enforce that each step in a delegation chain '
        'provably narrows or maintains \u2014 never escalates \u2014 the scope of authority. This requires '
        'a formal scope algebra where child scopes can be verified as subsets of parent scopes.',
        styles['BodyText2']
    ))
    story.append(Paragraph(
        '<b>Chain Depth Limits:</b> Maximum delegation depth should be configurable and enforced. Our '
        'experience suggests a default maximum of 5 hops balances practical orchestration needs with '
        'auditability.',
        styles['BodyText2']
    ))
    story.append(Paragraph(
        '<b>Cross-Organisation Trust Bootstrapping:</b> When agents operate across organisational '
        'boundaries, a progressive trust model is more practical than binary trust/no-trust. We recommend '
        'a graduated trust framework (e.g., L0\u2013L4) where agents start at the lowest trust level and '
        'progressively prove trustworthiness through verifiable mechanisms: self-declaration \u2192 domain '
        'verification \u2192 organisational verification \u2192 third-party attestation \u2192 continuous '
        'monitoring.',
        styles['BodyText2']
    ))

    # === SECTION 3 ===
    story.append(HRFlowable(width="100%", thickness=0.5, color=LIGHT_GRAY))
    story.append(Paragraph('Section 3 \u2014 Measurement and Assessment', styles['SectionHeader']))

    story.append(Paragraph(
        '3(a): Ways to assess and measure agent security',
        styles['SubsectionHeader']
    ))

    story.append(Paragraph('1. Delegation Chain Integrity Testing', styles['SubsubHeader']))
    story.append(Paragraph(
        'Security assessments should verify that delegation chains maintain scope boundaries under '
        'adversarial conditions:',
        styles['BodyText2']
    ))
    bullets = [
        'Attempt to issue a child delegation with broader scope than the parent',
        'Attempt to exceed the maximum delegation depth',
        'Attempt to use a revoked parent delegation to validate a child',
        'Verify that delegation expiry is enforced at every chain link',
    ]
    for b in bullets:
        story.append(Paragraph(f'\u2022  {b}', styles['BulletText']))

    story.append(Paragraph('2. Audit Trail Integrity Verification', styles['SubsubHeader']))
    story.append(Paragraph(
        'Agent audit trails should be assessable for tamper evidence. Hash-chained action receipts \u2014 '
        'where each receipt includes a cryptographic hash of the previous receipt \u2014 provide a mechanism '
        'for verifying that no receipts have been inserted, modified, or removed. Assessment should include:',
        styles['BodyText2']
    ))
    bullets = [
        'Chain continuity verification (no gaps in sequence numbers)',
        'Hash chain integrity (each receipt\'s previous-hash matches the computed hash of the prior receipt)',
        'Signature verification on each receipt',
        'Correlation of receipts with the delegation tokens that authorised them',
    ]
    for b in bullets:
        story.append(Paragraph(f'\u2022  {b}', styles['BulletText']))

    story.append(Paragraph('3. Configuration Drift Detection', styles['SubsubHeader']))
    story.append(Paragraph(
        'Assessors should be able to verify that an agent\'s current configuration matches the configuration '
        'attested in its identity document. This provides a cryptographic mechanism for detecting when an '
        'agent\'s behaviour may have changed from its assessed baseline.',
        styles['BodyText2']
    ))

    story.append(Paragraph('4. Compliance Mapping', styles['SubsubHeader']))
    story.append(Paragraph(
        'Agent security measurements should map directly to existing compliance frameworks. For example, '
        'action receipts should demonstrably satisfy:',
        styles['BodyText2']
    ))
    bullets = [
        'NIST 800-53 AU-2 (auditable events), AU-3 (content of audit records), AU-9 (protection of audit information), AU-10 (non-repudiation)',
        'NIST 800-53 IA-2 (identification and authentication), AC-6 (least privilege)',
        'SOC 2 CC6.1 (logical access security), CC6.2 (authorised scope), CC6.3 (audit trail integrity)',
    ]
    for b in bullets:
        story.append(Paragraph(f'\u2022  {b}', styles['BulletText']))

    # 3(b)
    story.append(Paragraph(
        '3(b): Approaches to anticipating development-stage risks',
        styles['SubsectionHeader']
    ))
    story.append(Paragraph(
        '<b>Threat Modelling for Delegation:</b> Before deploying multi-agent systems, organisations '
        'should model delegation flows and identify:',
        styles['BodyText2']
    ))
    bullets = [
        'Which agents can create sub-agents and with what scope',
        'Maximum blast radius of a compromised agent at each position in the delegation hierarchy',
        'Whether any delegation path could result in an agent with broader effective permissions than intended',
    ]
    for b in bullets:
        story.append(Paragraph(f'\u2022  {b}', styles['BulletText']))
    story.append(Spacer(1, 1*mm))
    story.append(Paragraph(
        '<b>Red Team Agent Impersonation:</b> Development testing should include adversarial scenarios '
        'where a rogue agent attempts to impersonate a legitimate agent, present forged delegation tokens, '
        'or replay captured tokens. Systems without cryptographic identity verification are trivially '
        'vulnerable to these attacks.',
        styles['BodyText2']
    ))

    # === SECTION 4 ===
    story.append(HRFlowable(width="100%", thickness=0.5, color=LIGHT_GRAY))
    story.append(Paragraph('Section 4 \u2014 Deployment Safeguards', styles['SectionHeader']))

    story.append(Paragraph(
        '4(a): Deployment environment interventions that address security risks',
        styles['SubsectionHeader']
    ))

    story.append(Paragraph('1. Cryptographic Identity Verification at Every Interaction Point', styles['SubsubHeader']))
    story.append(Paragraph(
        'Every system that accepts requests from an AI agent should verify the agent\'s cryptographic '
        'identity and delegation authority before executing any action. This is analogous to mTLS for '
        'service-to-service communication, but elevated to include agent-specific semantics (delegation '
        'scope, trust level, configuration attestation).',
        styles['BodyText2']
    ))

    story.append(Paragraph('2. Protocol-Native Identity Binding', styles['SubsubHeader']))
    story.append(Paragraph(
        'Agent identity verification should be integrated into the communication protocols agents use, '
        'rather than bolted on as a separate layer. For example:',
        styles['BodyText2']
    ))
    bullets = [
        'MCP tool calls should carry delegation tokens that the server validates before execution',
        'A2A agent communication should include mutual identity verification during session establishment',
        'HTTP-based agent APIs should accept and validate agent identity tokens alongside (or instead of) traditional API keys',
    ]
    for b in bullets:
        story.append(Paragraph(f'\u2022  {b}', styles['BulletText']))

    story.append(Paragraph('3. Registry Infrastructure', styles['SubsubHeader']))
    story.append(Paragraph(
        'Organisations deploying agents should operate identity registries that store and resolve agent '
        'identity documents. These registries serve a role analogous to DNS for domain names or certificate '
        'transparency logs for TLS certificates \u2014 they provide a discoverable, verifiable record of '
        'agent identities. Self-hosted registries should be first-class citizens alongside managed services '
        'to avoid creating a centralised point of control.',
        styles['BodyText2']
    ))

    # 4(b)
    story.append(Paragraph(
        '4(b): Methods to constrain and monitor agent access',
        styles['SubsectionHeader']
    ))

    story.append(Paragraph('1. Scoped Delegation with Constraint Enforcement', styles['SubsubHeader']))
    story.append(Paragraph(
        'Beyond scope (what actions an agent may perform), delegation tokens should carry enforceable '
        'constraints:',
        styles['BodyText2']
    ))
    bullets = [
        '<b>Rate limits:</b> Maximum actions per hour/day to contain the blast radius of a compromised agent',
        '<b>IP restrictions:</b> Restrict agent operation to specific network ranges',
        '<b>Temporal bounds:</b> Short-lived tokens (24 hours for low-trust agents, 7 days for high-trust) force regular re-authorisation',
        '<b>Geographic restrictions:</b> Limit agent operation to specific jurisdictions (critical for data sovereignty compliance)',
        '<b>Re-delegation limits:</b> Prevent unbounded delegation chains by setting maximum further delegation depth',
    ]
    for b in bullets:
        story.append(Paragraph(f'\u2022  {b}', styles['BulletText']))

    story.append(Paragraph('2. Hash-Chained Action Receipts for Monitoring', styles['SubsubHeader']))
    story.append(Paragraph(
        'Every significant action performed by an agent should produce a signed, hash-chained action '
        'receipt. These receipts enable:',
        styles['BodyText2']
    ))
    bullets = [
        'Real-time monitoring of agent behaviour against expected patterns',
        'Post-incident forensic analysis with tamper-evident guarantees',
        'Automated anomaly detection (unusual scope usage, unexpected action frequency, actions outside normal time windows)',
        'Complete attribution from action \u2192 delegation \u2192 authorising principal',
    ]
    for b in bullets:
        story.append(Paragraph(f'\u2022  {b}', styles['BulletText']))

    story.append(Paragraph('3. Progressive Trust with Automated Demotion', styles['SubsubHeader']))
    story.append(Paragraph(
        'Continuously monitored agents (highest trust level) should be subject to automated trust '
        'demotion if monitoring detects policy violations. This creates a self-correcting system where '
        'misbehaving agents automatically lose privileges without requiring human intervention.',
        styles['BodyText2']
    ))

    # 4(d)
    story.append(Paragraph(
        '4(d): Accountability frameworks for agent actions',
        styles['SubsectionHeader']
    ))
    story.append(Paragraph(
        '<b>The Delegation Chain as Accountability Chain:</b> The delegation chain from a root principal '
        '(human/organisation) to a leaf agent provides a natural accountability framework. By requiring '
        'that every agent action reference the specific delegation that authorised it, and that every '
        'delegation cryptographically chains back to a human principal, organisations can always answer: '
        '"Who authorised this agent to do this?"',
        styles['BodyText2']
    ))
    story.append(Paragraph(
        '<b>Non-Repudiation Through Cryptographic Signing:</b> When agents sign their action receipts '
        'with their own keys (separate from their delegator\'s keys), the agent cannot later deny having '
        'performed the action, and the delegator cannot deny having authorised the delegation. This provides '
        'bidirectional non-repudiation that satisfies compliance requirements.',
        styles['BodyText2']
    ))
    story.append(Paragraph(
        '<b>Regulatory Framework Alignment:</b> Agent audit systems should be designed from the outset '
        'to map to existing compliance frameworks. In our assessment experience, the most commonly required '
        'mappings are:',
        styles['BodyText2']
    ))
    bullets = [
        '<b>NIST 800-53 Rev. 5:</b> AU (Audit and Accountability), IA (Identification and Authentication), AC (Access Control) families',
        '<b>SOC 2:</b> Trust Services Criteria CC6 (Logical and Physical Access Controls), CC7 (System Operations)',
        '<b>Australian ISM:</b> ISM-0585 (identification of processes), ISM-0988 (logging of privileged actions), ISM-0580 (audit log integrity)',
    ]
    for b in bullets:
        story.append(Paragraph(f'\u2022  {b}', styles['BulletText']))

    # === RECOMMENDATIONS ===
    story.append(HRFlowable(width="100%", thickness=0.5, color=LIGHT_GRAY))
    story.append(Paragraph('Recommendations for NIST Guidance', styles['SectionHeader']))

    story.append(Paragraph(
        'Based on our experience building and assessing agent systems, we offer the following '
        'recommendations for NIST\'s forthcoming guidance:',
        styles['BodyText2']
    ))

    recs = [
        '<b>Establish a standard agent identity model</b> built on existing W3C Decentralized Identifier (DID) standards, extended with agent-specific metadata (model, runtime, configuration attestation, trust level, capabilities).',
        '<b>Define a scoped delegation token format</b> based on JWS/JWT conventions, with a formal scope grammar and constraint model that prevents privilege escalation through delegation chains.',
        '<b>Specify a tamper-evident audit format</b> using hash-chained, signed action receipts that map to NIST 800-53 audit controls, enabling compliance verification by existing assessment frameworks.',
        '<b>Mandate post-quantum cryptographic readiness</b> from the initial version of any agent identity standard. A hybrid Ed25519 + ML-DSA-65 approach provides immediate security with future quantum resistance.',
        '<b>Define progressive trust levels</b> that allow agents to earn trust through verifiable mechanisms, rather than requiring binary trust decisions. This is particularly important for cross-organisational agent interactions.',
        '<b>Ensure protocol composability</b> \u2014 agent identity should layer on top of existing communication protocols (MCP, A2A, HTTP) rather than requiring new transport mechanisms.',
        '<b>Prioritise open-source reference implementations</b> to accelerate adoption and enable security community review. An open-core model (open-source core protocol with commercial extensions for enterprise features) balances accessibility with sustainability.',
    ]
    for i, rec in enumerate(recs, 1):
        story.append(Paragraph(f'{i}.  {rec}', styles['RecommendationText']))

    # === CONCLUSION ===
    story.append(HRFlowable(width="100%", thickness=0.5, color=LIGHT_GRAY))
    story.append(Paragraph('Conclusion', styles['SectionHeader']))

    story.append(Paragraph(
        'The security challenges facing AI agent systems are fundamentally identity challenges. Without '
        'standardised, cryptographically verifiable agent identity, scoped delegation, and tamper-evident '
        'audit trails, the emerging agent ecosystem will remain vulnerable to impersonation, privilege '
        'escalation, and regulatory non-compliance.',
        styles['BodyText2']
    ))
    story.append(Paragraph(
        'NIST is uniquely positioned to establish the foundational standards that will shape agent security '
        'for the next decade. We strongly encourage NIST to prioritise agent identity infrastructure '
        'alongside the threat mitigation guidance sought by this RFI \u2014 the threats identified in '
        'Section 1 are largely symptoms of the identity gap, and addressing identity will mitigate them '
        'at the root.',
        styles['BodyText2']
    ))
    story.append(Paragraph(
        'Tech Blaze Consulting is committed to contributing to this effort and welcomes the opportunity '
        'to participate in further standards development, NCCoE demonstration projects, or public working '
        'groups.',
        styles['BodyText2']
    ))

    # === CONTACT ===
    story.append(Spacer(1, 6*mm))
    story.append(HRFlowable(width="100%", thickness=1, color=GREEN))
    story.append(Spacer(1, 4*mm))

    contact_data = [
        ['Pratyush Sood'],
        ['Principal Consultant & IRAP Assessor'],
        ['Tech Blaze Consulting Pty Ltd'],
        ['hello@techblaze.com.au'],
        ['https://techblaze.com.au'],
    ]
    contact_table = Table(contact_data, colWidths=[170*mm])
    contact_table.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (0, 0), 'Helvetica-Bold'),
        ('FONTNAME', (0, 1), (0, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('TEXTCOLOR', (0, 0), (0, 0), NAVY),
        ('TEXTCOLOR', (0, 1), (0, -1), DARK_GRAY),
        ('TEXTCOLOR', (0, 3), (0, 4), BLUE),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('TOPPADDING', (0, 0), (-1, -1), 1),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 1),
    ]))
    story.append(contact_table)

    # Build
    doc.build(story, onFirstPage=header_footer, onLaterPages=header_footer)
    print(f"PDF generated: {OUTPUT_PATH}")
    return OUTPUT_PATH


if __name__ == '__main__':
    path = build_pdf()
    print(f"Done! File: {path}")