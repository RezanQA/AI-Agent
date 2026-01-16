# AI-Agent

An advanced AI agent prompt for comprehensive security assessment, now in **version 5.0** with enhanced reasoning, adaptive learning, and context-aware intelligence.

## 🚀 What's New in v5.0

SecureVanguard Elite v5.0 represents a major leap forward in AI-powered security assessment capabilities:

### 🧠 Advanced Reasoning Framework
- **Multi-layer cognitive architecture** with deductive, inductive, abductive, and analogical reasoning
- **Chain-of-thought processing** for transparent and logical vulnerability analysis
- **Metacognitive capabilities** for self-awareness and quality control

### 🔄 Adaptive Learning System
- **Continuous improvement** through feedback loops and pattern reinforcement
- **Context-specific adaptation** based on technology stack, industry, and architecture
- **Exploit evolution** that generates and tests new payload variations
- **Performance monitoring** with automated calibration

### 🎯 Context-Aware Intelligence
- **Business impact modeling** with financial, operational, competitive, and compliance dimensions
- **Environmental awareness** that adapts behavior to production, staging, or development environments
- **Intelligent prioritization** using business-aligned risk scoring algorithms
- **Optimal timing** that respects peak hours and rate limits

### 🔗 Attack Chain Discovery
- **Automated multi-stage attack analysis** that discovers complex exploitation paths
- **Graph-based vulnerability relationships** with intelligent path finding
- **Chain validation** to ensure viability of discovered attack sequences
- **Impact amplification** calculations for combined vulnerabilities

### 📊 Probabilistic Risk Assessment
- **Bayesian inference** for accurate severity scoring with confidence intervals
- **Monte Carlo simulation** to model thousands of attack scenarios
- **Uncertainty quantification** with explicit confidence levels
- **Prior probability updates** based on environmental factors

### 💡 Self-Improvement Loop
- **Performance metrics tracking** (detection rate, precision, efficiency, coverage)
- **Automated parameter tuning** for optimal performance
- **Knowledge base expansion** from validated findings and public disclosures
- **Meta-learning** to improve learning strategies themselves

### 🎓 Explainable AI
- **Reasoning transparency** with complete evidence and logic chains
- **Decision audit trails** for quality review and compliance
- **Multi-audience explanations** (executives, developers, security teams)
- **Confidence justification** for every finding

### 🔧 Practical Enhancements
- **Intelligent test prioritization** based on likelihood and impact
- **Smart payload selection** optimized for detected context
- **Adaptive rate limiting** using AIMD algorithm
- **Incremental reporting** with real-time findings
- **Remediation prioritization** for maximum risk reduction

### 📈 Enhanced Output Formats
- **Machine-readable outputs** (SARIF, JSON API, DefectDojo, CSV)
- **Intelligent grouping** by root cause, attack chain, or component
- **Interactive reports** with filtering, drill-down, and progress tracking
- **Executive dashboards** with key metrics and visualizations

## 📖 Usage

The AI-Agent prompt is defined in `AI-Agent.md` and can be used with AI systems that support complex prompts and instructions.

### 🎯 New in This Version - Bug Bounty & Advanced Security Testing

This version includes comprehensive support for:

**Bug Bounty Programs:**
- Complete In-Scope and Out-of-Scope target definitions
- Vulnerability prioritization based on bounty payouts
- Responsible disclosure guidelines
- Bug bounty-specific testing methodology

**Business Logic Vulnerabilities:**
- Price manipulation and payment bypass
- Rate limiting bypass techniques  
- Workflow and verification skip attacks
- Race condition exploitation
- Parameter manipulation and state attacks

**Advanced IDOR Testing:**
- Sequential, UUID, hash-based ID enumeration
- Blind IDOR detection techniques
- IDOR attack chains (account takeover, data exfiltration, privilege escalation)
- Mass assignment combined with IDOR
- GraphQL IDOR testing

**Advanced Injection Attacks:**
- SQL Injection with modern WAF bypass techniques
- XSS (Stored, Reflected, DOM, Mutation) with context-aware payloads
- Command Injection with reverse shell payloads
- LFI/RFI with log poisoning and wrapper exploitation
- SSTI for multiple template engines
- XXE with out-of-band data exfiltration
- Deserialization attacks (Java, Python, PHP)
- NoSQL injection

**Authentication & Account Takeover:**
- OAuth 2.0 exploitation (authorization code interception, pre-account takeover)
- SSO vulnerabilities (SAML signature wrapping, response replay)
- JWT attacks (algorithm confusion, weak secrets, key injection)
- Complete account takeover chains
- MFA bypass techniques
- Session attacks and credential stuffing

### Quick Start Examples

```yaml
# Comprehensive Assessment with Bug Bounty Focus
ACTIVATE_SECUREVANGUARD_v5 {
  target: "https://app.example.com",
  mode: "bug_bounty",
  scope: {
    in_scope: ["*.example.com", "api.example.com"],
    out_of_scope: ["legacy.example.com"],
    vulnerability_types: ["RCE", "SQLi", "IDOR", "Account_Takeover", "Business_Logic"]
  },
  standards: ["OWASP_2025", "API_SECURITY_2023"]
}

# Business Logic and Advanced IDOR Testing
ACTIVATE_SECUREVANGUARD_v5 {
  target: "https://shop.example.com",
  mode: "focused",
  focus: [
    "business_logic",
    "price_manipulation",
    "idor_advanced",
    "rate_limit_bypass",
    "workflow_bypass"
  ],
  test_scenarios: [
    "negative_quantity",
    "discount_stacking",
    "payment_bypass",
    "race_conditions"
  ]
}

# Advanced Injection Testing with WAF Bypass
ACTIVATE_SECUREVANGUARD_v5 {
  target: "https://app.example.com",
  mode: "focused",
  focus: [
    "sql_injection_advanced",
    "xss_with_bypass",
    "command_injection",
    "lfi_rfi",
    "ssti",
    "xxe"
  ],
  waf_detection: true,
  bypass_techniques: "automatic"
}

# Authentication & Account Takeover Testing
ACTIVATE_SECUREVANGUARD_v5 {
  target: "https://app.example.com",
  mode: "focused",
  focus: [
    "oauth_exploitation",
    "jwt_attacks",
    "saml_vulnerabilities",
    "account_takeover",
    "mfa_bypass",
    "session_attacks"
  ],
  authentication_flows: ["oauth", "sso", "saml", "jwt"]
}

# Rapid Security Check
ACTIVATE_SECUREVANGUARD_v5 {
  target: "https://app.example.com",
  mode: "rapid",
  focus: ["injection", "authentication", "access_control", "idor"],
  max_duration: "30_minutes"
}

# CI/CD Integration
ACTIVATE_SECUREVANGUARD_v5 {
  target: "staging.example.com",
  mode: "continuous",
  trigger: "pull_request",
  fail_on: "critical_or_high"
}
```

## 🎯 Key Features

- **OWASP Top 10: 2025** comprehensive coverage with new categories (Supply Chain, Exceptional Conditions)
- **OWASP API Security Top 10: 2023** complete testing framework
- **Bug Bounty Program Support** with comprehensive In-Scope and Out-of-Scope definitions
- **Business Logic Error Testing** - Detect and exploit complex business logic flaws including:
  - Price manipulation and negative quantity attacks
  - Rate limiting bypass techniques
  - Workflow and payment bypass vulnerabilities
  - Race condition exploitation
- **Advanced IDOR Detection** - Comprehensive Insecure Direct Object Reference testing:
  - Sequential, UUID, hash-based, and encoded ID manipulation
  - Blind IDOR detection techniques
  - IDOR attack chains for account takeover and data exfiltration
  - GraphQL and API-specific IDOR testing
- **Advanced Injection Payloads** with modern WAF bypass techniques:
  - **SQL Injection**: Boolean-based, time-based, out-of-band, second-order with database-specific payloads
  - **Cross-Site Scripting (XSS)**: Stored, Reflected, DOM-based, mutation XSS with context-aware bypasses
  - **Command Injection**: OS command injection with blacklist bypasses and reverse shells
  - **LFI/RFI**: Local and Remote File Inclusion with wrapper exploitation and log poisoning
  - **SSTI**: Server-Side Template Injection for Jinja2, Freemarker, Velocity, Thymeleaf
  - **XXE**: XML External Entity with out-of-band data exfiltration
  - **Deserialization**: Java, Python, PHP insecure deserialization attacks
  - **NoSQL Injection**: MongoDB operator injection and authentication bypass
- **Authentication & Account Takeover Framework**:
  - **OAuth 2.0 Exploitation**: Authorization code interception, state parameter attacks, pre-account takeover
  - **SSO Vulnerabilities**: SAML XML signature wrapping, response replay, assertion modification
  - **JWT Attacks**: Algorithm confusion, weak secrets, key injection, claims manipulation
  - **Account Takeover Chains**: Password reset vulnerabilities, session attacks, MFA bypass, credential stuffing
- **Multi-standard compliance** (OWASP ASVS 4.0, MITRE ATT&CK, CWE/SANS Top 25)
- **Advanced detection engine** with false positive elimination
- **Intelligent payload generation** with context-aware mutations and automatic WAF bypass
- **Professional reporting templates** (executive, technical, developer, compliance)
- **Attack chain correlation** for complex multi-stage exploits
- **Ethical guidelines** and safety constraints built-in

## 📊 Improvements Over Previous Versions

| Aspect | v4.0 | v5.0 |
|--------|------|------|
| Reasoning | Pattern matching | Multi-mode reasoning + chain-of-thought |
| Learning | Static rules | Adaptive learning with feedback loops |
| Context | Technology-aware | Business + environment + timing aware |
| Risk Assessment | CVSS scoring | Probabilistic Bayesian inference |
| Reporting | Static reports | Interactive + machine-readable |
| Accuracy | ~90% | Target >98% with <2% FP rate |
| Explainability | Basic evidence | Full reasoning transparency |

## 🔒 Safety & Ethics

SecureVanguard Elite v5.0 includes comprehensive ethical guidelines:
- Always obtain written authorization
- Never exceed defined scope
- Use safe exploitation techniques only
- Protect discovered vulnerabilities
- Respect rate limits in production environments
- Immediate stop capability for unintended impacts

## 📚 Documentation

The complete agent prompt with all capabilities is available in `AI-Agent.md`, including:
- Detailed vulnerability testing frameworks
- Payload libraries and bypass techniques
- Detection and validation methodologies
- Professional reporting templates
- Compliance mapping (PCI DSS, GDPR, SOC2, HIPAA)
- Quality assurance checklists

## 🤝 Contributing

This is an advanced security assessment prompt designed for professional security testing. Contributions that enhance detection capabilities, reduce false positives, or improve explainability are welcome.

## ⚠️ Legal Notice

This prompt is intended for authorized security testing only. Users must:
- Obtain proper authorization before testing
- Comply with all applicable laws and regulations
- Use responsibly and ethically
- Not use for malicious purposes

## 📄 License

This project is shared for educational and professional security testing purposes.

---

**Version:** 5.0  
**Last Updated:** 2026-01-16  
**Aligned with:** OWASP Top 10: 2025 & OWASP API Security Top 10: 2023
