# Compliance Mapping (IaC Scanning)

## How It Works

**Automatic compliance mapping** is enabled by default on all IaC scans. The Vision One API returns `complianceStandards` arrays in every finding, showing which regulatory frameworks are violated without requiring any configuration or cloud account integration.

**Example scan result:**
```python
{
    "ruleId": "S3-016",
    "ruleTitle": "S3 Bucket Encryption",
    "riskLevel": "HIGH",
    "resource": "my-bucket",
    "complianceStandards": [
        {"id": "CIS-V8"},
        {"id": "NIST5"},
        {"id": "AWAF-2025"},
        {"id": "PCI-V4"},
        {"id": "HIPAA"},
        {"id": "ISO27001-2022"}
        // ... up to 20+ frameworks per finding
    ]
}
```

## Supported Compliance Frameworks (45 total)

### Multi-Cloud Standards (22)

- CIS Controls v8 (CIS-V8)
- NIST 800-53 Rev4/Rev5 (NIST4, NIST5)
- NIST Cybersecurity Framework v1.1/v2.0 (NIST-CSF, NIST-CSF-2_0)
- PCI DSS v3.2.1/v4.0.1 (PCI, PCI-V4)
- HIPAA, ISO 27001:2013/2022 (ISO27001, ISO27001-2022)
- SOC 2, HITRUST CSF v11.3.0
- FEDRAMP Rev 4
- AusGov ISM (AGISM-2024), APRA CPS 234
- MAS TRM 2021 (Singapore), NIS 2 Directive v2 (EU)
- FISC Security Guidelines V12 (Japan), ASAE 3150 (Australia)
- LGPD (Brazil), GDPR (EU), KISA ISMS-P (Korea)

### AWS-Specific (10)

- AWS Well-Architected Framework (AWAF-2025, AWAF-AI-2025, AWAF-ML-2025)
- AWS Security Reference Architecture (AWS-SRA, AWS-SRA-AI)
- CIS AWS Foundations Benchmark v3.0, v4.0.1, v5.0, v6.0, v7.0

### Azure-Specific (5)

- Azure Well-Architected Framework (AZUREWAF-2025)
- CIS Azure Foundations Benchmark v2.1, v3.0, v4.0, v5.0

### GCP-Specific (3)

- Google Cloud Well-Architected Framework (GCPWAF-2025)
- CIS GCP Foundation Benchmark v3.0, v4.0

### Other Cloud (5)

- Oracle Cloud Infrastructure Well-Architected (OCIWAF-2026)
- CIS OCI Foundations Benchmark v3.0, v3.1
- CIS Alibaba Cloud Foundation Benchmark v1.0, v2.0

## AI Assistant Guidance

### When reporting IaC scan results:

1. **Always report compliance violations for HIGH/EXTREME findings**
   - Parse `complianceStandards` array from findings
   - Format as: "⚠️ Violates 12 compliance frameworks: CIS-V8, NIST5, AWAF-2025, PCI-V4, HIPAA..."
   - Show count + first 5-6 frameworks to avoid overwhelming output

2. **Use targeted scanning when user mentions a framework:**
   - "Scan against CIS" → call `list_compliance_profiles`, find CIS profile, pass `profile_id` to scan
   - "Check PCI compliance" → find PCI profile, use it
   - "NIST validation" → find NIST profile, use it

3. **Proactively highlight compliance context:**
   - After scanning, summarize: "Found 15 HIGH findings violating 8 compliance frameworks"
   - For users in regulated industries, emphasize compliance impact

### Value proposition example:

**Before compliance mapping:**
```
Finding: S3 bucket is publicly readable
Risk: HIGH
Resource: my-bucket
```

**After compliance mapping:**
```
Finding: S3 bucket is publicly readable
Risk: HIGH
Resource: my-bucket
⚠️ Violates 22 compliance frameworks:
   • CIS-V8 (CIS Controls v8)
   • NIST5 (NIST 800-53 Rev5)
   • AWAF-2025 (AWS Well-Architected)
   • PCI-V4 (PCI DSS v4.0.1)
   • HIPAA (Healthcare)
   • ISO27001-2022, SOC2, FEDRAMP, AGISM-2024, MAS...
```

## Automatic vs Targeted Scanning

### Automatic (default)
- Runs comprehensive rule set
- Every finding mapped to ALL applicable frameworks
- No configuration needed

### Targeted (optional)
- User specifies `profile_id` (e.g., CIS, PCI, NIST)
- Runs only framework-specific rules
- Findings still include compliance mappings across all frameworks

Use `list_compliance_profiles()` to get available profiles and their IDs.
