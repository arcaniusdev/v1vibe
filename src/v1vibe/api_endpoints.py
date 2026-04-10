"""Vision One API endpoint constants.

Centralizes all API endpoint paths for easier version migration and maintenance.
Endpoints are organized by API version and functional area.
"""

# v3.0 API Endpoints

# Sandbox Analysis
SANDBOX_SUBMIT_FILE = "/v3.0/sandbox/files/analyze"
SANDBOX_SUBMIT_URL = "/v3.0/sandbox/urls/analyze"
SANDBOX_GET_TASK = "/v3.0/sandbox/tasks/{task_id}"
SANDBOX_GET_RESULT = "/v3.0/sandbox/analysisResults/{result_id}"
SANDBOX_GET_SUSPICIOUS_OBJECTS = "/v3.0/sandbox/analysisResults/{result_id}/suspiciousObjects"
SANDBOX_GET_REPORT = "/v3.0/sandbox/analysisResults/{result_id}/report"
SANDBOX_GET_QUOTA = "/v3.0/sandbox/submissionUsage"

# Threat Intelligence
THREAT_INTEL_FEED = "/v3.0/threatintel/feedIndicators"
THREAT_INTEL_SUSPICIOUS_OBJECTS = "/v3.0/threatintel/suspiciousObjects"

# AI Security
AI_GUARD_EVALUATE = "/v3.0/aiSecurity/applyGuardrails"

# Vulnerability Management
VULNERABILITY_GET_CVE = "/v3.0/asrm/vulnerabilities/{cve_id}"

# Beta API Endpoints

# Cloud Posture (IaC Security)
IAC_GET_COMPLIANCE_STANDARDS = "/beta/cloudPosture/complianceStandards"
IAC_GET_PROFILES = "/beta/cloudPosture/profiles"
IAC_SCAN_TEMPLATE = "/beta/cloudPosture/scanTemplate"
IAC_SCAN_ARCHIVE = "/beta/cloudPosture/scanTemplateArchive"
