from backend.agents.base_agent import BaseAgent
from backend.database.tigergraph_client import TigerGraphClient


class RCAAgent(BaseAgent):
    def __init__(self):
        super().__init__()
        self.tg = TigerGraphClient()

    def generate_rca(self, incident_id: str) -> dict:
        """
        Generate root cause analysis report for an incident.
        """
        incident = self.tg.get_incident_by_id(incident_id)
        if not incident:
            return {"error": f"Incident {incident_id} not found"}

        asset_info = self.tg.get_incident_asset(incident_id)
        
        if asset_info:
            asset_id = asset_info.get("asset_id")
            vulnerabilities = self.tg.get_asset_vulnerabilities(asset_id)
            threat_actors = self.tg.get_threat_actors_targeting(asset_id)
            connections = self.tg.get_asset_connections(asset_id, direction="both")
        else:
            asset_id = None
            vulnerabilities = []
            threat_actors = []
            connections = []

        # Calculate severity
        severity = self._calculate_incident_severity(incident, vulnerabilities)

        prompt = self._build_prompt(
            incident, asset_info, vulnerabilities, threat_actors, connections, severity
        )

        report = self._call_llm(prompt, temperature=0.2)

        # Extract key findings for structured output
        key_findings = self._extract_key_findings(report)

        return {
            "incident": incident,
            "affected_asset": asset_info,
            "severity": severity["level"],
            "severity_score": severity["score"],
            "vulnerabilities_involved": [v for v in vulnerabilities if not v.get("is_patched")],
            "suspected_threat_actors": threat_actors,
            "key_findings": key_findings,
            "root_cause_analysis": report
        }

    def _build_prompt(self, incident, asset_info, vulnerabilities, threat_actors, connections, severity):
        """Build production-grade RCA prompt"""

        # Format vulnerabilities
        vuln_text = "None found"
        if vulnerabilities:
            vuln_list = []
            for v in vulnerabilities:
                patched = "✅ Patched" if v.get("is_patched") else "❌ UNPATCHED"
                vuln_list.append(
                    f"- **{v.get('cve_id')}**: CVSS {v.get('cvss_score')} - {v.get('name')} [{patched}]"
                )
            vuln_text = "\n".join(vuln_list)

        # Format threat actors
        threat_text = "No known threat actors target this asset type"
        if threat_actors:
            threat_list = []
            for ta in threat_actors:
                threat_list.append(
                    f"- **{ta.get('name')}**: {ta.get('motivation')} (Tools: {ta.get('known_tools', 'Unknown')})"
                )
            threat_text = "\n".join(threat_list)

        # Format connections
        conn_text = "No connection data available"
        if connections:
            conn_list = []
            for conn in connections[:5]:
                conn_list.append(f"- {conn.get('connected_asset')} (port {conn.get('port')})")
            conn_text = "\n".join(conn_list)

        return f"""
You are a senior forensic investigator and incident responder at a major bank. Write a Root Cause Analysis (RCA) report.

## INCIDENT DETAILS

| Field | Value |
|-------|-------|
| **Incident ID** | {incident.get('incident_id')} |
| **Timestamp** | {incident.get('timestamp')} |
| **Attack Type** | {incident.get('attack_type')} |
| **Description** | {incident.get('description')} |
| **Severity** | {severity['level']} (Score: {severity['score']}/100) |

## AFFECTED ASSET

| Field | Value |
|-------|-------|
| **Name** | {asset_info.get('name') if asset_info else 'Unknown'} |
| **IP** | {asset_info.get('ip') if asset_info else 'Unknown'} |
| **Type** | {asset_info.get('asset_type') if asset_info else 'Unknown'} |
| **OS** | {asset_info.get('os') if asset_info else 'Unknown'} |
| **Critical** | {'Yes' if asset_info and asset_info.get('is_critical') else 'No'} |

## VULNERABILITIES ON AFFECTED ASSET
{vuln_text}

## THREAT ACTORS TARGETING THIS ASSET TYPE
{threat_text}

## NETWORK CONNECTIONS (Limited view)
{conn_text}

## INSTRUCTIONS

Write a professional RCA report with EXACTLY these 5 sections. Use the section headers as shown.

### 1. EXECUTIVE SUMMARY

Write 2-3 sentences for management:
- What happened in plain English
- The root cause in one sentence
- Whether customer data was affected

### 2. TIMELINE OF EVENTS

Create a numbered timeline of key events:
1. Initial compromise (how and when)
2. Detection (how the incident was found)
3. Containment (when it was stopped)
4. Eradication (when root cause was removed)

### 3. TECHNICAL ROOT CAUSE

Answer these questions:
- Which vulnerability or misconfiguration was exploited?
- Was this a known issue? If yes, why wasn't it patched?
- What security control failed?
- Provide evidence from the data above

### 4. IMPACT ASSESSMENT

Answer these questions:
- What data was accessed or exposed?
- What systems were affected?
- Business impact (operational, financial, reputational)
- Were customers affected?

### 5. RECOMMENDED FIXES

Provide SPECIFIC, ACTIONABLE fixes:
- Immediate fixes (patch commands, config changes)
- Long-term improvements (process changes, additional controls)
- How to verify each fix worked

## CRITICAL RULES

1. **NO hallucinations.** Only use the data provided above.
2. **NO placeholders.** If data is missing, state "No data available".
3. **Be specific.** Use actual CVE IDs, asset names, and timestamps from the data.
4. **No technical jargon without explanation.**
5. **Return ONLY markdown.** No text before or after the 5 sections.
6. **Keep executive summary short.** Management will read this first.

Now generate the RCA report:
"""

    def _calculate_incident_severity(self, incident, vulnerabilities):
        """Calculate incident severity score"""
        score = 0

        # Attack type severity
        attack_type = incident.get('attack_type', '').lower()
        if attack_type == 'ransomware':
            score += 35
        elif attack_type == 'exploit':
            score += 30
        elif attack_type == 'phishing':
            score += 25
        elif attack_type == 'misconfiguration':
            score += 20
        elif attack_type == 'insider':
            score += 30
        elif attack_type == 'ddos':
            score += 15
        else:
            score += 20

        # Vulnerability severity
        if vulnerabilities:
            unpatched_cvss = [v.get('cvss_score', 0) for v in vulnerabilities if not v.get('is_patched')]
            if unpatched_cvss:
                avg_cvss = sum(unpatched_cvss) / len(unpatched_cvss)
                score += min(avg_cvss * 3, 40)

        # Determine level
        if score >= 70:
            level = "CRITICAL"
        elif score >= 50:
            level = "HIGH"
        elif score >= 30:
            level = "MEDIUM"
        elif score >= 15:
            level = "LOW"
        else:
            level = "INFO"

        return {"level": level, "score": min(int(score), 100)}

    def _extract_key_findings(self, report: str) -> list:
        """Extract key findings from the RCA report"""
        findings = []
        lines = report.split('\n')
        
        for line in lines:
            line_lower = line.lower()
            # Look for sentences that indicate root cause
            if 'root cause' in line_lower or 'because' in line_lower or 'due to' in line_lower:
                clean_line = line.strip()
                # Remove markdown formatting
                clean_line = clean_line.replace('**', '').replace('###', '').strip()
                if clean_line and len(clean_line) < 200:
                    findings.append(clean_line)
        
        # If no findings extracted, provide default
        if not findings:
            findings = ["Review the full RCA report for detailed findings"]
        
        return findings[:3]
