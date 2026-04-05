from backend.agents.base_agent import BaseAgent
from backend.database.tigergraph_client import TigerGraphClient


class RemediatorAgent(BaseAgent):
    def __init__(self):
        super().__init__()
        self.tg = TigerGraphClient()

    def generate_playbook(self, asset_id: str, incident_context: str = None) -> dict:
        """
        Generate remediation playbook for a vulnerable asset.
        """

        asset = self.tg.get_asset_by_id(asset_id)
        if not asset:
            return {"error": f"Asset {asset_id} not found"}

        vulnerabilities = self.tg.get_asset_vulnerabilities(asset_id)
        unpatched = [v for v in vulnerabilities if not v.get("is_patched")]

        if not unpatched:
            return {
                "asset": asset,
                "message": "No unpatched vulnerabilities found on this asset.",
                "playbook": "No immediate remediation required. Continue regular patch management.",
                "severity": "LOW"
            }

        # Severity calculation
        avg_cvss = sum(v.get("cvss_score", 0) for v in unpatched) / len(unpatched)
        highest_cvss = max(v.get("cvss_score", 0) for v in unpatched)

        if avg_cvss >= 9.0 or highest_cvss >= 9.8:
            severity = "CRITICAL"
        elif avg_cvss >= 7.0 or highest_cvss >= 8.0:
            severity = "HIGH"
        elif avg_cvss >= 4.0:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        prompt = self._build_prompt(asset, unpatched, incident_context, severity)

        playbook = self._call_llm(prompt, temperature=0.1)

        return {
            "asset": asset,
            "severity": severity,
            "unpatched_vulnerabilities": unpatched,
            "playbook": playbook
        }

    def _build_prompt(self, asset, unpatched, incident_context, severity):
        """Build production-grade remediation prompt"""

        # Format vulnerabilities
        vuln_list = []
        for v in unpatched:
            cvss = v.get('cvss_score', 0)
            cve = v.get('cve_id')
            name = v.get('name', 'Unknown')
            desc = v.get('description', 'No description')[:150]

            if cvss >= 9.0:
                exploit = "REMOTE CODE EXECUTION - EXPLOIT PUBLIC"
            elif cvss >= 7.0:
                exploit = "PRIVILEGE ESCALATION - EXPLOIT LIKELY"
            elif cvss >= 4.0:
                exploit = "INFORMATION DISCLOSURE - EXPLOIT POSSIBLE"
            else:
                exploit = "LIMITED IMPACT - LOW PRIORITY"

            vuln_list.append(
                f"**{cve}: {name}**\n"
                f"- CVSS: {cvss} | {exploit}\n"
                f"- Description: {desc}\n"
                f"- Discovered: {v.get('discovered_date', 'Unknown')}"
            )

        vulns_text = "\n\n".join(vuln_list)

        # OS detection
        os_type = asset.get('os', 'Linux').lower()

        if 'ubuntu' in os_type or 'debian' in os_type:
            package_manager = "apt"
            shell = "bash"
        elif 'rhel' in os_type or 'centos' in os_type or 'red hat' in os_type:
            package_manager = "yum"
            shell = "bash"
        elif 'windows' in os_type or 'win' in os_type:
            package_manager = "winget"
            shell = "powershell"
        else:
            package_manager = "appropriate package manager"
            shell = "bash"

        # Incident context
        incident_note = ""
        if incident_context:
            incident_note = f"""
**ACTIVE INCIDENT DETECTED**

Context: {incident_context}

**CRITICAL:** This is an ACTIVE breach. Prioritize CONTAINMENT over eradication. Assume attacker has persistent access.
"""

        return f"""
You are a senior incident responder. Create a remediation playbook.

{incident_note}

## ASSET INFORMATION
- Name: {asset.get('name')}
- IP: {asset.get('ip')}
- Type: {asset.get('asset_type')}
- OS: {asset.get('os')}
- Critical: {'Yes' if asset.get('is_critical') else 'No'}
- Severity: {severity}

## VULNERABILITIES TO FIX
{vulns_text}

## ENVIRONMENT
- OS Family: {os_type}
- Package Manager: {package_manager}
- Shell: {shell}

## INSTRUCTIONS

Create a remediation playbook with EXACTLY these 5 sections.

### SECTION 1: CONTAINMENT (Execute immediately)
- Network isolation
- Process discovery + termination
- Service disablement

### SECTION 2: ERADICATION
- Patch vulnerabilities
- Harden configurations
- Remove malware

### SECTION 3: RECOVERY
- Restart services
- Restore network
- Verify integrity

### SECTION 4: VERIFICATION
- Check patches
- Test vulnerability removal
- Analyze logs

### SECTION 5: ROLLBACK
- Undo all major changes safely

## CRITICAL RULES

1. NO explanations outside these sections.
2. DO NOT hallucinate unknown values (PIDs, IPs, paths).
3. Use dynamic discovery commands:
   - Linux: ps aux, netstat, ss, lsof
   - Windows: Get-Process, Get-NetTCPConnection
4. Mark destructive commands with "# WARNING:"
5. Use OS-specific logging:
   - Linux:
     echo "$(date +'%Y-%m-%d %H:%M:%S') - Step X" >> /var/log/remediation.log
   - Windows:
     Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - Step X" >> C:\\Logs\\remediation.log
6. Return ONLY markdown.

7. Every command block must:
   - Log BEFORE execution
   - Execute the command
   - Log SUCCESS or FAILURE using exit status

8. Steps must be sequential and logically ordered (discovery → action → validation)

9. Every section MUST contain at least 2 actionable steps with commands

Now generate the playbook:
"""
