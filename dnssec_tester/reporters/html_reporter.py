"""HTML format report generator."""

from typing import List
from ..models import ValidationResult


class HTMLReporter:
    """Generates HTML format reports."""
    
    def generate(self, results: List[ValidationResult]) -> str:
        """Generate HTML report.
        
        Args:
            results: List of validation results
            
        Returns:
            HTML formatted report
        """
        html_parts = []
        html_parts.append('''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>DNSSEC Validation Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .report { max-width: 900px; margin: 0 auto; }
        .domain { border: 1px solid #ddd; margin-bottom: 20px; padding: 15px; }
        .status-secure { color: green; font-weight: bold; }
        .status-warning { color: orange; font-weight: bold; }
        .status-critical { color: red; font-weight: bold; }
        .issue { margin-left: 20px; padding: 10px; border-left: 4px solid #ff6b6b; }
        .severity-critical { border-left-color: #c41e3a; }
        .severity-high { border-left-color: #ff6b6b; }
        .severity-medium { border-left-color: #ffa500; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <div class="report">
        <h1>DNSSEC Validation Report</h1>
''')
        
        # Summary table
        secure_count = sum(1 for r in results if r.overall_status == 'secure')
        warning_count = sum(1 for r in results if r.overall_status == 'warnings')
        vulnerable_count = sum(1 for r in results if r.overall_status == 'vulnerable')
        no_dnssec_count = sum(1 for r in results if r.overall_status == 'no_dnssec')
        
        html_parts.append(f'''
        <h2>Summary</h2>
        <table>
            <tr>
                <th>Total Domains</th>
                <th>Secure</th>
                <th>Warnings</th>
                <th>Vulnerable</th>
                <th>No DNSSEC</th>
            </tr>
            <tr>
                <td>{len(results)}</td>
                <td class="status-secure">{secure_count}</td>
                <td class="status-warning">{warning_count}</td>
                <td class="status-critical">{vulnerable_count}</td>
                <td>{no_dnssec_count}</td>
            </tr>
        </table>
''')
        
        # Details for each domain
        html_parts.append('<h2>Domain Details</h2>')
        
        for result in results:
            status_class = f"status-{result.overall_status.replace('_', '-')}"
            html_parts.append(f'''
        <div class="domain">
            <h3>{result.domain}</h3>
            <p><strong>Status:</strong> <span class="{status_class}">{result.overall_status}</span></p>
            <p><strong>DNSSEC Enabled:</strong> {'Yes' if result.dnssec_enabled else 'No'}</p>
            <p><strong>Chain Valid:</strong> {'Yes' if result.chain_valid else 'No'}</p>
            <p><strong>Validation Time:</strong> {result.validation_time_ms:.2f}ms</p>
''')
            
            if result.security_issues:
                html_parts.append('<h4>Security Issues:</h4>')
                for issue in result.security_issues:
                    severity_class = f"severity-{issue.severity.value}"
                    html_parts.append(f'''
            <div class="issue {severity_class}">
                <strong>[{issue.severity.value.upper()}]</strong> {issue.message}
''')
                    if issue.details:
                        html_parts.append(f'<p>Details: {issue.details}</p>')
                    if issue.remediation:
                        html_parts.append(f'<p>Remediation: {issue.remediation}</p>')
                    html_parts.append('</div>')
            else:
                html_parts.append('<p style="color: green;">No security issues detected.</p>')
            
            html_parts.append('</div>')
        
        html_parts.append('''
    </div>
</body>
</html>
''')
        
        return ''.join(html_parts)
