"""Text format report generator."""

from typing import List
from ..models import ValidationResult, Severity


class TextReporter:
    """Generates human-readable text reports."""
    
    def generate(self, results: List[ValidationResult]) -> str:
        """Generate text report.
        
        Args:
            results: List of validation results
            
        Returns:
            Formatted text report
        """
        lines = []
        lines.append("="*70)
        lines.append("DNSSEC SECURITY TESTER - VALIDATION REPORT")
        lines.append("="*70)
        lines.append("")
        
        for result in results:
            lines.append(f"Domain: {result.domain}")
            lines.append("-" * 70)
            lines.append(f"Timestamp: {result.timestamp.isoformat()}")
            lines.append(f"Status: {result.overall_status.upper()}")
            lines.append(f"DNSSEC Enabled: {'Yes' if result.dnssec_enabled else 'No'}")
            lines.append(f"Chain Valid: {'Yes' if result.chain_valid else 'No'}")
            lines.append(f"Validation Time: {result.validation_time_ms:.2f}ms")
            lines.append("")
            
            if result.security_issues:
                lines.append("Security Issues:")
                for issue in result.security_issues:
                    severity_str = issue.severity.value.upper()
                    lines.append(f"  [{severity_str}] {issue.message}")
                    if issue.details:
                        lines.append(f"    Details: {issue.details}")
                    if issue.remediation:
                        lines.append(f"    Fix: {issue.remediation}")
                lines.append("")
            else:
                lines.append("No security issues detected.")
                lines.append("")
            
            lines.append("")
        
        lines.append("="*70)
        lines.append(f"Total domains: {len(results)}")
        lines.append(f"Secure: {sum(1 for r in results if r.overall_status == 'secure')}")
        lines.append(f"Warnings: {sum(1 for r in results if r.overall_status == 'warnings')}")
        lines.append(f"Vulnerable: {sum(1 for r in results if r.overall_status == 'vulnerable')}")
        lines.append(f"No DNSSEC: {sum(1 for r in results if r.overall_status == 'no_dnssec')}")
        lines.append("="*70)
        
        return "\n".join(lines)
