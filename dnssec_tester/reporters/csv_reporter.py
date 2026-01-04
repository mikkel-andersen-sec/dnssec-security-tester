"""CSV format report generator."""

import csv
from io import StringIO
from typing import List
from ..models import ValidationResult


class CSVReporter:
    """Generates CSV format reports."""
    
    def generate(self, results: List[ValidationResult]) -> str:
        """Generate CSV report.
        
        Args:
            results: List of validation results
            
        Returns:
            CSV formatted report
        """
        output = StringIO()
        
        fieldnames = [
            'domain',
            'timestamp',
            'status',
            'dnssec_enabled',
            'chain_valid',
            'validation_time_ms',
            'critical_issues',
            'high_issues',
            'medium_issues',
            'issue_summary',
        ]
        
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        
        for result in results:
            critical = sum(1 for i in result.security_issues if i.severity.value == 'critical')
            high = sum(1 for i in result.security_issues if i.severity.value == 'high')
            medium = sum(1 for i in result.security_issues if i.severity.value == 'medium')
            
            issue_summary = ', '.join([i.message[:50] for i in result.security_issues[:3]])
            
            writer.writerow({
                'domain': result.domain,
                'timestamp': result.timestamp.isoformat(),
                'status': result.overall_status,
                'dnssec_enabled': result.dnssec_enabled,
                'chain_valid': result.chain_valid,
                'validation_time_ms': f"{result.validation_time_ms:.2f}",
                'critical_issues': critical,
                'high_issues': high,
                'medium_issues': medium,
                'issue_summary': issue_summary,
            })
        
        return output.getvalue()
