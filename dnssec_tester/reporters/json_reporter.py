"""JSON report generator."""

import json
from typing import List
from ..models import ValidationResult


class JSONReporter:
    """Generates JSON format reports."""
    
    def generate(self, results: List[ValidationResult]) -> str:
        """Generate JSON report.
        
        Args:
            results: List of validation results
            
        Returns:
            JSON formatted report
        """
        data = {
            'results': [result.to_dict() for result in results],
            'summary': {
                'total_domains': len(results),
                'secure_domains': sum(1 for r in results if r.overall_status == 'secure'),
                'domains_with_warnings': sum(1 for r in results if r.overall_status == 'warnings'),
                'vulnerable_domains': sum(1 for r in results if r.overall_status == 'vulnerable'),
                'no_dnssec': sum(1 for r in results if r.overall_status == 'no_dnssec'),
            }
        }
        return json.dumps(data, indent=2, default=str)
