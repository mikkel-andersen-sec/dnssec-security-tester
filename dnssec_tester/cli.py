"""Command-line interface for DNSSEC Tester."""

import click
import json
import logging
from pathlib import Path
from typing import List

from .tester import DNSSECTester
from .config import DNSSECConfig, TestMode, ReportFormat
from .reporters.json_reporter import JSONReporter
from .reporters.text_reporter import TextReporter
from .reporters.csv_reporter import CSVReporter
from .reporters.html_reporter import HTMLReporter

logger = logging.getLogger(__name__)


class ReportFormatChoice(click.Choice):
    """Custom choice for report formats."""
    pass


@click.group()
@click.version_option()
def cli():
    """DNSSEC Security Tester - Comprehensive DNSSEC validation tool."""
    pass


@cli.command()
@click.argument('domain')
@click.option('--nameserver', '-n', multiple=True, help='Nameserver IP to use (can be used multiple times)')
@click.option('--timeout', '-t', type=int, default=10, help='Query timeout in seconds')
@click.option('--mode', type=click.Choice(['fast', 'comprehensive', 'deep']), default='comprehensive', help='Testing mode')
@click.option('--output', '-o', type=click.Path(), help='Output file path')
@click.option('--report', type=click.Choice(['json', 'csv', 'html', 'text']), default='json', help='Report format')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
@click.option('--follow-chain', is_flag=True, default=True, help='Follow DNSSEC chain')
@click.option('--check-algorithms', is_flag=True, default=True, help='Check algorithm strength')
@click.option('--check-keys', is_flag=True, default=True, help='Check key strength')
def test(domain: str, nameserver: tuple, timeout: int, mode: str, output: str, report: str, verbose: bool, follow_chain: bool, check_algorithms: bool, check_keys: bool):
    """Test a single domain for DNSSEC security.
    
    Example:
        dnssec-tester test example.com
        dnssec-tester test example.com --verbose --output report.json
    """
    
    # Setup logging
    log_level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=log_level)
    
    # Configure tester
    config = DNSSECConfig(
        timeout=timeout,
        nameservers=list(nameserver) if nameserver else ['8.8.8.8', '1.1.1.1'],
        mode=TestMode(mode),
        verbose=verbose,
        follow_chain=follow_chain,
        check_algorithms=check_algorithms,
        check_key_strength=check_keys,
        report_format=ReportFormat(report),
    )
    
    # Run test
    click.echo(f"Testing DNSSEC for {domain}...", err=True)
    tester = DNSSECTester(config)
    result = tester.test_domain(domain)
    
    # Generate report
    if report == 'json':
        reporter = JSONReporter()
        report_text = reporter.generate([result])
    elif report == 'html':
        reporter = HTMLReporter()
        report_text = reporter.generate([result])
    elif report == 'csv':
        reporter = CSVReporter()
        report_text = reporter.generate([result])
    else:
        reporter = TextReporter()
        report_text = reporter.generate([result])
    
    # Output results
    if output:
        Path(output).write_text(report_text)
        click.echo(f"Report saved to {output}", err=True)
    else:
        click.echo(report_text)


@cli.command()
@click.argument('domains_file', type=click.Path(exists=True))
@click.option('--output', '-o', type=click.Path(), help='Output file path')
@click.option('--report', type=click.Choice(['json', 'csv', 'html', 'text']), default='json', help='Report format')
@click.option('--nameserver', '-n', multiple=True, help='Nameserver IP to use')
@click.option('--timeout', '-t', type=int, default=10, help='Query timeout')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
def batch(domains_file: str, output: str, report: str, nameserver: tuple, timeout: int, verbose: bool):
    """Test multiple domains from a file.
    
    File should contain one domain per line.
    
    Example:
        dnssec-tester batch domains.txt --output results.json
    """
    
    log_level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=log_level)
    
    # Load domains
    with open(domains_file, 'r') as f:
        domains = [line.strip() for line in f if line.strip()]
    
    click.echo(f"Testing {len(domains)} domains...", err=True)
    
    # Configure tester
    config = DNSSECConfig(
        timeout=timeout,
        nameservers=list(nameserver) if nameserver else ['8.8.8.8', '1.1.1.1'],
        verbose=verbose,
        report_format=ReportFormat(report),
    )
    
    # Run tests
    tester = DNSSECTester(config)
    results = tester.test_domains(domains)
    
    # Generate report
    if report == 'json':
        reporter = JSONReporter()
        report_text = reporter.generate(results)
    elif report == 'html':
        reporter = HTMLReporter()
        report_text = reporter.generate(results)
    elif report == 'csv':
        reporter = CSVReporter()
        report_text = reporter.generate(results)
    else:
        reporter = TextReporter()
        report_text = reporter.generate(results)
    
    # Output results
    if output:
        Path(output).write_text(report_text)
        click.echo(f"Report saved to {output}", err=True)
    else:
        click.echo(report_text)


def main():
    """Entry point."""
    cli()


if __name__ == '__main__':
    main()
