#!/usr/bin/env python3
"""
VERA - Live Credential Scanner
Find and validate exposed secrets before attackers do.
"""

import click
import sys
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from datetime import datetime

# Local imports
from core.patterns import SecretPatterns
from scanners.aws_validator import AWSValidator
from scanners.stripe_validator import StripeValidator
from scanners.github_scanner import GitHubScanner
from core.reporter import ReportGenerator

console = Console()

@click.group()
@click.version_option(version="0.1.0")
def cli():
    """VERA - Find and validate exposed secrets before attackers do."""
    pass

@cli.command()
@click.argument('path', type=click.Path(exists=True), default='.')
@click.option('--output', '-o', type=click.Path(), help='Output report file')
@click.option('--json', is_flag=True, help='Output as JSON')
@click.option('--validate', is_flag=True, default=True, help='Validate found secrets')
def scan(path, output, json, validate):
    """Scan a directory or file for exposed secrets."""
    
    console.print(Panel.fit(
        "[bold cyan]🔍 VERA - Live Credential Scanner[/bold cyan]\n"
        "Finding and validating exposed secrets",
        border_style="cyan"
    ))
    
    try:
        scanner = VERA(validate=validate)
        results = scanner.scan_path(path)
        
        if json:
            reporter = ReportGenerator()
            reporter.save_json(results, output or 'vera_report.json')
            console.print(f"[green]✓[/green] JSON report saved to {output or 'vera_report.json'}")
        else:
            display_results(results, output)
            
    except Exception as e:
        console.print(f"[red]✗ Error: {e}[/red]")
        sys.exit(1)

@cli.command()
@click.argument('url')
def github(url):
    """Scan a GitHub repository."""
    # Implementation for GitHub scanning
    pass

@cli.command()
@click.argument('key')
def validate(key):
    """Validate a single secret key."""
    console.print(Panel.fit(
        f"[bold]Validating:[/bold] {key[:10]}...{key[-4:]}",
        border_style="yellow"
    ))
    
    if key.startswith('AKIA'):
        validator = AWSValidator()
        result = validator.validate(key)
    elif key.startswith('sk_live'):
        validator = StripeValidator()
        result = validator.validate(key)
    else:
        console.print("[yellow]⚠ Unknown key type[/yellow]")
        return
    
    console.print(f"[bold]Status:[/bold] {result['status']}")
    if result.get('details'):
        console.print(f"[bold]Details:[/bold] {result['details']}")

def display_results(results, output_file=None):
    """Display results in a beautiful format."""
    
    # Summary panel
    total = len(results['findings'])
    critical = len([f for f in results['findings'] if f.get('severity') == 'critical'])
    
    console.print(Panel.fit(
        f"[bold]Scan Complete[/bold]\n"
        f"📁 Files: {results['scanned_files']}\n"
        f"🔍 Findings: {total}\n"
        f"🚨 Critical: {critical}",
        border_style="green" if critical == 0 else "red"
    ))
    
    if critical > 0:
        # Critical findings table
        table = Table(title="🚨 Critical Findings - Immediate Action Required", 
                     border_style="red")
        table.add_column("File", style="cyan")
        table.add_column("Type", style="yellow")
        table.add_column("Status", style="bold red")
        table.add_column("Line", justify="right")
        
        for finding in results['findings'][:10]:  # Show top 10
            if finding.get('severity') == 'critical':
                table.add_row(
                    finding['file'][-40:],
                    finding['type'],
                    finding.get('validation', {}).get('status', 'UNKNOWN'),
                    str(finding['line'])
                )
        
        console.print(table)
        
        # Remediation steps
        console.print(Panel(
            "[bold]💡 Immediate Actions:[/bold]\n"
            "1. Revoke the exposed credentials immediately\n"
            "2. Check access logs for suspicious activity\n"
            "3. Rotate all related credentials\n"
            "4. Enable MFA for all accounts",
            title="Remediation",
            border_style="yellow"
        ))
    
    # Save report if requested
    if output_file:
        reporter = ReportGenerator()
        reporter.save_html(results, output_file)
        console.print(f"[green]✓[/green] Report saved to {output_file}")

class VERA:
    """Main VERA scanner class."""
    
    def __init__(self, validate=True):
        self.patterns = SecretPatterns()
        self.validate = validate
        self.aws_validator = AWSValidator() if validate else None
        self.stripe_validator = StripeValidator() if validate else None
        
    def scan_path(self, path):
        """Scan a path (file or directory)."""
        path = Path(path)
        findings = []
        scanned_files = 0
        
        if path.is_file():
            files = [path]
        else:
            files = list(path.rglob('*'))
        
        for file_path in files:
            if self._should_scan(file_path):
                try:
                    content = file_path.read_text(encoding='utf-8', errors='ignore')
                    file_findings = self.scan_content(str(file_path), content)
                    findings.extend(file_findings)
                    scanned_files += 1
                except Exception as e:
                    console.print(f"[yellow]⚠ Skipping {file_path}: {e}[/yellow]")
        
        return {
            'scan_time': datetime.utcnow().isoformat(),
            'scanned_files': scanned_files,
            'findings': findings,
            'summary': self._generate_summary(findings)
        }
    
    def scan_content(self, file_path, content):
        """Scan content for secrets."""
        findings = []
        
        for pattern_name, pattern in self.patterns.get_patterns().items():
            for match in pattern.finditer(content):
                finding = self._create_finding(file_path, content, pattern_name, match)
                if self.validate:
                    finding = self._validate_finding(finding)
                findings.append(finding)
        
        return findings
    
    def _create_finding(self, file_path, content, pattern_name, match):
        """Create a finding object."""
        line_num = content.count('\n', 0, match.start()) + 1
        secret = match.group(0)
        
        return {
            'file': file_path,
            'line': line_num,
            'type': pattern_name,
            'secret': self._mask_secret(secret),
            'full_secret': secret,
            'context': self._get_context(content, line_num),
            'severity': 'unknown',
            'validation': None
        }
    
    def _validate_finding(self, finding):
        """Validate a finding."""
        secret = finding['full_secret']
        
        if finding['type'] == 'AWS_ACCESS_KEY':
            # Look for matching secret key in context
            secret_key_pattern = self.patterns.get_pattern('AWS_SECRET_KEY')
            if secret_key_pattern:
                secret_key_match = secret_key_pattern.search(finding['context'])
                if secret_key_match:
                    if self.aws_validator:
                        result = self.aws_validator.validate_pair(
                            secret, 
                            secret_key_match.group(0)
                        )
                        finding['validation'] = result
                        finding['severity'] = 'critical' if result.get('valid') else 'low'
        elif finding['type'] == 'STRIPE_LIVE_KEY':
            if self.stripe_validator:
                result = self.stripe_validator.validate(secret)
                finding['validation'] = result
                finding['severity'] = 'critical' if result.get('valid') else 'medium'
        
        return finding
    
    def _should_scan(self, file_path):
        """Check if file should be scanned."""
        # Skip binary files, images, etc.
        extensions = {'.py', '.js', '.ts', '.java', '.go', '.php', '.rb', 
                     '.cpp', '.c', '.h', '.json', '.yaml', '.yml', '.env',
                     '.toml', '.txt', '.md', '.sh', '.bash', '.tf', '.xml'}
        return file_path.suffix in extensions
    
    def _mask_secret(self, secret):
        """Mask secret for display."""
        if len(secret) <= 8:
            return '***'
        return secret[:4] + '*' * (len(secret) - 8) + secret[-4:]
    
    def _get_context(self, content, line_num, context_lines=3):
        """Get context around the finding."""
        lines = content.split('\n')
        start = max(0, line_num - context_lines - 1)
        end = min(len(lines), line_num + context_lines)
        return '\n'.join(lines[start:end])
    
    def _generate_summary(self, findings):
        """Generate summary statistics."""
        critical = len([f for f in findings if f.get('severity') == 'critical'])
        return f"Found {len(findings)} potential secrets, {critical} critical"

if __name__ == '__main__':
    cli()
