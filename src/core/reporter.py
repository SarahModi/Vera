import json
from datetime import datetime
from pathlib import Path

class ReportGenerator:
    """Generate various report formats."""
    
    def save_json(self, results, filename):
        """Save results as JSON."""
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2, default=str)
    
    def save_html(self, results, filename):
        """Generate HTML report."""
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>VERA Security Scan Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .critical {{ color: #dc3545; font-weight: bold; }}
                .warning {{ color: #ffc107; }}
                .safe {{ color: #28a745; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <h1>🔍 VERA Security Scan Report</h1>
            <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            
            <h2>Summary</h2>
            <p>Scanned Files: {results['scanned_files']}</p>
            <p>Total Findings: {len(results['findings'])}</p>
            
            <h2>Findings</h2>
            <table>
                <tr>
                    <th>File</th>
                    <th>Type</th>
                    <th>Severity</th>
                    <th>Status</th>
                    <th>Line</th>
                </tr>
        """
        
        for finding in results['findings']:
            severity_class = {
                'critical': 'critical',
                'high': 'critical',
                'medium': 'warning',
                'low': 'safe'
            }.get(finding.get('severity', 'low'), 'safe')
            
            html += f"""
                <tr>
                    <td>{finding['file']}</td>
                    <td>{finding['type']}</td>
                    <td class="{severity_class}">{finding.get('severity', 'unknown')}</td>
                    <td>{finding.get('validation', {}).get('status', 'Not validated')}</td>
                    <td>{finding['line']}</td>
                </tr>
            """
        
        html += """
            </table>
        </body>
        </html>
        """
        
        with open(filename, 'w') as f:
            f.write(html)
