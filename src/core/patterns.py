import re

class SecretPatterns:
    """Collection of secret patterns with validation."""
    
    def __init__(self):
        self.patterns = {
            'AWS_ACCESS_KEY': re.compile(r'AKIA[0-9A-Z]{16}'),
            'AWS_SECRET_KEY': re.compile(r'(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])'),
            'AWS_SESSION_TOKEN': re.compile(r'(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{356,}(?![A-Za-z0-9/+=])'),
            'STRIPE_LIVE_KEY': re.compile(r'sk_live_[0-9a-zA-Z]{24}'),
            'STRIPE_TEST_KEY': re.compile(r'sk_test_[0-9a-zA-Z]{24}'),
            'GITHUB_TOKEN': re.compile(r'(ghp|github_pat)_[0-9a-zA-Z]{36,}'),
            'SLACK_WEBHOOK': re.compile(r'https://hooks\.slack\.com/services/T[0-9A-Z]{8}/B[0-9A-Z]{8}/[0-9A-Z]{24}'),
            'DISCORD_WEBHOOK': re.compile(r'https://discord(?:app)?\.com/api/webhooks/[0-9]{18,19}/[a-zA-Z0-9_-]{68}'),
            'TWILIO_KEY': re.compile(r'SK[0-9a-fA-F]{32}'),
            'SENDGRID_KEY': re.compile(r'SG\.[0-9a-zA-Z\-_]{22}\.[0-9a-zA-Z\-_]{43}'),
            'DATABASE_URL': re.compile(r'postgres(?:ql)?://[^:@]+:[^:@]+@[^/@]+/[^?\s]+'),
            'JWT_SECRET': re.compile(r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}')
        }
    
    def get_pattern(self, name):
        """Get specific pattern by name."""
        return self.patterns.get(name)
    
    def get_patterns(self):
        """Get all patterns."""
        return self.patterns
    
    def add_custom_pattern(self, name, pattern):
        """Add custom pattern."""
        self.patterns[name] = re.compile(pattern)
