import requests
import time

class StripeValidator:
    """Validate Stripe API keys."""
    
    def validate(self, api_key):
        """Validate Stripe API key."""
        result = {
            'valid': False,
            'status': 'unknown',
            'details': {},
            'timestamp': time.time()
        }
        
        headers = {
            'Authorization': f'Bearer {api_key}'
        }
        
        try:
            # Try to get balance (requires read access)
            response = requests.get(
                'https://api.stripe.com/v1/balance',
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                result['valid'] = True
                result['status'] = 'LIVE_MODE' if api_key.startswith('sk_live') else 'TEST_MODE'
                result['details'] = {
                    'available': data.get('available', []),
                    'pending': data.get('pending', []),
                    'livemode': data.get('livemode', False)
                }
            elif response.status_code == 401:
                result['status'] = 'INVALID_KEY'
            else:
                result['status'] = f'HTTP_{response.status_code}'
                
        except requests.exceptions.Timeout:
            result['status'] = 'TIMEOUT'
        except Exception as e:
            result['status'] = f'ERROR: {str(e)}'
        
        return result
