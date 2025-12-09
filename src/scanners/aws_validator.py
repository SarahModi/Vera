import boto3
from botocore.exceptions import ClientError
import time

class AWSValidator:
    """Validate AWS credentials."""
    
    def __init__(self):
        self.services_to_test = ['sts', 's3', 'iam']
    
    def validate_pair(self, access_key, secret_key):
        """Validate AWS key pair."""
        result = {
            'valid': False,
            'status': 'unknown',
            'details': {},
            'timestamp': time.time()
        }
        
        try:
            # Test with STS first
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name='us-east-1'
            )
            
            sts = session.client('sts')
            identity = sts.get_caller_identity()
            
            result['valid'] = True
            result['status'] = 'ACTIVE'
            result['details'] = {
                'account_id': identity['Account'],
                'user_arn': identity['Arn'],
                'user_id': identity['UserId']
            }
            
            # Test permissions
            permissions = self._test_permissions(session)
            result['details']['permissions'] = permissions
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            
            if error_code == 'InvalidClientTokenId':
                result['status'] = 'INVALID_ACCESS_KEY'
            elif error_code == 'SignatureDoesNotMatch':
                result['status'] = 'INVALID_SECRET_KEY'
            elif error_code == 'AccessDenied':
                result['status'] = 'ACCESS_DENIED'
                result['details'] = {'reason': 'Key valid but insufficient permissions'}
            elif error_code == 'ExpiredToken':
                result['status'] = 'EXPIRED'
            else:
                result['status'] = f'ERROR: {error_code}'
        
        except Exception as e:
            result['status'] = f'ERROR: {str(e)}'
        
        return result
    
    def _test_permissions(self, session):
        """Test what permissions the key has."""
        permissions = {}
        
        try:
            # Test S3 access
            s3 = session.client('s3')
            buckets = s3.list_buckets()
            permissions['s3_list'] = len(buckets.get('Buckets', [])) > 0
        except:
            permissions['s3_list'] = False
        
        try:
            # Test IAM access
            iam = session.client('iam')
            iam.get_user()
            permissions['iam_read'] = True
        except:
            permissions['iam_read'] = False
        
        return permissions
