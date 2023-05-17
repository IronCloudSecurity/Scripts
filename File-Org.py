import boto3
import json

def lambda_handler(event, context):
    # Extract the S3 bucket and object key from the event
    s3_bucket = event['Records'][0]['s3']['bucket']['name']
    s3_object_key = event['Records'][0]['s3']['object']['key']
    
    # Create an S3 client
    s3_client = boto3.client('s3')
    
    # Download the CloudTrail log file from S3
    response = s3_client.get_object(Bucket=s3_bucket, Key=s3_object_key)
    log_data = response['Body'].read().decode('utf-8')
    
    # Process the CloudTrail log file
    parsed_logs = json.loads(log_data)
    
    for log_entry in parsed_logs['Records']:
        # Extract relevant information from each log entry
        event_name = log_entry['eventName']
        user_agent = log_entry['userAgent']
        source_ip = log_entry['sourceIPAddress']
        
        # Perform threat detection logic based on the extracted information
        if event_name == 'PutObject' and 'malicious' in user_agent.lower():
            # Potential threat detected: Example - malicious user agent used in S3 PutObject API call
            print(f'Potential threat detected: Malicious user agent "{user_agent}" used in S3 PutObject API call')
        
        if event_name == 'StartInstances' and source_ip == '10.0.0.1':
            # Potential threat detected: Example - EC2 instance start API called from a specific IP address
            print(f'Potential threat detected: EC2 instance start API called from IP address {source_ip}')
        
    # Return a response indicating successful execution
    return {
        'statusCode': 200,
        'body': 'Lambda function executed successfully'
    }


def create_guardduty_finding(severity, description, resource_arn):
    guardduty_client = boto3.client('guardduty')

    response = guardduty_client.create_findings(
        DetectorId='84c412c4b583c3641450f45d790b1577',
        FindingTypes=['UnusualBehaviors:EC2/SSHBruteForce'],
        Severity="High",
        Description=Description,
        Resource={ 'arn:aws:logs:us-east-2:952514564423:log-group:aws-cloudtrail-logs3:*': resource_arn }
    )
    return response
