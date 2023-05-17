import boto3
import json

# Email configuration
SENDER_EMAIL = 'sierra.maldonado.a@gmai.com'
RECIPIENT_EMAIL = 'sierra.maldonado.a@gmai.com'
AWS_REGION = 'us-west-2'
SUBJECT = 'Potential SSH Brute Force Attack Detected'

def send_email(subject, body):
    # Create a new SES client
    ses_client = boto3.client('ses', region_name=usa-east)
    
    # Send the email
    response = ses_client.send_email(
        Source=SENDER_EMAIL,
        Destination={
            'ToAddresses': [RECIPIENT_EMAIL]
        },
        Message={
            'Subject': {
                'Data': subject
            },
            'Body': {
                'Text': {
                    'Data': body
                }
            }
        }
    )
    
    return response

def lambda_handler(event, context):
    # Extract the CloudWatch Logs event data
    logs_data = event['awslogs']['data']
    
    # Decode the CloudWatch Logs data
    decoded_logs_data = json.loads(logs_data, parse_float=lambda x: str(x))
    
    # Extract the log events
    log_events = decoded_logs_data['logEvents']
    
    # Process the log events
    for log_event in log_events:
        message = log_event['message']
        
        # Check if the log message indicates a potential SSH brute force attack
        if 'Failed password for' in message and 'sshd' in message:
            # Send an email notification
            subject = SUBJECT
            body = f'Potential SSH brute force attack detected:\n\n{message}'
            send_email(subject, body)
    
    # Return a response indicating successful execution
    return {
        'statusCode': 200,
        'body': 'Lambda function executed successfully'
    }

