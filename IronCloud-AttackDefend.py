import boto3

def lambda_handler(event, context):
    # Extract GuardDuty finding details from the event
    finding = event['detail']

    # Extract relevant information from the finding
    severity = finding['severity']
    title = finding['title']
    description = finding['description']
    accountId = finding['accountId']
    
    # Prepare the email subject and body
    subject = f"GuardDuty Finding: {title} (Severity: {severity})"
    body = f"GuardDuty has detected a finding with the following details:\n\n"
    body += f"Title: {title}\n"
    body += f"Description: {description}\n"
    body += f"Account ID: {accountId}\n"
    
    # Specify the recipient email address
    recipient_email = "maldonado.sierra.a@gmail.com"

    # Create the SES client
    ses_client = boto3.client('ses')

    # Send the email
    try:
        response = ses_client.send_email(
            Source="maldonado.sierra.a@gmail.com",
            Destination={
                'ToAddresses': [recipient_email]
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
        print(f"Email sent successfully to {recipient_email}")
    except Exception as e:
        print(f"Error sending email: {str(e)}")

    # Process VPC Flow Logs
    vpc_flow_logs = event['Records']
    
    # Process each VPC Flow Log entry
    for log in vpc_flow_logs:
        # Extract relevant information from the log entry
        log_timestamp = log['timestamp']
        source_ip = log['sourceIPAddress']
        destination_ip = log['destinationIPAddress']
        action = log['action']
        
        # Perform custom analysis or threat detection logic
        if action == 'ACCEPT':
            # Check for suspicious behavior or specific attack patterns
            if check_suspicious_behavior(source_ip, destination_ip):
                # Take appropriate actions based on the detection
                process_threat_detection(source_ip, log_timestamp)
    
    return {
        'statusCode': 200,
        'body': 'VPC Flow Logs processing complete'
    }

def check_suspicious_behavior(source_ip, destination_ip):
    # Check for SSH brute force attacks or other suspicious behavior
    if check_ssh_brute_force(source_ip, destination_ip):
        return True

    return False

def check_ssh_brute_force(source_ip, destination_ip):
    # Check if the destination IP is an SSH server and source IP has multiple failed SSH connections
    if destination_ip == 'YOUR_SSH_SERVER_IP' and count_failed_ssh_connections(source_ip) > 10:
        return True
    
    return False

def count_failed_ssh_connections(source_ip):
    # Use CloudWatch Logs Insights to count failed SSH connections
    logs_client = boto3.client('logs')
    query = f"fields @timestamp, @message | filter @message like /Failed password for/ and @message like /{source_ip}/ | stats count(*) as total"
    response = logs_client.start_query(
        logGroupName='YOUR_LOG_GROUP_NAME',
        startTime=int(log_timestamp) - 3600,  # Specify the desired time range
        endTime=int(log_timestamp),
        queryString=query
    )
    query_id = response['queryId']
    results = logs_client.get_query_results(queryId=query_id)
    
    # Extract the count of failed SSH connections from the query results
    count = int(results['statistics']['recordsMatched'])
    
    return count

def process_threat_detection(ip, timestamp):
    Logging the event to CloudWatch Logs
    log_message = f"Threat detected from IP: {ip} at {timestamp}"
    cloudwatch_logs = boto3.client


def process_threat_detection(ip, timestamp):
    Logging the event to CloudWatch Logs
    log_message = f"Threat detected from IP: {ip} at {timestamp}"
    cloudwatch_logs = boto3.client('logs')
    cloudwatch_logs.create_log_stream(
        logGroupName='CustomAnalysisLogs',
        logStreamName='CustomAnalysisStream'
    )
    cloudwatch_logs.put_log_events(
        logGroupName='CustomAnalysisLogs',
        logStreamName='CustomAnalysisStream',
        logEvents=[
            {
                'timestamp': int(timestamp),
                'message': log_message
            }
        ]
    )

    
    return {
        'statusCode': 200,
        'body': 'Processing complete'
    }
_
