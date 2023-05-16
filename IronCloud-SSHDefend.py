import boto3

def send_alert(alert_message):
    # Function to send alert/notification
    print(f"ALERT: {alert_message}")

def lambda_handler(event, context):
    # Retrieve CloudWatch Logs events from the event payload
    log_events = event['Records']
    
    for log_event in log_events:
        # Extract relevant information from the log event
        log_group = log_event['logGroup']
        log_stream = log_event['logStream']
        log_event_message = log_event['message']
        
        # Perform threat detection based on specific log patterns
        if 'Failed password' in log_event_message and 'sshd' in log_event_message:
            # Detect failed SSH attempts and alert
            alert_message = f"Failed SSH attempt detected in log group '{log_group}', log stream '{log_stream}':\n{log_event_message}"
            send_alert(alert_message)
       
        
    return {
        'statusCode': 200,
        'body': 'Security log monitoring completed.'
    }
