import boto3

def send_alert(alert_message):
    # Function to send alert/notification
    print(f"ALERT: {alert_message}")

def lambda_handler(event, context):
    # Retrieve CloudTrail events from the event payload
    cloudtrail_events = event['Records']
    
    for event in cloudtrail_events:
        # Extract relevant information from the CloudTrail event
        event_name = event['eventName']
        event_source = event['eventSource']
        user_identity = event['userIdentity']
        
        # Perform threat detection based on specific criteria
        if event_source == 'aws.ec2' and event_name == 'TerminateInstances':
            # Detect termination of EC2 instances and alert
            instance_id = event['requestParameters']['instancesSet']['items'][0]['instanceId']
            alert_message = f"EC2 instance {instance_id} was terminated."
            send_alert(alert_message)
        
        elif event_source == 'aws.iam' and event_name == 'DeleteUser':
            # Detect deletion of IAM users and alert
            username = user_identity['userName']
            alert_message = f"IAM user {username} was deleted."
            send_alert(alert_message)
        
    return {
        'statusCode': 200,
        'body': 'Threat monitoring completed.'
    }
