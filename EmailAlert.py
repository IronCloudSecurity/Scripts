import boto3

def lambda_handler(event, context):
    # Parse log events from CloudWatch Logs
    log_events = event['Records']
    
    for log_event in log_events:
        # Extract relevant information from log event
        log_message = log_event['message']
        source_ip = extract_source_ip(log_message)
        outcome = extract_outcome(log_message)
        
        # Track failed login attempts
        increment_failed_attempts(source_ip, outcome)
        
        # Detect brute force patterns
        if is_brute_force_attack(source_ip):
            # Trigger an action
            mitigate_brute_force_attack(source_ip)
        
    return {
        'statusCode': 200,
        'body': 'Lambda function executed successfully'
    }

def extract_source_ip(log_message):
    # Hard code a specific IP address
    source_ip = '3.142.131.22'  
    return source_ip


def extract_outcome(log_message):
    # Example parsing logic assuming the outcome is indicated by keywords like "Success" or "Failure"
    if 'Success' in log_message:
        outcome = 'Success'
    elif 'Failure' in log_message:
        outcome = 'Failure'
    else:
        outcome = 'Unknown'
    
    return outcome

failed_attempts_cache = {}  # Dictionary to store failed login attempts

def increment_failed_attempts(source_ip, outcome):
    # Check if the source IP already exists in the cache
    if source_ip in failed_attempts_cache:
        # Increment the counter for the existing IP
        failed_attempts_cache[source_ip] += 1
    else:
        # Add the source IP to the cache with an initial count of 1
        failed_attempts_cache[source_ip] = 1

def is_brute_force_attack(source_ip):
    threshold = 3  # Adjust the threshold based on your requirements
    if source_ip in failed_attempts_cache and failed_attempts_cache[source_ip] > threshold:
        return True
    else:
        return False

def mitigate_brute_force_attack(source_ip):
    # Example logic to send a notification via Amazon Simple Notification Service (SNS)
    sns_client = boto3.client('sns')
    topic_arn = 'arn:aws:sns:us-east-2:952514564423:BruteForce'
    message = f"Brute force attack detected from IP address: {source_ip}"
    
    sns_client.publish(TopicArn=topic_arn, Message=message)
    
    # Example logic to add the IP address to a blocklist using AWS WAF
    waf_client = boto3.client('waf')
    ip_set_id = 'i-0f124bb0be9fa0f06'
    
    waf_client.update_ip_set(IPSetId=ip_set_id, ChangeToken='i-0f124bb0be9fa0f06', Updates=[
        {
            'Action': 'INSERT',
            'IPSetDescriptor': {
                'Type': 'IPV4',
                'Value': source_ip
            }
        }
    ])
