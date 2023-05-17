import boto3

def lambda_handler(event, context):
    # Extract instance ID from the event
    instance_id = event['detail']['instance-id']
    
    # Check if the event is related to a brute force attack
    if event['detail']['eventName'] == 'ConsoleLogin' and event['detail']['errorMessage'] == 'Failed authentication':
        # Create a DynamoDB client
        dynamodb_client = boto3.client('dynamodb')
        
        # Check if the instance has a counter in the DynamoDB table
        response = dynamodb_client.get_item(
            TableName='FailedAttemptsTable',
            Key={'InstanceID': {'S': instance_id}}
        )
        
        if 'Item' not in response:
            # If the instance does not have a counter, initialize it to 1
            dynamodb_client.put_item(
                TableName='FailedAttemptsTable',
                Item={'InstanceID': {'S': instance_id}, 'Attempts': {'N': '1'}}
            )
        else:
            # If the instance has a counter, increment it by 1
            attempts = int(response['Item']['Attempts']['N'])
            attempts += 1
            
            if attempts >= 3:
                # If the failed attempts exceed the threshold, send an email notification
                # Create an SNS client
                sns_client = boto3.client('sns')
                
                # Publish a message to the SNS topic
                response = sns_client.publish(
                    TopicArn='arn:aws:sns:us-east-2:952514564423:aws-cloudtrail-logs2:68b30b62-ead0-4e6d-aa8b-683322499727',
                    Message=f"Brute force attack detected on EC2 instance {instance_id}. Failed attempts: {attempts}"
                )
                
                # Print the response to check for any errors
                print(response)
            
            # Update the counter in the DynamoDB table
            dynamodb_client.put_item(
                TableName='FailedAttemptsTable',
                Item={'InstanceID': {'S': instance_id}, 'Attempts': {'N': str(attempts)}}
            )
