import json
import boto3

def send_email(subject, body):
    ses_client = boto3.client('ses', region_name='us-east-1')  # Replace with your desired AWS region
    sender_email = 'maldonado.sierra.a@gmail.com'  # Replace with the email address you want to send from
    recipient_email = 'maldonado.sierra.a@gmail.com'  # Replace with the email address of the recipient
    
    response = ses_client.send_email(
        Source=sender_email,
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
    
    print("Email notification sent.")
    return response
    
def lambda_handler(event, context):
    print(json.dumps(event))  # Print the event object for debugging purposes
    
    if 'Records' in event:
        for record in event['Records']:
            # Extract relevant information from the CloudTrail event
            event_name = record['eventName']
            user_identity = record['userIdentity']
            vpc_id = record['requestParameters'].get('vpcId')

            if event_name in ['DeleteFlowLogs', 'ModifyFlowLogs', 'DisableVpcFlowLogs']:
                # Verify authorization and check for unauthorized access
                if user_identity.get('type') == 'IAMUser':
                    # Check if the IAM user has the necessary permissions for VPC Flow Logs configuration
                    subject = "Threat detected: VPC Flow Logs configuration modified or removed"
                    body = f"Threat detected: VPC Flow Logs configuration modified or removed in VPC {vpc_id}"

                    # Send email notification
                    send_email(subject, body)

        return {
            'statusCode': 200,
            'body': 'Threat detection completed.'
        }
    else:
        return {
            'statusCode': 400,
            'body': 'Invalid event payload. Missing Records key.'
        }
