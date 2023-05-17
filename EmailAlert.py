import json
import boto3

def lambda_handler(event,context):
    client = bot3.client('guardduty')
    response = client.get_findings()
    
    for findings in response['FindingIDs']:
        findings_details = client.get_findings(findingsIDs=findings)
        
        if finding_details['Severity'] > 4.0:
            take_action(findings_details)
def take_action(findings):
    sns = boto3.client('sns')
    response = sns.publish(
        TopicARN='arn:aws:sns:us-east-2:952514564423:BruteForce:b4f525f1-4106-401f-bac5-8b13cd4fc604',
        Message=json.dumps(finding),
        Subject="GuardDuty Findings"
    )
