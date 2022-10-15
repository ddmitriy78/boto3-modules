
import boto3
import botocore
from botocore.exceptions import ClientError
import time
import datetime

accountid = ''
role = ''
root_account = ''

# This is a paginator
def paginate(method, **kwargs):
    client = method.__self__
    paginator = client.get_paginator(method.__name__)
    for page in paginator.paginate(**kwargs).result_key_iters():
        for result in page:
            yield result

'''
# Converts date time to string use with in the json
example:
print(json.dumps(policy, indent=2, default=cbm.time_str_converter))
'''
def time_str_converter(o):
    if isinstance(o, datetime.datetime):
        return o.__str__()

'''Assume Role & Get STS credentials for an account'''

# Assume role in the account to deploy and configure
def assume_role(account_id, account_role):
    sts_client = boto3.client('sts')
    role_arn = 'arn:aws:iam::' + account_id + ':role/' + account_role
    # Call the assume_role method of the STSConnection object and pass the role
    # ARN and a role session name.

    assuming_role = True
    count = 1
    while assuming_role is True and count != 0:
        try:
            assuming_role = False
            assumedRoleObject = sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName="NewAccountRole"
            )
            creds = assumedRoleObject['Credentials']
        except Exception as e:
            assuming_role = True
            print('error getting credentials:', account_id, account_role)
            #time.sleep(1)
            count -= 1
            creds = False
    return creds


'''STS Get Caller Identity'''


def get_caller_identity():
    sts = boto3.client('sts')
    response = sts.get_caller_identity()
    return response

'''
AWS Organization Modules
Required:
root_account
organization OU
'''

# Gets all the children accounts from the Organizations
def list_children_id(root_account):
    children_list = []
    client = boto3.client('organizations')
    for account in paginate(client.list_accounts, MaxResults=10):
        if account['Status'] == "ACTIVE":
            children_list.append(account['Id'])
    return children_list

# Listing accounts under OU using the paginator
def list_accounts_for_parent(credentials, reg, parent_ou_id):
    accounts = []
    iam = boto3.client('organizations',
                       aws_access_key_id=credentials['AccessKeyId'],
                       aws_secret_access_key=credentials['SecretAccessKey'],
                       aws_session_token=credentials['SessionToken'],
                       region_name=reg)
    for account in paginate(iam.list_accounts_for_parent, ParentId=parent_ou_id):
        if account['Status'] == "ACTIVE" and account['Id'] != root_account:
            accounts.append(account)
    return accounts


# Lists the organizational units (OUs) in a parent organizational unit or root.
def list_ou_for_parent(credentials, reg, parent_ou_id):
    ous = []
    iam = boto3.client('organizations',
                       aws_access_key_id=credentials['AccessKeyId'],
                       aws_secret_access_key=credentials['SecretAccessKey'],
                       aws_session_token=credentials['SessionToken'],
                       region_name=reg)
    for ou in paginate(iam.list_organizational_units_for_parent, ParentId=parent_ou_id):
        ous.append(ou)
    return ous

# Get AWS account alias
def get_aws_account_name(credentials, reg):
    iam = boto3.client('iam',
                          aws_access_key_id=credentials['AccessKeyId'],
                          aws_secret_access_key=credentials['SecretAccessKey'],
                          aws_session_token=credentials['SessionToken'],
                          region_name=reg)

    account_info = iam.list_account_aliases()
    account_name = account_info['AccountAliases']
    return account_name[0]

# Get AWS account id
def get_account_id(credentials, reg):
    sts = boto3.client('sts',
                          aws_access_key_id=credentials['AccessKeyId'],
                          aws_secret_access_key=credentials['SecretAccessKey'],
                          aws_session_token=credentials['SessionToken'],
                          region_name=reg)
    account_id = sts.get_caller_identity()["Account"]
    return account_id


'''SNS Topic'''


def sns_publish(topicarn, subject, message):
    subject = subject
    print(subject)
    client = boto3.client('sns')
    response = client.publish(
        TopicArn=topicarn,
        Message=message,
        Subject=subject
    )
    return response


'''SQS'''


def create_sqs(sqs_name, region):
    client = boto3.client('sqs', region_name=region)
    try:
        response = client.create_queue(
            QueueName=sqs_name,
            Attributes={
                'DelaySeconds': '30'
            }
        )
        q_url = response['QueueUrl']
        print(q_url)
        return q_url
    except ClientError as e:
        print(e)
        q_url = e
    return q_url


def send_sqs(q_url, message, region):
    client = boto3.client('sqs', region_name=region)
    try:
        response = client.send_message(
            QueueUrl=q_url,
            MessageBody=message,
            DelaySeconds=300
        )
        print(response)
        q_msg_id = response['MessageId']
        print(q_msg_id)
    except ClientError as e:
        print(e)
        response = e
    return response


def rsv_sqs(q_url, region):
    client = boto3.client('sqs', region_name=region)
    try:
        response = client.receive_message(
            QueueUrl=q_url
        )
        print(response)
    except ClientError as e:
        print(e)


'''EC2 Modules'''



def ec2_describe(credentials, region, id):
    ec2 = boto3.client('ec2',
                          aws_access_key_id=credentials['AccessKeyId'],
                          aws_secret_access_key=credentials['SecretAccessKey'],
                          aws_session_token=credentials['SessionToken'],
                          region_name=region)

    response = ec2.describe_instances(
        InstanceIds=[id]
    )
    return response


def ec2_stop(credentials, region, id):
    ec2 = boto3.client('ec2',
                          aws_access_key_id=credentials['AccessKeyId'],
                          aws_secret_access_key=credentials['SecretAccessKey'],
                          aws_session_token=credentials['SessionToken'],
                          region_name=region)
    response = ec2.stop_instances(
        InstanceIds=[id],
        DryRun=False
    )


def add_ec2_tag(credentials, region, ec2_id, key, value):
    ec2 = boto3.client('ec2',
                          aws_access_key_id=credentials['AccessKeyId'],
                          aws_secret_access_key=credentials['SecretAccessKey'],
                          aws_session_token=credentials['SessionToken'],
                          region_name=region)
    print('Trying to Tag', ec2_id, key, value)
    response = ec2.create_tags(
        Resources=[
            ec2_id
        ],
        Tags=[
            {'Key': key, 'Value': value}
        ]
    )
    return response


def check_ami(credentials, region, imageId):
    ec2 = boto3.client('ec2',
                          aws_access_key_id=credentials['AccessKeyId'],
                          aws_secret_access_key=credentials['SecretAccessKey'],
                          aws_session_token=credentials['SessionToken'],
                          region_name=region)
    check = False
    image = ec2.describe_images(
        ImageIds=[
            imageId
        ]
    )
    print('Checking ami', imageId)
    print('AMI name: ', image['Images'][0]['Name'])
    if image['Images'][0]['Public'] is False:
        print('AMI is Private')
        # print('AMI name: ', image['Images'][0]['Tags']
        tags = image['Images'][0]['Tags']
        for tag in tags:
            print(tag)
            if tag['Key'] == 'HardenedAMI' and tag['Value'] == 'Yes':
                print('Found HardenedAMI')
                check = 'Approved'
    else:
        check = 'Unapproved'
    return check


'''S3'''


def get_list_s3(bucket, key):
    print({'msg': 'get_s3_object', 'bucket': bucket, 'key': key})
    s3 = boto3.resource('s3')
    out_list = []
    try:
        object = s3.Object(bucket, key)

        '''
        Iterates through all the objects, doing the pagination for you. Each obj is an ObjectSummary, so it doesn't
        contain the body. You'll need to call get to get the whole body.
        '''
        body = object.get()['Body'].read()
        body = (body.decode('utf8'))
        list = body.split (',')
        for i in list:
            i = i.strip('\n')
            if i:
                out_list.append(i)
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == True:
            out_list = 'We got an error'
        else:
            out_list = "Unexpected error: %s" % e

    return list


'''IAM'''


# Get list of IAM users in the AWS account
def get_users():
    client = boto3.client('iam')
    response = None
    user_names = []
    marker = None

    # By default, only 100 roles are returned at a time.
    # 'Marker' is used for pagination.
    while (response is None or response['IsTruncated']):
        # Marker is only accepted if result was truncated.
        if marker is None:
            response = client.list_users()
        else:
            response = client.list_users(Marker=marker)

        users = response['Users']
        for user in users:
            user_names.append(user['Arn'])

        if response['IsTruncated']:
            marker = response['Marker']

    return user_names

# Get list of IAM roles in the aws account
def get_roles(credentials, reg):
    # Create a client that will be referenced to make an API call
    iam = boto3.client('iam',
                          aws_access_key_id=credentials['AccessKeyId'],
                          aws_secret_access_key=credentials['SecretAccessKey'],
                          aws_session_token=credentials['SessionToken'],
                          region_name=reg)
    response = None
    role_names = []
    marker = None

    # By default, only 100 roles are returned at a time.
    # 'Marker' is used for pagination.
    while (response is None or response['IsTruncated']):
        # Marker is only accepted if result was truncated.
        if marker is None:
            response = iam.list_roles()
        else:
            response = iam.list_roles(Marker=marker)
        roles = response['Roles']
        for role in roles:
            role_names.append(role['Arn'])

        if response['IsTruncated']:
            marker = response['Marker']

    return role_names

# Get list of IAM groups in the AWS account
def get_groups():
    client = boto3.client('iam')
    response = None
    group_names = []
    marker = None

    # By default, only 100 roles are returned at a time.
    # 'Marker' is used for pagination.
    while (response is None or response['IsTruncated']):
        # Marker is only accepted if result was truncated.
        if marker is None:
            response = client.list_groups()
        else:
            response = client.list_groups(Marker=marker)

        groups = response['Groups']
        for group in groups:
            group_names.append(group['Arn'])

        if response['IsTruncated']:
            marker = response['Marker']

    return group_names

def list_attached_role_policies(role, path):
    client = boto3.client('iam')
    try:
        response = client.list_attached_role_policies(
            RoleName=role,
            PathPrefix=path
        )
        policies = response
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == True:
            policies = 'We got an error'
        else:
            policies = "Unexpected error: %s" % e
    return policies

def list_attached_user_policies(user, path):
    client = boto3.client('iam')
    try:
        response = client.list_attached_user_policies(
            UserName=role,
            PathPrefix=path
        )
        policies = response
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == True:
            policies = 'We got an error'
        else:
            policies = "Unexpected error: %s" % e
    return policies


def list_attached_group_policies(role, path):
    client = boto3.client('iam')
    try:
        response = client.list_attached_group_policies(
            GroupName=role,
            PathPrefix=path
        )
        policies = response
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == True:
            if e.response['Error']['Code'] == True:
                policies = 'We got an error'
            else:
                policies = "Unexpected error: %s" % e
    return policies


def list_granting_policies(arn, services):

    response = None
    marker = None
    client = boto3.client('iam')

    # By default, only 100 roles are returned at a time.
    # 'Marker' is used for pagination.
    status = False
    while (response is None or response['IsTruncated']):
        # Marker is only accepted if result was truncated.
        while status != "COMPLETED":
            try:
                if marker is None:
                    response = client.list_policies_granting_service_access(
                        Arn=arn,
                        ServiceNamespaces=services
                    )
                else:
                    response = client.list_policies_granting_service_access(
                        Marker=marker,
                        Arn=arn,
                        ServiceNamespaces=services
                    )

                status = response['JobStatus']
                print('job status: ', status)
                time.sleep(2)
            except botocore.exceptions.ClientError as e:
                status = False
                if e.response['Error']['Code'] == True:
                    response = 'We got an error'
                else:
                    response = "Unexpected error: %s" % e

    return response


# Tag the role with key and value
def tag_role(role, key, value):
    client = boto3.client('iam')
    try:
        response = client.tag_role(
            RoleName=role,
            Tags=[
                {
                    'Key': key,
                    'Value': value
                },
            ]
        )
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == True:
            response = 'We got an error'
        else:
            response = "Unexpected error: %s" % e
    return response

# Tag the user with key and value
def tag_user(user, key, value):
    client = boto3.client('iam')
    try:
        response = client.tag_user(
            UserName=user,
            Tags=[
                {
                    'Key': key,
                    'Value': value
                },
            ]
        )
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == True:
            response = 'We got an error'
        else:
            response = "Unexpected error: %s" % e
    return response


def get_iam_policy(credentials, policyarn):
    iam = boto3.client('iam',
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken'],
        region_name='us-east-1')

    try:
        response = iam.get_policy(PolicyArn = policyarn)
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == True:
            response = 'We got an error'
        else:
            error  = "Unexpected error: %s" % e
            print(error)
            response = False
    return response



