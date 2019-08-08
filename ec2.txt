== Elastic Compute Cloud (EC2) Overview ==
Elastic Compute Cloud (EC2) is a widely used service offered by Amazon. It allows to rent virtual computers that can be used to run arbitrary applications. EC2 provides a scalable solution to deploy a new computer, which in AWS terminology is called an "instance", and mange its status via a web-based user interface. The user can manage every aspect of an EC2 instance from the creation and execution to the definition of access policies. EC2 instances provide many different features two of which are particular relevant when from a security perspective: Elastic Block Store<ref>Elastic Block Store https://aws.amazon.com/ebs/</ref> and Instance Metadata Service<ref>Instance Metadata and User data https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html</ref>.



===  Publicly accessible EC2 snapshots ===
EBS snapshots are, by default, stored in a private S3 bucket that is not directly accessible via the S3 dashboard. However, EBS snapshots are manageable via the EC2 interface and their permissions can be changed to be public. If an EBS snapshot is publicly accessible, it is possible to have access to the EBS block by mounting it in an EC2 instance under your control. EBS block are essentially as a virtual disk that can be mounted like any other virtual disk in EC2. To mount an EBS block two things are needed:

# an EC2 instance under where the EBS snapshot can be mounted to;
# the ID that identifies the EBS snapshot.

To get an EC2 instance refer to the AWS documentation of how to create and launch an EC2 instance<ref>Create Your EC2 Resources and Launch Your EC2 Instance https://docs.aws.amazon.com/efs/latest/ug/gs-step-one-create-ec2-resources.html</ref>.

To get the ID that identifies an EBS snapshot, the <code>aws</code> command line tool can be used to search for publicity accessible EBS snapshots:

<pre>
aws --profile [PROFILE] ec2 describe-snapshots --filters [FILTERS] --region [REGION]
</pre>

The command above will respond with a JSON listing all the publicly available snapshots that satisfies the values specified by the <code>--filters</code> flag (for a complete description of the kind of filters refer to the documentation<ref><code>describe-snapshot</code> https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-snapshots.html</ref>). The JSON will contain information about the snapshot along with <code>SnapshotId</code> that identifies the EBS snapshot. For example, to list all the publicly accessible snapshots containing the word backup and located in the east-us-2 region use the following command:

<pre>
aws --profile default ec2 describe-snapshots --filters Name=description,Values="*backup*" --region east-us-2
</pre>

The result of executing the command above would output a JSON listing all the publicly accessible snapshots satisfying the search criteria.

<pre>
{
    "Snapshots": [
        {
            "Description": "Phoenix_competitor_analysis_backup_set",
            "Encrypted": false,
            "VolumeId": "vol-ffffffff",
            "State": "completed",
            "VolumeSize": 100,
            "StartTime": "2017-08-30T05:24:48.000Z",
            "Progress": "100%",
            "OwnerId": "234190327268",
            "SnapshotId": "snap-0dc716aaf28921496"
        },
        {
            "Description": "backup",
            "Encrypted": false,
            "VolumeId": "vol-0b21c8a6c158367fc",
            "State": "completed",
            "VolumeSize": 8,
            "StartTime": "2018-05-21T13:01:49.000Z",
            "Progress": "100%",
            "OwnerId": "388304843501",
            "SnapshotId": "snap-041c06c0c3658323c"
        },
        {
            "Description": "backup",
            "Encrypted": false,
            "VolumeId": "vol-0ee056a878d9dfdb1",
            "State": "completed",
            "VolumeSize": 30,
            "StartTime": "2018-01-07T13:52:56.000Z",
            "Progress": "100%",
            "OwnerId": "682345607706",
            "SnapshotId": "snap-0e793674b08737e95"
        },
        {
            "Description": "copy of backup sprerdda - BAckup-17-8-2018",
            "Encrypted": false,
            "VolumeId": "vol-ffffffff",
            "State": "completed",
            "VolumeSize": 30,
            "StartTime": "2018-08-22T15:03:48.179Z",
            "Progress": "100%",
            "OwnerId": "869858413856",
            "SnapshotId": "snap-02326682d84d3aedd"
        }
    ]
}
</pre>

Once the snapshot has been identified, it is possible to mount it by creating an EBS volume in your account:

<pre>
aws  ec2 create-volume --availability-zone us-west-2a --region us-west-2  --snapshot-id [SNAPSHOT_ID]
</pre>

===  Metadata leakage ===
EC2 instances have something called Instance Metadata Service (IMS). IMS allows any AWS EC2 instance to retrieve data about the instance itself that can be used to configure or managing the running instance. IMS is accessible from within the instance itself by querying the end-point located at http://169.254.169.254.

IMS returns many interesting information such as the one shown in the table below (for a complete list refer to the Instance Metadata Category<ref>Instance Metadata Category https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html#instancedata-data-categories</ref> documentation).

{| class="wikitable"
|-
|http://169.254.169.254/latest/meta-data/ami-id
|The AMI ID used to launch the instance.
|-
|http://169.254.169.254/latest/meta-data/iam/security-credentials/
|If there is an IAM role associated it returns its name (which can be used in the next handler).
|-
|http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name
|If there is an IAM role associated with the instance, role-name is the name of the role, and role-name contains the temporary security credentials associated with the role (for more information, see Retrieving Security Credentials from Instance Metadata). Otherwise, not present.
|-
|http://169.254.169.254/latest/user-data
|Returns a user-defined script which is run every time a new EC2 instance is launched for the first time.
|}


Examples:
Command:
<pre>
curl http://169.254.169.254/latest/meta-data/ami-id
</pre>
Output:
<pre>
ami-336b4456
</pre>

Command:
<pre>
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
</pre>
Output:
<pre>
IAM_TEST_S3_READ
</pre>

Command:
<pre>
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/IAM_TEST_S3_READ
</pre>
Output:
<pre>
 {
  "Code" : "Success",
  "LastUpdated" : "2018-08-27T15:23:14Z",
  "Type" : "AWS-HMAC",
  "AccessKeyId" : "AS[REDACTED]TEM",
  "SecretAccessKey" : "EgKirlp[REDACTED]hkYp",
  "Token" : "FQoGZXIvYXdzEJH//////////wE[REDACTED]=",
  "Expiration" : "2018-08-27T21:36:24Z"
}
</pre>

Command:
<pre>
curl http://169.254.169.254/latest/user-data
</pre>
Output:
<pre>
 #!/bin/bash -xe
sudo apt-get update
# install coturn
apt-get install -y coturn
# install kms
sudo apt-get update
sudo apt-get install -y wget
echo "deb http://ubuntu.kurento.org xenial kms6" | sudo tee /etc/apt/sources.list.d/kurento.list
wget -O - http://ubuntu.kurento.org/kurento.gpg.key | sudo apt-key add -
sudo apt-get update 
sudo apt-get install -y kurento-media-server-6.0
systemctl enable kurento-media-server-6.0
# enable coturn
sudo echo TURNSERVER_ENABLED=1 > /etc/default/coturn
# turn config file
sudo cat >/etc/turnserver.conf<<-EOF
[...]

sudo /usr/local/bin/cfn-signal -e $? --stack arn:aws:cloudformation:us-east-2:118366151276:sta
</pre>

To being able to access such information, the attacker has to find a way to query <code>http://169.254.169.254</code> from within the EC2 instance itself. There are many ways in which this can be accomplished from being able to find a Server Side Request Forgery (SSRF) vulnerability<ref>Abusing the AWS metadata service using SSRF vulnerabilities https://blog.christophetd.fr/abusing-aws-metadata-service-using-ssrf-vulnerabilities/</ref><ref>When a web application SSRF causes the cloud to rain credentials & more https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2017/august/when-a-web-application-ssrf-causes-the-cloud-to-rain-credentials-and-more/</ref>, or exploit a proxy setup on the EC2 instance all the way to DNS rebinding<ref>DNS Rebinding Headless Browsers https://labs.mwrinfosecurity.com/blog/from-http-referer-to-aws-security-credentials/</ref>.

== External Resources ==
This is a collection of additional external resources related to testing EC2.

* DNS Rebinding Headless Browsers (https://labs.mwrinfosecurity.com/blog/from-http-referer-to-aws-security-credentials/)
* Cloud Metadata (https://gist.github.com/BuffaloWill/fa96693af67e3a3dd3fb)
* Abusing the AWS metadata service using SSRF vulnerabilities (https://blog.christophetd.fr/abusing-aws-metadata-service-using-ssrf-vulnerabilities/)
* EC2's most dangerous feature (http://www.daemonology.net/blog/2016-10-09-EC2s-most-dangerous-feature.html)

==  References ==

