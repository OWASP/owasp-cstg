
# Overview

## Introduction to the OWASP Cloud Security Testing Guide

As the growth and adoption of cloud computing expands, organisations are increasingly migrating their environments into highly dynamic cloud ecosystems. Whilst cloud services may address a number of fundamental historic security risks, they are not fail-safe and operate on a Shared Responsibility Model (https://aws.amazon.com/compliance/shared-responsibility-model/) which means that Security and Compliance is shared between the Cloud Provider and the customer. 

### Key Areas in Cloud Security

Security within Cloud environments is heavily influenced by the main models for cloud computing as defined by each Cloud Service Provider.  Infrastructure as a Service (IaaS), Platform as a Service (PaaS), Software as a Service (SaaS). 

![](https://github.com/orlyjamie/Cloud-Testing-Guide/blob/master/cloud-model.jpg)

To put simply, depending on the cloud computing model in question, it is a matter of Security "in" the Cloud vs. Security "Of" the Cloud which is defined by the "Shared Responsibility Model" used by each Cloud Service Provider.

The existence of the Shared Responsibility Model combined with the complexity of cloud services offered by each Cloud Service Providers directly impacts the way security tests are performed in comparison with traditional security assessments. 

In some ways, testers who have experience penetration testing in traditional on-premises environments can easily apply their knowledge when testing the security of cloud assets as the operating systems and applications are fundamentally the same. 

In other ways, the high speed of which Cloud Service Providers release products and services means that penetration testers must continuously maintain in-depth understanding of each new product released by the Cloud Service Provider(s) in order to understand how they can be vulnerable to exploitation, and more importantly, how to secure them from misuse. 

Let's discuss the key areas in cloud service provider security.

#### Cloud Data Storage

Cloud Data Storage is a major service offered by the majority of Cloud Service Providers. Cloud storage services are not only used to store non-sensitive but also sensitive objects containing data such as database backups, file-system backups, user credentials, PII and more in resources commonly referred to as "Buckets".  

Although the key to protecting cloud storage services relies on the proper configuration of Access Control Lists (ACLs), there are still factors that can lead to the compromise of data such as the insecure storage of API keys used to provide access to said services. 

When developing applications and networks, we must ensure that authentication credentials such as API keys used to provide access to cloud storage services are considered during the design process. One common bad-practice is when developers hardcode cloud storage service API keys into applications where the source-code is available to end-users, therefore compromising the security of entire cloud storage buckets.

#### Internal Cloud API Services

Cloud service providers offer a vast number of internal API endpoints that can accessed on-demand by any processes running on internal assets such as compute services. These internal APIs offer a range of functions such as but not limited to the generation of access credentials, access to instance metadata and access to credential vaults that contain hundreds or in some cases thousands of credentials used by internal resources.

Although the metadata service is almost never exposed to the internet, it may be indirectly exposed by a vulnerable internet-facing application. For example, a server-side request forgery (SSRF) vulnerability in a cloud hosted web-application could expose the metadata service to the entire internet. Attackers may use the leaked metadata to further compromise internal assets or even compromise the entire cloud infrastructure.

Metadata APIs can be most effectively protected by Cloud Service Providers, however, if such protection is not available, organisations should enforce preventative measures to minimise the risk by implementing network layer controls to prevent unnecessary access to the internal APIs combined with least privilege specifically for IAM roles and only allow the services or processes needed be able to query the internal APIs. 

#### Authentication and Authorisation

Authenticating to cloud environments can be performed using a number of methods such as but not limited to: Console access, API access and IAM Access all with their own unique access control policies and rules. Statistically speaking, the more accounts and authentication methods used by an organisation, the higher chance there is for these accounts to be compromised. 

It is not uncommon for cloud access keys to be exposed. They can be exposed within public source code repositories, unprotected issue trackers, unprotected Kubernetes dashboards, and other such sources.

Organisations should take extra precaution to securely store their keys, creating unique keys for each external service and restricting access following the principle of least privilege.


#### Architecture Design 

Not all security issues within cloud environments are directly caused by vulnerable software. Just as traditional networks require carefully planned architecture using practices such as risk assessments, threat modelling and security requirements, so do structure of cloud environment networks need careful design to increase resilience and prevent attackers from easily pivoting throughout internal cloud networks after exploiting a single vulnerability. 

When testing cloud environments it is important to address any poorly implemented security architecture such as but not limited to, overly excessive port access for compute resources that should only have service-specific ports open. 

Each cloud environment and organisation will have different technical and business requirements that will influence the structure of their internal cloud architecture, testers must be able to identify risks within these designs and recommend changes where necessary to avoid unnecessary exposure or high-risk configurations. 

#### Secure Configuration & Monitoring

For the most part, a large percentage of the security issues that are exploited within a cloud environment can be mitigated with sufficient configuration and monitoring. 

From a testing perspective, almost all of the tools that have been designed to audit the security of cloud environments perform configuration checks which are matched against specific best-practices or compliance benchmarks such as NIST and CIS. Although this means that some testing can be automated, Cloud Service Providers continuously update, modify and release new cloud products and services which means that testers must not solely rely on available scanning tools to review security and monitoring configurations. 


## Navigating the Cloud Security Testing Guide

The CSTG contains the following main sections:

1. The [Amazon Web Services Testing Guide](0x04a-Mobile-App-Taxonomy.md) covers  Amazon Web Services testing methodologies and cloud service provider overview and security best-practices.

2. The [Microsoft Azure Testing Guide](0x05a-Platform-Overview.md) covers  Microsoft Azure testing methodologies and cloud service provider overview and security best-practices.

3. The [Google Cloud Testing Guide](0x06a-Platform-Overview.md) covers  Google Cloud Platform testing methodologies and cloud service provider overview and security best-practices.
