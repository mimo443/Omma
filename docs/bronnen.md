OWASP API Security Top 10 (2023), API7:2023 SSRF: 
https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/ 

Skip to content
logo
OWASP API Security Top 10
API7:2023 Server Side Request Forgery

Search

 OWASP/API-Security
2.2k
398
Home
 
2023
 
2019
2023
Notice
Table of Contents
About OWASP
Foreword
Introduction
Release Notes
API Security Risks
OWASP Top 10 API Security Risks – 2023
API1:2023 Broken Object Level Authorization
API2:2023 Broken Authentication
API3:2023 Broken Object Property Level Authorization
API4:2023 Unrestricted Resource Consumption
API5:2023 Broken Function Level Authorization
API6:2023 Unrestricted Access to Sensitive Business Flows
API7:2023 Server Side Request Forgery
API8:2023 Security Misconfiguration
API9:2023 Improper Inventory Management
API10:2023 Unsafe Consumption of APIs
What's Next For Developers
What's Next For DevSecOps
Methodology and Data
Acknowledgments
Table of contents
Is the API Vulnerable?
Example Attack Scenarios
Scenario #1
Scenario #2
How To Prevent
References
OWASP
External
API7:2023 Server Side Request Forgery
Threat agents/Attack vectors	Security Weakness	Impacts
API Specific : Exploitability Easy	Prevalence Common : Detectability Easy	Technical Moderate : Business Specific
Exploitation requires the attacker to find an API endpoint that accesses a URI that’s provided by the client. In general, basic SSRF (when the response is returned to the attacker), is easier to exploit than Blind SSRF in which the attacker has no feedback on whether or not the attack was successful.	Modern concepts in application development encourage developers to access URIs provided by the client. Lack of or improper validation of such URIs are common issues. Regular API requests and response analysis will be required to detect the issue. When the response is not returned (Blind SSRF) detecting the vulnerability requires more effort and creativity.	Successful exploitation might lead to internal services enumeration (e.g. port scanning), information disclosure, bypassing firewalls, or other security mechanisms. In some cases, it can lead to DoS or the server being used as a proxy to hide malicious activities.
Is the API Vulnerable?
Server-Side Request Forgery (SSRF) flaws occur when an API is fetching a remote resource without validating the user-supplied URL. It enables an attacker to coerce the application to send a crafted request to an unexpected destination, even when protected by a firewall or a VPN.

Modern concepts in application development make SSRF more common and more dangerous.

More common - the following concepts encourage developers to access an external resource based on user input: Webhooks, file fetching from URLs, custom SSO, and URL previews.

More dangerous - Modern technologies like cloud providers, Kubernetes, and Docker expose management and control channels over HTTP on predictable, well-known paths. Those channels are an easy target for an SSRF attack.

It is also more challenging to limit outbound traffic from your application, because of the connected nature of modern applications.

The SSRF risk can not always be completely eliminated. While choosing a protection mechanism, it is important to consider the business risks and needs.

Example Attack Scenarios
Scenario #1
A social network allows users to upload profile pictures. The user can choose either to upload the image file from their machine, or provide the URL of the image. Choosing the second, will trigger the following API call:

POST /api/profile/upload_picture

{
  "picture_url": "http://example.com/profile_pic.jpg"
}
An attacker can send a malicious URL and initiate port scanning within the internal network using the API Endpoint.

{
  "picture_url": "localhost:8080"
}
Based on the response time, the attacker can figure out whether the port is open or not.

Scenario #2
A security product generates events when it detects anomalies in the network. Some teams prefer to review the events in a broader, more generic monitoring system, such as a SIEM (Security Information and Event Management). For this purpose, the product provides integration with other systems using webhooks.

As part of a creation of a new webhook, a GraphQL mutation is sent with the URL of the SIEM API.

POST /graphql

[
  {
    "variables": {},
    "query": "mutation {
      createNotificationChannel(input: {
        channelName: \"ch_piney\",
        notificationChannelConfig: {
          customWebhookChannelConfigs: [
            {
              url: \"http://www.siem-system.com/create_new_event\",
              send_test_req: true
            }
          ]
          }
      }){
        channelId
    }
    }"
  }
]

During the creation process, the API back-end sends a test request to the provided webhook URL, and presents to the user the response.

An attacker can leverage this flow, and make the API request a sensitive resource, such as an internal cloud metadata service that exposes credentials:

POST /graphql

[
  {
    "variables": {},
    "query": "mutation {
      createNotificationChannel(input: {
        channelName: \"ch_piney\",
        notificationChannelConfig: {
          customWebhookChannelConfigs: [
            {
              url: \"http://169.254.169.254/latest/meta-data/iam/security-credentials/ec2-default-ssm\",
              send_test_req: true
            }
          ]
        }
      }) {
        channelId
      }
    }
  }
]
Since the application shows the response from the test request, the attacker can view the credentials of the cloud environment.

How To Prevent
Isolate the resource fetching mechanism in your network: usually these features are aimed to retrieve remote resources and not internal ones.
Whenever possible, use allow lists of:
Remote origins users are expected to download resources from (e.g. Google Drive, Gravatar, etc.)
URL schemes and ports
Accepted media types for a given functionality
Disable HTTP redirections.
Use a well-tested and maintained URL parser to avoid issues caused by URL parsing inconsistencies.
Validate and sanitize all client-supplied input data.
Do not send raw responses to clients.
References
OWASP
Server Side Request Forgery
Server-Side Request Forgery Prevention Cheat Sheet
External
CWE-918: Server-Side Request Forgery (SSRF)
URL confusion vulnerabilities in the wild: Exploring parser inconsistencies, Snyk
PreviousAPI6:2023 Unrestricted Access to Sensitive Business Flows
NextAPI8:2023 Security Misconfiguration
© Copyright 2023 - OWASP API Security Project team
Made with Material for MkDocs

​

OWASP SSRF Prevention Cheat Sheet: 
https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
​Skip to content
logo
OWASP Cheat Sheet Series
Server Side Request Forgery Prevention

Search

 OWASP/CheatSheetSeries
31k
4.3k
OWASP Cheat Sheet Series
Introduction
Index Alphabetical
Index ASVS
Index MASVS
Index Proactive Controls
Index Top 10
Cheatsheets
AI Agent Security
AJAX Security
Abuse Case
Access Control
Attack Surface Analysis
Authentication
Authorization
Authorization Testing Automation
Automotive Security.md
Bean Validation
Browser Extension Vulnerabilities
C-Based Toolchain Hardening
CI CD Security
Choosing and Using Security Questions
Clickjacking Defense
Content Security Policy
Cookie Theft Mitigation
Credential Stuffing Prevention
Cross-Site Request Forgery Prevention
Cross Site Scripting Prevention
Cryptographic Storage
DOM Clobbering Prevention
DOM based XSS Prevention
Database Security
Denial of Service
Dependency Graph SBOM
Deserialization
Django REST Framework
Django Security
Docker Security
DotNet Security
Drone Security
Error Handling
File Upload
Forgot Password
GraphQL
HTML5 Security
HTTP Headers
HTTP Strict Transport Security
Infrastructure as Code Security
Injection Prevention
Injection Prevention in Java
Input Validation
Insecure Direct Object Reference Prevention
JAAS
JSON Web Token for Java
Java Security
Key Management
Kubernetes Security
LDAP Injection Prevention
LLM Prompt Injection Prevention
Laravel
Legacy Application Management
Logging
Logging Vocabulary
Mass Assignment
Microservices Security
Microservices based Security Arch Doc
Mobile Application Security
Multifactor Authentication
NPM Security
Network Segmentation
NoSQL Security
NodeJS Docker
Nodejs Security
OAuth2
OS Command Injection Defense
PHP Configuration
Password Storage
Pinning
Prototype Pollution Prevention
Query Parameterization
REST Assessment
REST Security
Ruby on Rails
SAML Security
SQL Injection Prevention
Secrets Management
Secure AI Model Ops
Secure Cloud Architecture
Secure Code Review
Secure Product Design
Securing Cascading Style Sheets
Server Side Request Forgery Prevention
Serverless FaaS Security
Session Management
Software Supply Chain Security
Symfony
TLS Cipher String
Third Party Javascript Management
Third Party Payment Gateway Integration.md
Threat Modeling
Transaction Authorization
Transport Layer Protection
Transport Layer Security
Unvalidated Redirects and Forwards
User Privacy Protection
Virtual Patching
Vulnerability Disclosure
Vulnerable Dependency Management
WebSocket Security
Web Service Security
XML External Entity Prevention
XML Security
XSS Filter Evasion
XS Leaks
Zero Trust Architecture
gRPC Security
Table of contents
Introduction
Context
Overview of a SSRF common flow
Cases
Case 1 - Application can send request only to identified and trusted applications
Example
Available protections
Application layer
String
IP address
Domain name
URL
Network layer
Case 2 - Application can send requests to ANY external IP address or domain name
Challenges in blocking URLs at application layer
Available protections
Application layer
Network layer
IMDSv2 in AWS
Semgrep Rules
References
Tools and code used for schemas
Server-Side Request Forgery Prevention Cheat Sheet¶
Introduction¶
The objective of the cheat sheet is to provide advices regarding the protection against Server Side Request Forgery (SSRF) attack.

This cheat sheet will focus on the defensive point of view and will not explain how to perform this attack. This talk from the security researcher Orange Tsai as well as this document provide techniques on how to perform this kind of attack.

Context¶
SSRF is an attack vector that abuses an application to interact with the internal/external network or the machine itself. One of the enablers for this vector is the mishandling of URLs, as showcased in the following examples:

Image on an external server (e.g. user enters image URL of their avatar for the application to download and use).
Custom WebHook (users have to specify Webhook handlers or Callback URLs).
Internal requests to interact with another service to serve a specific functionality. Most of the times, user data is sent along to be processed, and if poorly handled, can perform specific injection attacks.
Overview of a SSRF common flow¶
SSRF Common Flow

Notes:

SSRF is not limited to the HTTP protocol. Generally, the first request is HTTP, but in cases where the application itself performs the second request, it could use different protocols (e.g. FTP, SMB, SMTP, etc.) and schemes (e.g. file://, phar://, gopher://, data://, dict://, etc.).
If the application is vulnerable to XML eXternal Entity (XXE) injection then it can be exploited to perform a SSRF attack, take a look at the XXE cheat sheet to learn how to prevent the exposure to XXE.
Cases¶
Depending on the application's functionality and requirements, there are two basic cases in which SSRF can happen:

Application can send request only to identified and trusted applications: Case when allowlist approach is available.
Application can send requests to ANY external IP address or domain name: Case when allowlist approach is unavailable.
Because these two cases are very different, this cheat sheet will describe defences against them separately.

Case 1 - Application can send request only to identified and trusted applications¶
Sometimes, an application needs to perform a request to another application, often located on another network, to perform a specific task. Depending on the business case, user input is required for the functionality to work.

Example¶
Take the example of a web application that receives and uses personal information from a user, such as their first name, last name, birth date etc. to create a profile in an internal HR system. By design, that web application will have to communicate using a protocol that the HR system understands to process that data. Basically, the user cannot reach the HR system directly, but, if the web application in charge of receiving user information is vulnerable to SSRF, the user can leverage it to access the HR system. The user leverages the web application as a proxy to the HR system.

The allowlist approach is a viable option since the internal application called by the VulnerableApplication is clearly identified in the technical/business flow. It can be stated that the required calls will only be targeted between those identified and trusted applications.

Available protections¶
Several protective measures are possible at the Application and Network layers. To apply the defense in depth principle, both layers will be hardened against such attacks.

Application layer¶
The first level of protection that comes to mind is Input validation.

Based on that point, the following question comes to mind: How to perform this input validation?

As Orange Tsai shows in his talk, depending on the programming language used, parsers can be abused. One possible countermeasure is to apply the allowlist approach when input validation is used because, most of the time, the format of the information expected from the user is globally known.

The request sent to the internal application will be based on the following information:

String containing business data.
IP address (V4 or V6).
Domain name.
URL.
Note: Disable the support for the following of the redirection in your web client in order to prevent the bypass of the input validation described in the section Exploitation tricks > Bypassing restrictions > Input validation > Unsafe redirect of this document.

String¶
In the context of SSRF, validations can be added to ensure that the input string respects the business/technical format expected.

A regex can be used to ensure that data received is valid from a security point of view if the input data have a simple format (e.g. token, zip code, etc.). Otherwise, validation should be conducted using the libraries available from the string object because regex for complex formats are difficult to maintain and are highly error-prone.

User input is assumed to be non-network related and consists of the user's personal information.

Example:

//Regex validation for a data having a simple format
if(Pattern.matches("[a-zA-Z0-9\\s\\-]{1,50}", userInput)){
    //Continue the processing because the input data is valid
}else{
    //Stop the processing and reject the request
}
IP address¶
In the context of SSRF, there are 2 possible validations to perform:

Ensure that the data provided is a valid IP V4 or V6 address.
Ensure that the IP address provided belongs to one of the IP addresses of the identified and trusted applications.
The first layer of validation can be applied using libraries that ensure the security of the IP address format, based on the technology used (library option is proposed here to delegate the managing of the IP address format and leverage battle-tested validation function):

Verification of the proposed libraries has been performed regarding the exposure to bypasses (Hex, Octal, Dword, URL and Mixed encoding) described in this article.

JAVA: Method InetAddressValidator.isValid from the Apache Commons Validator library.
It is NOT exposed to bypass using Hex, Octal, Dword, URL and Mixed encoding.
.NET: Method IPAddress.TryParse from the SDK.
It is exposed to bypass using Hex, Octal, Dword and Mixed encoding but NOT the URL encoding.
As allowlisting is used here, any bypass tentative will be blocked during the comparison against the allowed list of IP addresses.
JavaScript: Library ip-address.
It is NOT exposed to bypass using Hex, Octal, Dword, URL and Mixed encoding.
Ruby: Class IPAddr from the SDK.
It is NOT exposed to bypass using Hex, Octal, Dword, URL and Mixed encoding.
Use the output value of the method/library as the IP address to compare against the allowlist.

After ensuring the validity of the incoming IP address, the second layer of validation is applied. An allowlist is created after determining all the IP addresses (v4 and v6 to avoid bypasses) of the identified and trusted applications. The valid IP is cross-checked with that list to ensure its communication with the internal application (string strict comparison with case sensitive).

Domain name¶
In the attempt of validate domain names, it is apparent to do a DNS resolution to verify the existence of the domain. In general, it is not a bad idea, yet it opens up the application to attacks depending on the configuration used regarding the DNS servers used for the domain name resolution:

It can disclose information to external DNS resolvers.
It can be used by an attacker to bind a legit domain name to an internal IP address. See the section Exploitation tricks > Bypassing restrictions > Input validation > DNS pinning of this document.
An attacker can use it to deliver a malicious payload to the internal DNS resolvers and the API (SDK or third-party) used by the application to handle the DNS communication and then, potentially, trigger a vulnerability in one of these components.
In the context of SSRF, there are two validations to perform:

Ensure that the data provided is a valid domain name.
Ensure that the domain name provided belongs to one of the domain names of the identified and trusted applications (the allowlisting comes to action here).
Similar to the IP address validation, the first layer of validation can be applied using libraries that ensure the security of the domain name format, based on the technology used (library option is proposed here in order to delegate the managing of the domain name format and leverage battle tested validation function):

Verification of the proposed libraries has been performed to ensure that the proposed functions do not perform any DNS resolution query.

JAVA: Method DomainValidator.isValid from the Apache Commons Validator library.
.NET: Method Uri.CheckHostName from the SDK.
JavaScript: Library is-valid-domain.
Python: Module validators.domain.
Ruby: No valid dedicated gem has been found.
domainator, public_suffix and addressable has been tested but unfortunately they all consider <script>alert(1)</script>.owasp.org as a valid domain name.
This regex, taken from here, can be used: ^(((?!-))(xn--|_{1,1})?[a-z0-9-]{0,61}[a-z0-9]{1,1}\.)*(xn--)?([a-z0-9][a-z0-9\-]{0,60}|[a-z0-9-]{1,30}\.[a-z]{2,})$
Example of execution of the proposed regex for Ruby:

domain_names = ["owasp.org","owasp-test.org","doc-test.owasp.org","doc.owasp.org",
                "<script>alert(1)</script>","<script>alert(1)</script>.owasp.org"]
domain_names.each { |domain_name|
    if ( domain_name =~ /^(((?!-))(xn--|_{1,1})?[a-z0-9-]{0,61}[a-z0-9]{1,1}\.)*(xn--)?([a-z0-9][a-z0-9\-]{0,60}|[a-z0-9-]{1,30}\.[a-z]{2,})$/ )
        puts "[i] #{domain_name} is VALID"
    else
        puts "[!] #{domain_name} is INVALID"
    end
}
$ ruby test.rb
[i] owasp.org is VALID
[i] owasp-test.org is VALID
[i] doc-test.owasp.org is VALID
[i] doc.owasp.org is VALID
[!] <script>alert(1)</script> is INVALID
[!] <script>alert(1)</script>.owasp.org is INVALID
After ensuring the validity of the incoming domain name, the second layer of validation is applied:

Build an allowlist with all the domain names of every identified and trusted applications.
Verify that the domain name received is part of this allowlist (string strict comparison with case sensitive).
Unfortunately here, the application is still vulnerable to the DNS pinning bypass mentioned in this document. Indeed, a DNS resolution will be made when the business code will be executed. To address that issue, the following action must be taken in addition of the validation on the domain name:

Ensure that the domains that are part of your organization are resolved by your internal DNS server first in the chains of DNS resolvers.
Monitor the domains allowlist in order to detect when any of them resolves to a/an: - Local IP address (V4 + V6). - Internal IP of your organization (expected to be in private IP ranges) for the domain that are not part of your organization.
The following Python3 script can be used, as a starting point, for the monitoring mentioned above:

# Dependencies: pip install ipaddress dnspython
import ipaddress
import dns.resolver

# Configure the allowlist to check
DOMAINS_ALLOWLIST = ["owasp.org", "labslinux"]

# Configure the DNS resolver to use for all DNS queries
DNS_RESOLVER = dns.resolver.Resolver()
DNS_RESOLVER.nameservers = ["1.1.1.1"]

def verify_dns_records(domain, records, type):
    """
    Verify if one of the DNS records resolve to a non public IP address.
    Return a boolean indicating if any error has been detected.
    """
    error_detected = False
    if records is not None:
        for record in records:
            value = record.to_text().strip()
            try:
                ip = ipaddress.ip_address(value)
                # See https://docs.python.org/3/library/ipaddress.html#ipaddress.IPv4Address.is_global
                if not ip.is_global:
                    print("[!] DNS record type '%s' for domain name '%s' resolve to
                    a non public IP address '%s'!" % (type, domain, value))
                    error_detected = True
            except ValueError:
                error_detected = True
                print("[!] '%s' is not valid IP address!" % value)
    return error_detected

def check():
    """
    Perform the check of the allowlist of domains.
    Return a boolean indicating if any error has been detected.
    """
    error_detected = False
    for domain in DOMAINS_ALLOWLIST:
        # Get the IPs of the current domain
        # See https://en.wikipedia.org/wiki/List_of_DNS_record_types
        try:
            # A = IPv4 address record
            ip_v4_records = DNS_RESOLVER.query(domain, "A")
        except Exception as e:
            ip_v4_records = None
            print("[i] Cannot get A record for domain '%s': %s\n" % (domain,e))
        try:
            # AAAA = IPv6 address record
            ip_v6_records = DNS_RESOLVER.query(domain, "AAAA")
        except Exception as e:
            ip_v6_records = None
            print("[i] Cannot get AAAA record for domain '%s': %s\n" % (domain,e))
        # Verify the IPs obtained
        if verify_dns_records(domain, ip_v4_records, "A")
        or verify_dns_records(domain, ip_v6_records, "AAAA"):
            error_detected = True
    return error_detected

if __name__== "__main__":
    if check():
        exit(1)
    else:
        exit(0)
URL¶
Do not accept complete URLs from the user because URL are difficult to validate and the parser can be abused depending on the technology used as showcased by the following talk of Orange Tsai.

If network related information is really needed then only accept a valid IP address or domain name.

Network layer¶
The objective of the Network layer security is to prevent the VulnerableApplication from performing calls to arbitrary applications. Only allowed routes will be available for this application in order to limit its network access to only those that it should communicate with.

The Firewall component, as a specific device or using the one provided within the operating system, will be used here to define the legitimate flows.

In the schema below, a Firewall component is leveraged to limit the application's access, and in turn, limit the impact of an application vulnerable to SSRF:

Case 1 for Network layer protection about flows that we want to prevent

Network segregation (see this set of implementation advice can also be leveraged and is highly recommended in order to block illegitimate calls directly at network level itself.

Case 2 - Application can send requests to ANY external IP address or domain name¶
This case happens when a user can control a URL to an External resource and the application makes a request to this URL (e.g. in case of WebHooks). Allow lists cannot be used here because the list of IPs/domains is often unknown upfront and is dynamically changing.

In this scenario, External refers to any IP that doesn't belong to the internal network, and should be reached by going over the public internet.

Thus, the call from the Vulnerable Application:

Is NOT targeting one of the IP/domain located inside the company's global network.
Uses a convention defined between the VulnerableApplication and the expected IP/domain in order to prove that the call has been legitimately initiated.
Challenges in blocking URLs at application layer¶
Based on the business requirements of the above mentioned applications, the allowlist approach is not a valid solution. Despite knowing that the block-list approach is not an impenetrable wall, it is the best solution in this scenario. It is informing the application what it should not do.

Here is why filtering URLs is hard at the Application layer:

It implies that the application must be able to detect, at the code level, that the provided IP (V4 + V6) is not part of the official private networks ranges including also localhost and IPv4/v6 Link-Local addresses. Not every SDK provides a built-in feature for this kind of verification, and leaves the handling up to the developer to understand all of its pitfalls and possible values, which makes it a demanding task.
Same remark for domain name: The company must maintain a list of all internal domain names and provide a centralized service to allow an application to verify if a provided domain name is an internal one. For this verification, an internal DNS resolver can be queried by the application but this internal DNS resolver must not resolve external domain names.
Available protections¶
Taking into consideration the same assumption in the following example for the following sections.

Application layer¶
Like for the case n°1, it is assumed that the IP Address or domain name is required to create the request that will be sent to the TargetApplication.

The first validation on the input data presented in the case n°1 on the 3 types of data will be the same for this case BUT the second validation will differ. Indeed, here we must use the block-list approach.

Regarding the proof of legitimacy of the request: The TargetedApplication that will receive the request must generate a random token (ex: alphanumeric of 20 characters) that is expected to be passed by the caller (in body via a parameter for which the name is also defined by the application itself and only allow characters set [a-z]{1,10}) to perform a valid request. The receiving endpoint must only accept HTTP POST requests.

Validation flow (if one the validation steps fail then the request is rejected):

The application will receive the IP address or domain name of the TargetedApplication and it will apply the first validation on the input data using the libraries/regex mentioned in this section.
The second validation will be applied against the IP address or domain name of the TargetedApplication using the following block-list approach: - For IP address:
The application will verify that it is a public one (see the hint provided in the next paragraph with the python code sample).
For domain name:
The application will verify that it is a public one by trying to resolve the domain name against the DNS resolver that will only resolve internal domain name. Here, it must return a response indicating that it do not know the provided domain because the expected value received must be a public domain.
To prevent the DNS pinning attack described in this document, the application will retrieve all the IP addresses behind the domain name provided (taking records A + AAAA for IPv4 + IPv6) and it will apply the same verification described in the previous point about IP addresses.
The application will receive the protocol to use for the request via a dedicated input parameter for which it will verify the value against an allowed list of protocols (HTTP or HTTPS).
The application will receive the parameter name for the token to pass to the TargetedApplication via a dedicated input parameter for which it will only allow the characters set [a-z]{1,10}.
The application will receive the token itself via a dedicated input parameter for which it will only allow the characters set [a-zA-Z0-9]{20}.
The application will receive and validate (from a security point of view) any business data needed to perform a valid call.
The application will build the HTTP POST request using only validated information and will send it (don't forget to disable the support for redirection in the web client used).
Network layer¶
Similar to the following section.

IMDSv2 in AWS¶
In cloud environments SSRF is often used to access and steal credentials and access tokens from metadata services (e.g. AWS Instance Metadata Service, Azure Instance Metadata Service, GCP metadata server).

IMDSv2 is an additional defence-in-depth mechanism for AWS that mitigates some of the instances of SSRF.

To leverage this protection migrate to IMDSv2 and disable old IMDSv1. Check out AWS documentation for more details.

Semgrep Rules¶
Semgrep is a command-line tool for offline static analysis. Use pre-built or custom rules to enforce code and security standards in your codebase. Explore the Semgrep rules for SSRF to effectively identify and investigate potential SSRF vulnerabilities.

References¶
Online version of the SSRF bible (PDF version is used in this cheat sheet).

Article about Bypassing SSRF Protection.

Articles about SSRF attacks: Part 1, part 2 and part 3.

Article about IMDSv2

Tools and code used for schemas¶
Mermaid Online Editor and Mermaid documentation.
Draw.io Online Editor.
Mermaid code for SSRF common flow (printscreen are used to capture PNG image inserted into this cheat sheet):

sequenceDiagram
    participant Attacker
    participant VulnerableApplication
    participant TargetedApplication
    Attacker->>VulnerableApplication: Crafted HTTP request
    VulnerableApplication->>TargetedApplication: Request (HTTP, FTP...)
    Note left of TargetedApplication: Use payload included<br>into the request to<br>VulnerableApplication
    TargetedApplication->>VulnerableApplication: Response
    VulnerableApplication->>Attacker: Response
    Note left of VulnerableApplication: Include response<br>from the<br>TargetedApplication
Draw.io schema XML code for the "case 1 for network layer protection about flows that we want to prevent" schema (printscreen are used to capture PNG image inserted into this cheat sheet).

©Copyright 2026 - Cheat Sheets Series Team - This work is licensed under Creative Commons Attribution-ShareAlike 4.0 International.
Made with Material for MkDocs



https://www.aikido.dev/blog/appsec-threats
Aikido Platform
Your Complete Security HQ


Explore platform


Advanced AppSec suite, built for devs.


Dependencies (SCA)
SAST & AI SAST
IaC
AI Code Quality
Secrets
Malware
Licenses (SBOM)
Outdated Software
Container Images

Unified cloud security with real-time visibility.


CSPM
Virtual Machines
Infrastructure as Code
Cloud Search
Container & K8s Scanning
Hardened Images

AI-powered offensive security testing.


Autonomous Pentests
DAST
Attack Surface
API Scanning

in-app runtime defense and threat detection.


Runtime Protection
AI Monitoring
Bot Protection
By Feature
AI AutoFix
CI/CD Security
IDE Integrations
On-Prem Scanning
By Use Case
Compliance
Vulnerability Management
Secure Your Code
Generate SBOMs
ASPM
CSPM
AI at Aikido
Block 0-Days
By Stage
Startup
Enterprise
By Industry
FinTech
HealthTech
HRTech
Legal Tech
Group Companies
Agencies
Mobile apps
Manufacturing
Public Sector
Banks
Developer
Docs
How to use Aikido
Public API docs
Aikido developer hub
Changelog
See what shipped
Security
In-house research
Malware & CVE intelligence
Trust Center
Safe, private, compliant
Learn
Software Security Academy
Students
Get Aikido free
Open Source

Aikido Intel
Malware & OSS threat feed

Zen
In-app firewall protection

OpenGrep
Code analysis engine

Aikido Safe Chain
Prevent malware during install.
Company
Blog
Get insights, updates & more
Customers
Trusted by the best teams
State of AI report
Insights from 450 CISOs and devs
Integrations

IDEs

CI/CD Systems

Clouds

Git Systems

Compliance

Messengers

Task Managers
More integrations
About
About
Meet the team
Careers
We’re hiring
Press Kit
Download brand assets
Events
See you around?
Open Source
Our OSS projects
Customer Stories
Trusted by the best teams
Partner Program
Partner with us
Pricing
Contact
Login
Start for Free
No CC required
Book a demo
Aikido
FR
JP
DE
PT
Login
Start for Free
No CC required
Blog
/
Guides & Best Practices
10 Common Web Application Security Threats
Joel Hans
Joel Hans
|
#AppSec
Published on:
July 10, 2025
Last updated on:
December 15, 2025
Why are you here?
You know your applications are vulnerable to all kinds of attacks. Overall, cybercrime was forecast to cost $9.5tn in 2025, according to Cybersecurity Ventures - that’s a threefold increase on 2015. And last year, web application attacks accounted for 12% of all data breaches, up from 9% the previous year. This steady rise coupled with the fact that failing to secure web applications can violate numerous regulations, means that developers are keen to better understand the threats that impact them the most. 

So we’re going to reduce the noise around common vulnerabilities and focus on three essential details:

The TL;DR, which will better inform you of what the type of attack is. 
A concise answer to the question, “Does this affect me?” with a clear yes or no (✅ or 🙅) and brief explanation.
Quick tips in response to “How can I fix it?” that don’t involve expensive tools or costly refactors.
1. SQL injection & NoSQL injection
TL;DR: This classic vulnerability is made possible by unsanitized and unvalidated user input, which allows attackers to run queries directly against your database. From there, they can extract data, modify records, or delete at will.

Does this affect me?‍

✅ if your app interacts with a SQL or NoSQL database at any point. Injection attacks have been around for decades, and automated attacks will immediately start to probe your endpoints with common exploits.

🙅 if you have no dynamic content based on database records. This could be because you’re entirely client-side, using a static site generator (SSG), or doing server-side rendering with a database but never accepting input from users.

How do I fix it? First and foremost, sanitize and validate all user input to eliminate unwanted characters or strings. Leverage open-source libraries and frameworks that allow for parameterized queries, and never concatenate user input into a database query. If you’re using Node.js, consider our open-source security engine Runtime, which autonomously projects you from SQL/NoSQL injection attacks and more.

2. Cross-site scripting (XSS)
TL;DR: XSS is another injection attack that allows an attacker to send a malicious script to another, potentially gathering their authentication credentials or confidential data.

Does this affect me?‍

✅ if your app accept user input and outputs it elsewhere as dynamic content.

🙅 if you don’t accept user input at all.

How do I fix it? As with SQL/NoSQL injection attacks, you should validate user input when you include said input inside the href attribute of anchor tags to ensure the protocol isn’t javascript. Take care when using JavaScript methods like innerHTML or React’s dangerouslySetInnerHTML, which can arbitrarily execute any code embedded into the string during output. Regardless of your approach, sanitize HTML output with open-source sanitizers like DOMPurify to send only clean, non-executable HTML to your users.

3. Server-side request forgery (SSRF)
TL;DR: SSRF attacks happen when a malicious actor abuses your app to interact with its underlying network, operating it like a proxy to jump to potentially more vulnerable or lucrative services.

Does this affect me?‍

✅ if your app interfaces with another service or API that performs a specific operation with user data—even if you’ve used allow lists to restrict traffic between only known and trusted endpoint.🙅 if you’re truly static.

How do I fix it? While a regex to validate IP addresses or hostnames is an okay start, it’s usually prone to bypasses like octal encoding. Two more reliable solutions are to use an allowlist and your platform’s native URL parser to restrict input to only safe and known hosts, and disabling redirects in the fetch requests. Depending on your framework, you can also freely leverage open-source projects—like ssrf-req-filter for Node.js—to properly refuse any requests to internal hosts.

4. Path traversal
TL;DR: This security flaw lets attackers access files and directories on your web server by reference files using ../ sequences or even absolute paths. Using sneaky tactics like double encoding, attackers can use framework-specific folder-file hierarchies or common filenames to find valuable information.

Does this affect me?‍

✅ Your app runs on a web server and includes references to the filesystem—no skirting around this one.

How do I fix it? Your first step is to remove any sensitive files, like any containing environment variables or secrets, from your web server’s root directory, and establish a process to prevent further slip-ups. 

be to never store sensitive files, like those containing environment variables or secrets, in your web server’s root directory. Also, don’t store these files in any folder meant to be publicly accessible, like the /static and /public folders of a Next.js project. Finally, strip ../ path separators and their encoded variants from user input.

Runtime also works fantastically well for path traversal… just saying.

5. XML eXternal Entity (XXE) injection
TL;DR: XXE attacks leverage a weakness in XML parsers that allows external entities, referenced by a document type definition (DTD), to be fetched and processed without validation or sanitization. The type and severity of the attack are limited mostly by the attacker’s skills and any OS-level security/permissions from your infrastructure provider.

Does this affect me?‍

✅ if you parse XML for any reason, including single sign-on authentication flows using SAML.

🙅 if you don’t have to deal with XML in your app!

How do I fix it? Disable external DTD resolving in your XML parser. You likely can’t refuse DTDs entirely, as it’s normal for some XML payloads to contain them—just don’t let your XML parser do anything with them.

6. Deserialization
TL;DR: Attackers can send malicious data through a deserialization function built into your app (like unserialize() from node-serialize) to execute code remotely, run a denial-of-service, or even create a reverse shell.

Does this affect me?‍

✅ if your app deserializes data directly from user interaction or through background functions/services like cookies, HTML forms, third-party APIs, caching, and more.

🙅 if you’re running a fully-static app with none of the above.

How do I fix it? In general, avoid deserializing user input (aka untrusted) data. If you must, only accept said data from authenticated and authorized users based on trusted signatures, certificates, and identity providers.

7. Shell injection/command injection
TL;DR: Your app passes user input directly to the underlying shell of the OS on which your web server and app executes, allowing attackers to execute arbitrary commands or traverse the filesystem, often with sufficient privileges to extract data or pivot to another system.

Does this affect me?‍

✅ if your app interacts with the filesystem or shell directly, such as a UNIX command like cat.

🙅 if you already use a framework API or method to safely pass arguments to the command you need to execute, or don’t need to interact with the filesystem/shell, such as in an SSG.

How do I fix it? Avoid accepting user input directly into commands or calling them directly. Instead, use your framework’s API/method, like child_process.execFile() in Node.js, which lets you pass arguments in a list of strings. Even with that protection, always run your apps with the least privileges necessary for the required business logic to prevent an attacker from “escaping” the web server and accessing root-only folders and files.

And yes, we’re back for one more friendly reminder to add Runtime to any Node.js project with one command (npm add @aikidosec/runtime || yarn install @aikidosec/runtime) to instantly protect your app against common shell/command injection attacks.

8. Local file inclusion (LFI)
TL;DR: LFI attacks involve tricking your app into exposing or running files on the system running your web server, which allows attackers to extract information or execute code remotely. While path traversal only allows attackers to read files, LFI attacks execute those files within your app, opening you up to a laundry list of vulnerabilities like remote code execution (RCE).

Does this affect me?‍

✅ if your app uses the path to a file as user input.

🙅 if your app doesn’t require users to supply paths to complete any action.

How do I fix it? Always sanitize user input to prevent the path traversal methods discussed above. If you must include files on the local filesystem beyond those typically found in “safe” /public or /static folders, use an allowlist to file names and locations that your app is permitted to read and execute.

9. Prototype pollution
TL;DR: This JavaScript-specific vulnerability lets an attacker manipulate your app’s global objects using __proto__. The new object is then inherited across your app, potentially giving them access to confidential data or further escalating their privileges.

Does this affect me?‍

✅ if you’re using JavaScript.

🙅 if you’re using anything but JavaScript! 

How do I fix it? Start by sanitizing keys from user input using allowlists or an open-source helper library. You can extend your protection by using Object.freeze() to prevent changes to a prototype, or even using the --disable-proto=delete flag offered with Node.js.

10. Open redirects
TL;DR: In this common vector for phishing, attackers craft a custom URL like https://www.example.com/abc/def?&success=false&redirectURL=https://example.phishing.com to trick your app into redirecting unsuspecting users to a malicious website. In addition, attackers can chain redirects together with other vulnerabilities for even more impact, leading to account takeovers and more.

Does this affect me?

✅ if your app redirects users to another page/view after completing an action, like sending them to example.app/dashboard after successful authentication.

🙅 if you’re still living that static-generated life.

How do I fix it? First, remove parameter-based redirects from your app and replace them with fixed redirects based on an allowlist of trusted domains and paths to which you can redirect users after they take specific actions. This might slightly degrade the user experience, but it’s a meaningful compromise to provide a secure experience, not one that leaves them blaming you for the strange expenses on their credit card statement.

What’s next?
If you’re feeling overwhelmed by the scope of attacks and all the work required to protect against them, know you’re not alone.
‍
No one expects you to solve all these security problems and possible vulnerabilities yourself. SQL injection attacks alone have existed for decades, and folks are still finding CVEs in sophisticated apps, frameworks, and libraries all the time. That’s not to say you should also take these security problems with a grain of salt—if your app meets the ✅ for any of these top 10 security problems, you should start taking action.

Chances are you’re either using enterprise-grade (aka, expensive and complex) security tools, or have cobbled together a handful of open-source projects into a CI/CD pipeline or Git commit hooks and are hoping for the best. This could leave some security gaps, such as: 

How your app could be vulnerable due to less-than-ideal programming practices, insecure dependencies, and beyond.
Where the vulnerabilities are most likely hiding, down to single LOCs or entries in your package.json file.
Why you should fix certain vulnerabilities immediately and why others are lower priority.
Aikido Security helps to plug these gaps in 2 simple steps:

1. Scan your code with Aikido
Sign up (free, takes 2 min) and scan your repos. Get a focused list of critical vulnerabilities based on your app’s actual architecture and usage. See exactly what matters, get guided fixes, and get alerts for new issues in your latest commits.

2. Protect your Node.js apps with Runtime
Add our open-source Runtime to block injection, prototype pollution, and path traversal attacks at the server level—without the overhead of WAFs or agents. Runtime also sends real-time attack data back to Aikido so you can see what’s being targeted and prioritize fixes.

Now you’re off on the right foot, with a clearer picture as to:

How your app is vulnerable in more ways than you might have once thought.
Where you should focus your time and attention to fix the most critical issues first.
Why security and vulnerability scanning isn’t a one-time effort, but a continuous process.
‍


Written by
Joel Hans
Copywriter

Joel Hans is a developer-focused copywriter, senior developer educator and developer relations specialist, with experience of writing in the developer security domain.

Jump to:
Why are you here?
1. SQL injection & NoSQL injection
2. Cross-site scripting (XSS)
3. Server-side request forgery (SSRF)
4. Path traversal
5. XML eXternal Entity (XXE) injection
6. Deserialization
7. Shell injection/command injection
8. Local file inclusion (LFI)
9. Prototype pollution
10. Open redirects
What’s next?
Feature/Aspect	CycloneDX	SPDX	SWID
Core Utility	Versatile BOM management	Detailed compliance tracking	Software asset precision
Data Formats	XML, JSON, Protobuf	Tag/Value, JSON, XML, YAML, RDF	XML
Standardization	OWASP Initiative	ISO/IEC Standard	ISO/IEC Standard
Information Depth	Extensive component focus	Comprehensive metadata	Focused identification
Secure your software now
Start for Free
No CC required
Book a demo
Share:
Get secure now
Secure your code, cloud, and runtime in one central system.
Find and fix vulnerabilities fast automatically.

Start Scanning
No CC required
Book a demo
No credit card required | Scan results in 32secs.

Company
Platform
Pricing
About
Careers
Contact
Partner with us
Resources
Docs
Public API Docs
Vulnerability Database
Blog
Customer Stories
Integrations
Glossary
Press Kit
Customer Reviews
Industries
For HealthTech
For MedTech
For FinTech
For SecurityTech
For LegalTech
For HRTech
For Agencies
For Enterprise
For Startups
For PE & Group Companies
For Government & Public Sector
For Smart Manufacturing & Engineering
Use Cases
Compliance
SAST & DAST
ASPM
Vulnerability Management
Generate SBOMs
WordPress Security
Secure Your Code
Aikido for Microsoft
Aikido for AWS
Compare
vs All Vendors
vs Snyk
vs Wiz
vs Mend
vs Orca Security
vs Veracode
vs GitHub Advanced Security
vs GitLab Ultimate
vs Checkmarx
vs Semgrep
vs SonarQube
Legal
Privacy Policy
Cookie Policy
Terms of Use
Master Subscription Agreement
Data Processing Agreement
Connect
hello@aikido.dev
Security
Trust Center
Security Overview
Change Cookie Preferences
Subscribe
Stay up to date with all updates
Email*
LinkedIn
YouTube
X
© 2025 Aikido Security BV | BE0792914919
🇪🇺 Registered address: Coupure Rechts 88, 9000, Ghent, Belgium
🇪🇺 Office address: Keizer Karelstraat 15, 9000, Ghent, Belgium
🇺🇸 Office address: 95 Third St, 2nd Fl, San Francisco, CA 94103, US

SOC 2
Compliant

ISO 27001
Compliant

FedRAMP
Implementing


​