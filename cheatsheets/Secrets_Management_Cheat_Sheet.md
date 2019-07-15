# Contents

1. [Introduction](#1-Introduction)
1. [General](#2-General-Secrets-Management)
1. [Continuous Integration (CI) and Continuous Deployment (CD)](#3-Continuous-Integration-(CI)-and-Continuous-Deployment-(CD))
1. [Cloud Providers](#4-Cloud-Providers)
1. [Containers and Orchestration](#5-Containers-&-Orchestrators)
1. [Implementation Guidance](#6-Implementation-Guidance) 
1. [Encryption](#7-Encryption)
1. [Applications](#8-Applications)
1. [Workflow in Case of Compromise](#9-Workflow-in-case-of-compromise)
1. [Secrets Management Tooling](#10-Secrets-Management-Tooling-Guidelines)

# 1. Introduction

Secrets are being used everywhere nowadays, especially with the popularity DevOps movement. Application Programming Interface (API) keys, database credentials, Identity and Access Management (IAM) permissions, Secure Shell (SSH) keys, certificates, etc. Many organizations have them hard coded in plaintext within the source code, littered throughout configuration files and configuration management tools.

There is a growing need for organisations to centralise the storage, provisioning, auditing, rotation and management of secrets in order to control access to and prevent secrets from leaking and compromising the organization. Most of the time, services share the same secrets that make identifying the source of compromise or leak very challenging.

This cheat sheet offers best practices and guidelines to help implement secrets management properly.

# 2. General Secrets Management

The following sections address the main concepts relating to secrets management.

## 2.1 High Availability

It is important to select a technology and hosting strategy (e.g. on-premises or cloud-based) that is robust enough to reliably service traffic from:

* Users (e.g. SSH keys, root account passwords). In an incident response scenario, users expect to be provisioned with credentials rapidly so they can recover services that have gone offline. Having to wait for credentials could impact the responsiveness of the operations team.
* Applications (e.g. database credentials and API keys). If the service is not preferment it could degrade the availability of dependent applications or increase application start-up times.

Within a large organisation such a service could receive a huge volume of requests to action in a timely manner. Cloud platforms can be used to utilise high-availability features such as Disaster Recovery (DR) and to allow for scaling of resources to meet the demand.

## 2.2 Centralized Approach

It makes sense to maintain a single, centralised system for the purpose of secrets management. Having too many systems could result in confusion over which one to use for which purpose, and this could slow down a response to an incident. A single system would be easier to maintain, manage and audit. A single system would also act as the source of truth, not only for secrets but the policies that apply to them.

## 2.3 Fine Grained Access-Control List (ACL)

An important feature of secrets management is the ability to enforce Access Control Lists (ACLs). ACLs can be very complex, comprising of a number of rules to define the allowed permissions for a user (principle) restricting how they can interact with objects within a system. The smallest action within a system, such as the ability to update a specific field within an individual document in a data store should be supported by the ACL system to allow for fine-grained control.

Cloud providers typically provide fine-grained access control functionality, and so it is important to select a secrets management solution that integrates with the organisations cloud providers.

The enforcement of policies such as a requirement to use multi-factor authentication should also be supported by the secrets management solution.

## 2.4 Remove Human Interaction

When managing secrets at scale it is important to provide self-help functionality for users, such as requesting access to systems, password change and account recovery. Certain requests for access could be pre-authorised by policy by the secrets management system, so as to remove human interaction. Large organisations can expect to receive many hundreds of access requests per day for internal systems from their staff. Without some level of automation and pre-approval based on existing group memberships, this could overwhelm the staff responsible for approving such requests.

## 2.5 Auditing

Auditing is an important role of secrets management due to the nature of the application. Auditing must be implemented in a secure way so as to be resilient against attempts to tamper with or delete the audit logs. At minimum the following should be audited:

* Who requested a secret and for what system and role.
* Whether the secret request was approved or rejected.
* When the secret was used and by whom/source.
* When the secret has expired.
* If any attempts to re-use expired secrets have been made.
* If there have been any authentication errors.

All audit logs must be correctly timestamped. This is another reason for the need of a centralised approach to secrets management.

## 2.6 Secret Lifecycle

Secrets follow a lifecycle. The stages in the secrets management lifecycle are as follows:

* Creation
* Rotation
* Deletion

### 2.6.1 Creation

New secrets must be securely generated and cryptographically robust enough for their purpose. Secrets must have the minimum privileges assigned to them to enable their requested use/role.

Credentials should be transmitted in a secure manor, such that ideally the password would not be transmitted along with the username when requesting user accounts. Instead the password should be transmitted via alternate channels such as SMS. The enrolment of multi-factor authentication devices will also likely be required in order to create user accounts and this capability should be supported in the secrets management solution.

Applications may not benefit from having multiple channels for the secure communication of credentials and so credentials must be provisioned in a secure way.

### 2.6.1 Rotation

Secrets should be regularly rotated so that any stolen credentials will only work for a short period of time. This will also reduce the tendency for users to fall back to bad-habits such as re-using credentials.

### 2.6.1 Deletion

When secrets are no longer required they must be securely deleted in order to restrict unauthorised access. With certificates this also involves publishing certificate revocation. For user and application accounts, it is important that the solution verify the credentials no longer work to provide assurance that the deletion was successful.

### 2.6.1 Lifespan

With exception of emergency break-glass credentials, secrets should always be created to expire after a fixed time.

Policies should be applied by the secrets management solution to ensure credentials are only made available for a limited time that is appropriate for the type of credential.

## 2.7 Transport Layer Security (TLS) Everywhere

It goes without saying that no secrets should ever be transmitted via plaintext. There is no excuse in this day and age given the ubiquitous adoption of SSL/TLS to not use encryption to protect the secrets in transit.

Secrets management solutions can be used to provision and rotate SSL certificates and also SSL Certificate Authority (CA) certificates.

## 2.8 Automate Key Rotation

Keys should be rotated regularly as per security best practice and defined by organisational policy. They should also be rotated when a key has been potentially compromised. A secrets management solution should perform this task automatically.

## 2.9 Restore and Backup

The master encryption keys for the secrets management vault must be kept secure, ideally within Hardware Security Modules (HSM). Typically the master encryption key will be split into several sub-keys, requiring a number of these keys to be present in order to re-construct the master encryption key. These sub-keys should be physically kept with the responsible staff members and distributed such that staff sickness or leave would not affect the organisation from being able to re-construct the master key from the remaining keys.

Consideration must be made for the possibility that the central secrets management service could become unavailable, perhaps due to scheduled down-time for maintenance - in which case it could be impossible to retrieve the credentials required to restore the service if they were not previously acquired. Should the secrets management system become unavailable, emergency break-glass processes should be implemented to restore the service.

Emergency break-glass credentials therefore should be regularly backed up in a secure fashion and tested routinely to verify they work.

## 2.10 Policies

Policies defining the minimum complexity requirements of passwords, as well as approved encryption algorithms are typically set at an organisation-wide level and should be enforced consistently. The use of a centralised secrets management solution would help companies to enforce these policies.

# 3. Continuous Integration (CI) and Continuous Deployment (CD)

The process of building, testing and deploying changes generally requires access to many systems. Continuous Integration (CI) and Continuous Deployment (CD) tools typically store secrets themselves for providing configuration to the application or for during deployment.

## 3.1. Build Tools

Internal repositories
Code repositories

## 3.2. Rotation vs Dynamic Creation

Some secrets management solutions can interface directly with authenticating services such as database servers. This integration is typically achieved via an agent, extension or Pluggable Authentication Module (PAM) in order to provision accounts on the fly. This direct integration allows the secrets management system to provide dynamic secrets, which are one-time or short-lived access credentials with the minimum permissions required for each specific service or application. This is called dynamic secrets.

The use of dynamic secrets negates the need for rotation as new credentials are provisioned frequently, possibly each time access is requested. With a solution or systems that do not support dynamic secrets, rotation should be used to ensure compliance with organisation policy.

## 3.3. Identity Authentication



## 3.4. Deployment



# 4. Cloud Providers



## 4.1. Vendor Lock-In

Organisations should mitigate the risk of vendor lock in.

## 4.2. Geo Restrictions

Certain encryption algorithms are prohibited from being used in restricted countries. With a centralised system, this could pose a problem and consideration will need to be made to select strong cryptography that is approved and legal for use in the countries it will be used.

## 4.3. Latency



## 4.4. Data Access (keys of the kingdom)



# 5. Containers & Orchestrators



## 5.1. Injection of Secrets (file, in-memory)



## 5.2. Short-Lived Side-car Containers

When using containers to deliver microservices, consideration should be made to utilise a short-lived side-car container for the purpose of providing secrets for those containers that do not directly support integration to the secrets management solution. A short-lived side-car container is one which serves the purpose of supporting a container that provides a business service, for a brief period of time such as during container boot-up. Such side-car containers can be used provide an application its initial configuration and secrets before being securely erased.

## 5.3. Internal vs External Access



# 6. Implementation Guidance



## 6.1. Key Material Management Policies



## 6.2. Dynamic vs Static Use Cases



## 6.3. Processes and Governance



# 7. Encryption

Secrets should be encrypted whilst at rest on disk and also during transit using Transport Layer Security (TLS).

## 7.1. Encryption as a Service (EaaS)

Some secrets management solutions allow applications to use them as encryption services, for encrypting sensitive data such as social security numbers for example, which is then stored by the application in encrypted form. The application can later decrypt the data using the secrets management solution without needing a decryption key.

# 8. Applications



## 8.1. Least Amount of Impact (LAoI)



## 8.2. Ease of Use



## 8.3. Ease of On-boarding



# 9. Workflow in Case of Compromise



## 9.1. Process



# 10. Secrets Management Tooling Guidelines

* Where supported the use of dynamic secrets should be preferred over the use of static credentials.

* Many native integrations possible (Cloud platforms, CI/CD tooling, application libraries, container orchestrators)
* Secret lifecycle (rotation, deletion, lifespan)
* Key material management (keys to kingdom)
* Open source? (Depending on security posture)
* Encryption (at rest, in transit)
* Access control (fine grained)
* Performance
* Audit logs
* Scalable (enterprise)
* Manageable operations (upgrading, recovery)
* Agnostic
* Support for many secrets backends: database, certificates, SSH keys, cloud providers, key/value, etc
* dynamic secrets
* Encryption as a service
* Fine grained policies (MFA requirements)
* Extensibility
* Documentation

# Authors and Primary Editors

* Dominik de Smit - dominik.de.smit@araido.com
* Anthony Fielding - anthony.fielding@orbital3.com
