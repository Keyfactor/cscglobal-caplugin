## Overview

This integration allows for the Synchronization, Enrollment, and Revocation of certificates from the CSCGlobal. This is the AnyGateway REST version.

## Requirements

This integration is tested and confirmed as working for Anygateway REST 24.2 and above. Notice: Keyfactor Anygateway REST 24.4 requires the use of .Net 8.

## Gateway Registration

The Root certificates for installation on the Anygateway server machine should be obtained from CSC.

## Certificate Template Creation Step

PLEASE NOTE, AT THIS TIME THE RAPID_SSL TEMPLATE IS NOT SUPPORTED BY THE CSC API AND WILL NOT WORK WITH THIS INTEGRATION

The following certificate templates are supported. Please set up the key sizes accordingly in the Certificate Profile menu of Anygateway REST, then enter the remaining details
and the Enrollment Fields for each Template accordingly using the Certificate Templates section in Command. If you would like to set up default values for enrollment parameters, you can do so the in the Certificate Template Menu of Anygateway REST.
If a field value is specified as both an Enrollment Field in Command and in the Certificate Template Menu in the REST Gateway, the value in the Enrollment Field will take precedence.

CONFIG ELEMENT				| DESCRIPTION
----------------------------|------------------
Template Short Name	| CSC TrustedSecure OV
Template Display Name	| CSC TrustedSecure OV
Friendly Name	| CSC TrustedSecure OV
Keys Size  | 2048
Enforce RFC 2818 Compliance | True
CSR Enrollment | True
Pfx Enrollment | True


**CSC TrustedSecure OV - Enrollment Fields**

NAME | DATA TYPE	| VALUES
-----|--------------|-----------------
Term | Multiple Choice | 12,24
Applicant First Name | String | N/A
Applicant Last Name | String | N/A
Applicant Email Address | String | N/A
Applicant Phone | String | N/A
Domain Control Validation Method | Multiple Choice | EMAIL
Organization Contact | Multiple Choice | Get From CSC Differs For Clients
Business Unit | Multiple Choice | Get From CSC Differs For Clients
Notification Email(s) Comma Separated | String | N/A
CN DCV Email | String | N/A

**CSC TrustedSecure OV Wildcard - Details Tab**

CONFIG ELEMENT				| DESCRIPTION
----------------------------|------------------
Template Short Name	| CSC TrustedSecure OV Wildcard
Template Display Name	| CSC TrustedSecure OV Wildcard
Friendly Name	| CSC TrustedSecure OV Wildcard
Keys Size  | 2048
Enforce RFC 2818 Compliance | True
CSR Enrollment | True
Pfx Enrollment | True


**CSC TrustedSecure OV Wildcard - Enrollment Fields**

NAME | DATA TYPE	| VALUES
-----|--------------|-----------------
Term | Multiple Choice | 12,24
Applicant First Name | String | N/A
Applicant Last Name | String | N/A
Applicant Email Address | String | N/A
Applicant Phone | String | N/A
Domain Control Validation Method | Multiple Choice | EMAIL
Organization Contact | Multiple Choice | Get From CSC Differs For Clients
Business Unit | Multiple Choice | Get From CSC Differs For Clients
Notification Email(s) Comma Separated | String | N/A
CN DCV Email | String | N/A

**CSC TrustedSecure OV, Multiple Names - Details Tab**

CONFIG ELEMENT				| DESCRIPTION
----------------------------|------------------
Template Short Name	| CSC TrustedSecure OV, Multiple Names
Template Display Name	| CSC TrustedSecure OV, Multiple Names
Friendly Name	| CSC TrustedSecure OV, Multiple Names
Keys Size  | 2048
Enforce RFC 2818 Compliance | True
CSR Enrollment | True
Pfx Enrollment | True


**CSC TrustedSecure OV, Multiple Names - Enrollment Fields**

NAME | DATA TYPE	| VALUES
-----|--------------|-----------------
Term | Multiple Choice | 12,24
Applicant First Name | String | N/A
Applicant Last Name | String | N/A
Applicant Email Address | String | N/A
Applicant Phone | String | N/A
Domain Control Validation Method | Multiple Choice | EMAIL
Organization Contact | Multiple Choice | Get From CSC Differs For Clients
Business Unit | Multiple Choice | Get From CSC Differs For Clients
Notification Email(s) Comma Separated | String | N/A
CN DCV Email | String | N/A
Addtl Sans Comma Separated DCV Emails | String | N/A

**CSC TrustedSecure EV - Details Tab**

CONFIG ELEMENT				| DESCRIPTION
----------------------------|------------------
Template Short Name	| CSC TrustedSecure EV
Template Display Name	| CSC TrustedSecure EV
Friendly Name	| CSC TrustedSecure EV
Keys Size  | 2048
Enforce RFC 2818 Compliance | True
CSR Enrollment | True
Pfx Enrollment | True


**CSC TrustedSecure EV - Enrollment Fields**

NAME | DATA TYPE	| VALUES
-----|--------------|-----------------
Term | Multiple Choice | 12,24
Applicant First Name | String | N/A
Applicant Last Name | String | N/A
Applicant Email Address | String | N/A
Applicant Phone | String | N/A
Domain Control Validation Method | Multiple Choice | EMAIL
Organization Contact | Multiple Choice | Get From CSC Differs For Clients
Business Unit | Multiple Choice | Get From CSC Differs For Clients
Notification Email(s) Comma Separated | String | N/A
CN DCV Email | String | N/A
Organization Country | String | N/A

**CSC TrustedSecure DV - Details Tab**

CONFIG ELEMENT				| DESCRIPTION
----------------------------|------------------
Template Short Name	| CSC TrustedSecure DV
Template Display Name	| CSC TrustedSecure DV
Friendly Name	| CSC TrustedSecure DV
Keys Size  | 2048
Enforce RFC 2818 Compliance | True
CSR Enrollment | True
Pfx Enrollment | True


**CSC TrustedSecure DV - Enrollment Fields**

NAME | DATA TYPE	| VALUES
-----|--------------|-----------------
Term | Multiple Choice | 12,24
Applicant First Name | String | N/A
Applicant Last Name | String | N/A
Applicant Email Address | String | N/A
Applicant Phone | String | N/A
Domain Control Validation Method | Multiple Choice | EMAIL
Organization Contact | Multiple Choice | Get From CSC Differs For Clients
Business Unit | Multiple Choice | Get From CSC Differs For Clients
Notification Email(s) Comma Separated | String | N/A
CN DCV Email | String | N/A

**CSC TrustedSecure DV Wildcard - Details Tab**

CONFIG ELEMENT				| DESCRIPTION
----------------------------|------------------
Template Short Name	| CSC TrustedSecure DV Wildcard
Template Display Name	| CSC TrustedSecure DV Wildcard
Friendly Name	| CSC TrustedSecure DV Wildcard
Keys Size  | 2048
Enforce RFC 2818 Compliance | True
CSR Enrollment | True
Pfx Enrollment | True


**CSC TrustedSecure DV Wildcard - Enrollment Fields**

NAME | DATA TYPE	| VALUES
-----|--------------|-----------------
Term | Multiple Choice | 12,24
Applicant First Name | String | N/A
Applicant Last Name | String | N/A
Applicant Email Address | String | N/A
Applicant Phone | String | N/A
Domain Control Validation Method | Multiple Choice | EMAIL
Organization Contact | Multiple Choice | Get From CSC Differs For Clients
Business Unit | Multiple Choice | Get From CSC Differs For Clients
Notification Email(s) Comma Separated | String | N/A
CN DCV Email | String | N/A

**CSC TrustedSecure DV, Multiple Names - Details Tab**

CONFIG ELEMENT				| DESCRIPTION
----------------------------|------------------
Template Short Name	| CSC TrustedSecure DV, Multiple Names
Template Display Name	| CSC TrustedSecure DV, Multiple Names
Friendly Name	| CSC TrustedSecure DV, Multiple Names
Keys Size  | 2048
Enforce RFC 2818 Compliance | True
CSR Enrollment | True
Pfx Enrollment | True


**CSC TrustedSecure DV, Multiple Names - Enrollment Fields**

NAME | DATA TYPE	| VALUES
-----|--------------|-----------------
Term | Multiple Choice | 12,24
Applicant First Name | String | N/A
Applicant Last Name | String | N/A
Applicant Email Address | String | N/A
Applicant Phone | String | N/A
Domain Control Validation Method | Multiple Choice | EMAIL
Organization Contact | Multiple Choice | Get From CSC Differs For Clients
Business Unit | Multiple Choice | Get From CSC Differs For Clients
Notification Email(s) Comma Separated | String | N/A
CN DCV Email | String | N/A
Addtl Sans Comma Separated DCV Emails | String | N/A

**CSC TrustedSecure EV, Multiple Names - Details Tab**

CONFIG ELEMENT				| DESCRIPTION
----------------------------|------------------
Template Short Name	| CSC TrustedSecure EV, Multiple Names
Template Display Name	| CSC TrustedSecure EV, Multiple Names
Friendly Name	| CSC TrustedSecure EV, Multiple Names
Keys Size  | 2048
Enforce RFC 2818 Compliance | True
CSR Enrollment | True
Pfx Enrollment | True


**CSC TrustedSecure EV, Multiple Names - Enrollment Fields**

NAME | DATA TYPE	| VALUES
-----|--------------|-----------------
Term | Multiple Choice | 12,24
Applicant First Name | String | N/A
Applicant Last Name | String | N/A
Applicant Email Address | String | N/A
Applicant Phone | String | N/A
Domain Control Validation Method | Multiple Choice | EMAIL
Organization Contact | Multiple Choice | Get From CSC Differs For Clients
Business Unit | Multiple Choice | Get From CSC Differs For Clients
Notification Email(s) Comma Separated | String | N/A
CN DCV Email | String | N/A
Organization Country | String | N/A
Addtl Sans Comma Separated DCV Emails | String | N/A

**CSC TrustedSecure OV Wildcard, Multiple Names - Details Tab**

CONFIG ELEMENT				| DESCRIPTION
----------------------------|------------------
Template Short Name	| CSC TrustedSecure OV Wildcard, Multiple Names
Template Display Name	| CSC TrustedSecure OV Wildcard, Multiple Names
Friendly Name	| CSC TrustedSecure OV Wildcard, Multiple Names
Keys Size  | 2048
Enforce RFC 2818 Compliance | True
CSR Enrollment | True
Pfx Enrollment | True


**CSC TrustedSecure OV Wildcard, Multiple Names - Enrollment Fields**

NAME | DATA TYPE	| VALUES
-----|--------------|-----------------
Term | Multiple Choice | 12,24
Applicant First Name | String | N/A
Applicant Last Name | String | N/A
Applicant Email Address | String | N/A
Applicant Phone | String | N/A
Domain Control Validation Method | Multiple Choice | EMAIL
Organization Contact | Multiple Choice | Get From CSC Differs For Clients
Business Unit | Multiple Choice | Get From CSC Differs For Clients
Notification Email(s) Comma Separated | String | N/A
CN DCV Email | String | N/A
Addtl Sans Comma Separated DCV Emails | String | N/A

**CSC TrustedSecure DV Wildcard, Multiple Names - Details Tab**

CONFIG ELEMENT				| DESCRIPTION
----------------------------|------------------
Template Short Name	| CSC TrustedSecure DV Wildcard, Multiple Names
Template Display Name	| CSC TrustedSecure DV Wildcard, Multiple Names
Friendly Name	| CSC TrustedSecure DV Wildcard, Multiple Names
Keys Size  | 2048
Enforce RFC 2818 Compliance | True
CSR Enrollment | True
Pfx Enrollment | True


**CSC TrustedSecure DV Wildcard, Multiple Names - Enrollment Fields**

NAME | DATA TYPE	| VALUES
-----|--------------|-----------------
Term | Multiple Choice | 12,24
Applicant First Name | String | N/A
Applicant Last Name | String | N/A
Applicant Email Address | String | N/A
Applicant Phone | String | N/A
Domain Control Validation Method | Multiple Choice | EMAIL
Organization Contact | Multiple Choice | Get From CSC Differs For Clients
Business Unit | Multiple Choice | Get From CSC Differs For Clients
Notification Email(s) Comma Separated | String | N/A
CN DCV Email | String | N/A
Addtl Sans Comma Separated DCV Emails | String | N/A

