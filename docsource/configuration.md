## Overview

This integration allows for the Synchronization, Enrollment, and Revocation of certificates from the CSCGlobal. This is the AnyGateway REST version.

## Requirements

This integration is tested and confirmed as working for Anygateway REST 24.2 and above. Notice: Keyfactor Anygateway REST 24.4 requires the use of .Net 8.

## Gateway Registration

The Root certificates for installation on the Anygateway server machine should be obtained from CSC.

## Certificate Template Creation Step

PLEASE NOTE, AT THIS TIME THE RAPID_SSL TEMPLATE IS NOT SUPPORTED BY THE CSC API AND WILL NOT WORK WITH THIS INTEGRATION

The following templates are supported. Please set up the key sizes accordingly in the Certificate Profile menu of Anygateway REST, then enter the remaining details
and the Enrollment Fields for each Template accordingly using the Certificate Templates section in Command:

CONFIG ELEMENT				| DESCRIPTION
----------------------------|------------------
Template Short Name	| CSC TrustedSecure Premium Certificate
Template Display Name	| CSC TrustedSecure Premium Certificate
Friendly Name	| CSC TrustedSecure Premium Certificate
Keys Size  | 2048
Enforce RFC 2818 Compliance | True
CSR Enrollment | True
Pfx Enrollment | True


**CSC TrustedSecure Premium Certificate - Enrollment Fields**

NAME | DATA TYPE	| VALUES
-----|--------------|-----------------
Term | Multiple Choice | 12,24
Applicant First Name | String | N/A
Applicant Last Name | String | N/A
Applicant Email Address | String | N/A
Applicant Phone (+nn.nnnnnnnn) | String | N/A
Domain Control Validation Method | Multiple Choice | EMAIL
Organization Contact | Multiple Choice | Get From CSC Differs For Clients
Business Unit | Multiple Choice | Get From CSC Differs For Clients
Notification Email(s) Comma Separated | String | N/A
CN DCV Email (admin@yourdomain.com) | String | N/A

**CSC TrustedSecure EV Certificate - Details Tab**

CONFIG ELEMENT				| DESCRIPTION
----------------------------|------------------
Template Short Name	| CSC TrustedSecure EV Certificate
Template Display Name	| CSC TrustedSecure EV Certificate
Friendly Name	| CSC TrustedSecure EV Certificate
Keys Size  | 2048
Enforce RFC 2818 Compliance | True
CSR Enrollment | True
Pfx Enrollment | True


**CSC TrustedSecure EV Certificate - Enrollment Fields**

NAME | DATA TYPE	| VALUES
-----|--------------|-----------------
Term | Multiple Choice | 12,24
Applicant First Name | String | N/A
Applicant Last Name | String | N/A
Applicant Email Address | String | N/A
Applicant Phone (+nn.nnnnnnnn) | String | N/A
Domain Control Validation Method | Multiple Choice | EMAIL
Organization Contact | Multiple Choice | Get From CSC Differs For Clients
Business Unit | Multiple Choice | Get From CSC Differs For Clients
Notification Email(s) Comma Separated | String | N/A
CN DCV Email (admin@yourdomain.com) | String | N/A
Organization Country | String | N/A

**CSC TrustedSecure UC Certificate - Details Tab**

CONFIG ELEMENT				| DESCRIPTION
----------------------------|------------------
Template Short Name	| CSC TrustedSecure UC Certificate
Template Display Name	| CSC TrustedSecure UC Certificate
Friendly Name	| CSC TrustedSecure UC Certificate
Keys Size  | 2048
Enforce RFC 2818 Compliance | True
CSR Enrollment | True
Pfx Enrollment | True


**CSC TrustedSecure UC Certificate - Enrollment Fields**

NAME | DATA TYPE	| VALUES
-----|--------------|-----------------
Term | Multiple Choice | 12,24
Applicant First Name | String | N/A
Applicant Last Name | String | N/A
Applicant Email Address | String | N/A
Applicant Phone (+nn.nnnnnnnn) | String | N/A
Domain Control Validation Method | Multiple Choice | EMAIL
Organization Contact | Multiple Choice | Get From CSC Differs For Clients
Business Unit | Multiple Choice | Get From CSC Differs For Clients
Notification Email(s) Comma Separated | String | N/A
CN DCV Email (admin@yourdomain.com) | String | N/A
Addtl Sans Comma Separated DVC Emails | String | N/A
	

**CSC TrustedSecure Premium Wildcard Certificate - Details Tab**

CONFIG ELEMENT				| DESCRIPTION
----------------------------|------------------
Template Short Name	| CSC TrustedSecure Premium Wildcard Certificate
Template Display Name	| CSC TrustedSecure Premium Wildcard Certificate
Friendly Name	| CSC TrustedSecure Premium Wildcard Certificate
Keys Size  | 2048
Enforce RFC 2818 Compliance | True
CSR Enrollment | True
Pfx Enrollment | True


**CSC TrustedSecure Premium Wildcard Certificate - Enrollment Fields**

NAME | DATA TYPE	| VALUES
-----|--------------|-----------------
Term | Multiple Choice | 12,24
Applicant First Name | String | N/A
Applicant Last Name | String | N/A
Applicant Email Address | String | N/A
Applicant Phone (+nn.nnnnnnnn) | String | N/A
Domain Control Validation Method | Multiple Choice | EMAIL
Organization Contact | Multiple Choice | Get From CSC Differs For Clients
Business Unit | Multiple Choice | Get From CSC Differs For Clients
Notification Email(s) Comma Separated | String | N/A
CN DCV Email (admin@yourdomain.com) | String | N/A

**CSC TrustedSecure Domain Validated SSL - Details Tab**

CONFIG ELEMENT				| DESCRIPTION
----------------------------|------------------
Template Short Name	| CSC TrustedSecure Domain Validated SSL
Template Display Name	| CSC TrustedSecure Domain Validated SSL
Friendly Name	| CSC TrustedSecure Domain Validated SSL
Keys Size  | 2048
Enforce RFC 2818 Compliance | True
CSR Enrollment | True
Pfx Enrollment | True


**CSC TrustedSecure Domain Validated SSL - Enrollment Fields**

NAME | DATA TYPE	| VALUES
-----|--------------|-----------------
Term | Multiple Choice | 12,24
Applicant First Name | String | N/A
Applicant Last Name | String | N/A
Applicant Email Address | String | N/A
Applicant Phone (+nn.nnnnnnnn) | String | N/A
Domain Control Validation Method | Multiple Choice | EMAIL
Organization Contact | Multiple Choice | Get From CSC Differs For Clients
Business Unit | Multiple Choice | Get From CSC Differs For Clients
Notification Email(s) Comma Separated | String | N/A
CN DCV Email (admin@yourdomain.com) | String | N/A

**CSC TrustedSecure Domain Validated Wildcard SSL - Details Tab**

CONFIG ELEMENT				| DESCRIPTION
----------------------------|------------------
Template Short Name	| CSC TrustedSecure Domain Validated Wildcard SSL
Template Display Name	| CSC TrustedSecure Domain Validated Wildcard SSL
Friendly Name	| CSC TrustedSecure Domain Validated Wildcard SSL
Keys Size  | 2048
Enforce RFC 2818 Compliance | True
CSR Enrollment | True
Pfx Enrollment | True


**CSC TrustedSecure Domain Validated Wildcard SSL - Enrollment Fields**

NAME | DATA TYPE	| VALUES
-----|--------------|-----------------
Term | Multiple Choice | 12,24
Applicant First Name | String | N/A
Applicant Last Name | String | N/A
Applicant Email Address | String | N/A
Applicant Phone (+nn.nnnnnnnn) | String | N/A
Domain Control Validation Method | Multiple Choice | EMAIL
Organization Contact | Multiple Choice | Get From CSC Differs For Clients
Business Unit | Multiple Choice | Get From CSC Differs For Clients
Notification Email(s) Comma Separated | String | N/A
CN DCV Email (admin@yourdomain.com) | String | N/A

**CSC TrustedSecure Domain Validated UC Certificate - Details Tab**

CONFIG ELEMENT				| DESCRIPTION
----------------------------|------------------
Template Short Name	| CSC TrustedSecure Domain Validated UC Certificate
Template Display Name	| CSC TrustedSecure Domain Validated UC Certificate
Friendly Name	| CSC TrustedSecure Domain Validated UC Certificate
Keys Size  | 2048
Enforce RFC 2818 Compliance | True
CSR Enrollment | True
Pfx Enrollment | True


**CSC TrustedSecure Domain Validated UC Certificate - Enrollment Fields**

NAME | DATA TYPE	| VALUES
-----|--------------|-----------------
Term | Multiple Choice | 12,24
Applicant First Name | String | N/A
Applicant Last Name | String | N/A
Applicant Email Address | String | N/A
Applicant Phone (+nn.nnnnnnnn) | String | N/A
Domain Control Validation Method | Multiple Choice | EMAIL
Organization Contact | Multiple Choice | Get From CSC Differs For Clients
Business Unit | Multiple Choice | Get From CSC Differs For Clients
Notification Email(s) Comma Separated | String | N/A
CN DCV Email (admin@yourdomain.com) | String | N/A
Addtl Sans Comma Separated DVC Emails | String | N/A

