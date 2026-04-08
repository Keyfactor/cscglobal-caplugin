## Overview

This integration allows for the Synchronization, Enrollment, and Revocation of certificates from the CSCGlobal. This is the AnyGateway REST version.

## Requirements

This integration is tested and confirmed as working for Anygateway REST 24.2 and above. Notice: Keyfactor Anygateway REST 24.4 requires the use of .Net 8.

## Gateway Registration

The Root certificates for installation on the Anygateway server machine should be obtained from CSC.

## CA Connection Configuration

When defining the Certificate Authority in the AnyCA Gateway REST portal, configure the following fields on the **CA Connection** tab:

CONFIG ELEMENT | DESCRIPTION | DEFAULT
---------------|-------------|--------
CscGlobalUrl | The base URL for the CSCGlobal API (e.g. `https://apis.cscglobal.com`) | (required)
ApiKey | Your CSCGlobal API key | (required)
BearerToken | Your CSCGlobal Bearer token for authentication | (required)
DefaultPageSize | Page size for API list requests | 100
SyncFilterDays | Number of days from today used to filter certificates by expiration date during **incremental** sync. Only certificates expiring within this window are returned. Does not apply to full sync. | 5
RenewalWindowDays | Number of days before the annual order expiry date within which a **RenewOrReissue** request triggers a paid **Renewal** rather than a free **Reissue**. See [Renewal vs. Reissue Logic](#renewal-vs-reissue-logic) below. | 30

## Renewal vs. Reissue Logic

CSC Global subscriptions are annual orders. When Keyfactor Command sends a **RenewOrReissue** request, the plugin must decide whether to submit a **Renewal** (a new paid order) or a **Reissue** (a free re-key under the existing active order).

The decision is based on the **RenewalWindowDays** setting and works as follows:

1. The plugin fetches the original certificate from CSC and reads its `orderDate`.
2. It computes the **order expiry** as `orderDate + 1 year`.
3. It calculates **days remaining** until the order expires.
4. If `days remaining <= RenewalWindowDays`, the request is treated as a **Renewal** (new paid order).
5. If `days remaining > RenewalWindowDays`, the request is treated as a **Reissue** (free under the active order).

**Example with default RenewalWindowDays = 30:**

```
Order Date:    2025-04-08
Order Expiry:  2026-04-08
Today:         2026-03-15
Days Left:     24

24 <= 30  -->  RENEWAL (new paid order)
```

```
Order Date:    2025-04-08
Order Expiry:  2026-04-08
Today:         2025-09-01
Days Left:     219

219 > 30  -->  REISSUE (free under active order)
```

**Fallback behavior:** If the plugin cannot retrieve the `orderDate` from CSC (e.g., API error or missing field), it falls back to checking the certificate's expiration date. If the certificate is already expired, it treats the request as a Renewal.

**Note:** Both Renewal and Reissue submissions are asynchronous at CSC. The plugin returns a "pending" status and the issued certificate will appear in Keyfactor after the next sync cycle.

## Certificate Template Creation Step

PLEASE NOTE, AT THIS TIME THE RAPID_SSL TEMPLATE IS NOT SUPPORTED BY THE CSC API AND WILL NOT WORK WITH THIS INTEGRATION

The following certificate templates are supported. Please set up the key sizes accordingly in the Certificate Profile menu of Anygateway REST, then enter the remaining details
and the Enrollment Fields for each Template accordingly using the Certificate Templates section in Command. If you would like to set up default values for enrollment parameters, you can do so the in the Certificate Template Menu of Anygateway REST.
If a field value is specified as both an Enrollment Field in Command and in the Certificate Template Menu in the REST Gateway, the value in the Enrollment Field will take precedence.

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
Applicant Phone | String | N/A
Domain Control Validation Method | Multiple Choice | EMAIL
Organization Contact | Multiple Choice | Get From CSC Differs For Clients
Business Unit | Multiple Choice | Get From CSC Differs For Clients
Notification Email(s) Comma Separated | String | N/A
CN DCV Email | String | N/A

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
Applicant Phone | String | N/A
Domain Control Validation Method | Multiple Choice | EMAIL
Organization Contact | Multiple Choice | Get From CSC Differs For Clients
Business Unit | Multiple Choice | Get From CSC Differs For Clients
Notification Email(s) Comma Separated | String | N/A
CN DCV Email | String | N/A
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
Applicant Phone | String | N/A
Domain Control Validation Method | Multiple Choice | EMAIL
Organization Contact | Multiple Choice | Get From CSC Differs For Clients
Business Unit | Multiple Choice | Get From CSC Differs For Clients
Notification Email(s) Comma Separated | String | N/A
CN DCV Email | String | N/A
Addtl Sans Comma Separated DCV Emails | String | N/A
	

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
Applicant Phone | String | N/A
Domain Control Validation Method | Multiple Choice | EMAIL
Organization Contact | Multiple Choice | Get From CSC Differs For Clients
Business Unit | Multiple Choice | Get From CSC Differs For Clients
Notification Email(s) Comma Separated | String | N/A
CN DCV Email | String | N/A

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
Applicant Phone | String | N/A
Domain Control Validation Method | Multiple Choice | EMAIL
Organization Contact | Multiple Choice | Get From CSC Differs For Clients
Business Unit | Multiple Choice | Get From CSC Differs For Clients
Notification Email(s) Comma Separated | String | N/A
CN DCV Email | String | N/A

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
Applicant Phone | String | N/A
Domain Control Validation Method | Multiple Choice | EMAIL
Organization Contact | Multiple Choice | Get From CSC Differs For Clients
Business Unit | Multiple Choice | Get From CSC Differs For Clients
Notification Email(s) Comma Separated | String | N/A
CN DCV Email | String | N/A

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
Applicant Phone | String | N/A
Domain Control Validation Method | Multiple Choice | EMAIL
Organization Contact | Multiple Choice | Get From CSC Differs For Clients
Business Unit | Multiple Choice | Get From CSC Differs For Clients
Notification Email(s) Comma Separated | String | N/A
CN DCV Email | String | N/A
Addtl Sans Comma Separated DCV Emails | String | N/A

