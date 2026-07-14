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
Enabled | Flag to Enable or Disable gateway functionality. Set to `false` to allow creating the CA record before configuration information is available; the plugin then short-circuits Ping, Sync, Enroll, and Revoke with a warning until it is re-enabled. | `true`
CscGlobalUrl | The base URL for the CSCGlobal API (e.g. `https://apis.cscglobal.com`) | (required)
ApiKey | Your CSCGlobal API key | (required)
BearerToken | Your CSCGlobal Bearer token for authentication | (required)
DefaultPageSize | Page size for API list requests | 100
SyncFilterDays | Number of days from today used to filter certificates by expiration date during **incremental** sync. Only certificates expiring within this window are returned. Does not apply to full sync. | 5
RenewalWindowDays | Number of days before the annual order expiry date within which a **RenewOrReissue** request triggers a paid **Renewal** rather than a free **Reissue**. See [Renewal vs. Reissue Logic](#renewal-vs-reissue-logic) below. | 30
DcvPollTimeoutSeconds | Max seconds to synchronously poll CSC for certificate issuance after submitting an order. `0` disables polling (enrollment returns pending immediately; cert arrives on the next sync). When `>0`, fast-validating orders can return the issued cert directly in the enrollment response. See [Synchronous Issuance Polling](#synchronous-issuance-polling) below. | 0

> **Note:** DNS auto-publishing for CNAME DCV is handled by the AnyCA Gateway REST framework's Domain Validation system (gateway 3.3+). It's configured in the gateway UI under **Domain Validation Configurations**, not on the CA Connection tab. See [DNS Auto-Publishing (CNAME DCV)](#dns-auto-publishing-cname-dcv).

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

## DNS Auto-Publishing (CNAME DCV)

CSC supports two Domain Control Validation (DCV) methods: **EMAIL** and **CNAME**. With CNAME validation, CSC returns a CNAME record (name → target) that must exist in DNS before they will validate the order.

By default this plugin returns the CNAME details to Keyfactor Command for **manual publishing**. To fully automate enrollment, the plugin uses the **AnyCA Gateway REST framework's built-in DNS provider system** (available in framework 3.3 and later). The framework discovers DNS provider plugins deployed alongside the CA plugin and routes each CNAME to whichever provider claims the matching DNS zone.

### Requirements

* AnyCA Gateway REST framework **3.3 or later** (the `IDomainValidatorFactory` interface ships in `Keyfactor.AnyGateway.IAnyCAPlugin` 3.3+).
* At least one DNS provider DLL (e.g. GoDaddy, Cloudflare, Route 53, Azure) deployed in the gateway `Extensions` folder.
* A Domain Validation Configuration registered in the gateway UI that maps your domain(s) to the deployed provider (for example, `*.example.com` → GoDaddy).

### How It Works

1. CSC returns the CNAME `name → target` details in the enrollment response.
2. For each CNAME entry, the plugin calls `IDomainValidatorFactory.ResolveDomainValidator(recordName, "cname")`.
3. The framework returns the `IDomainValidator` whose Domain Validation Configuration matches the record's zone (or `null` if no match).
4. The plugin calls `validator.StageValidation(recordName, cnameTarget, ct)` to publish the record.
5. CSC asynchronously validates the CNAME; the issued certificate appears on the next sync.

### Behavior

* **Resolution is per record, not per CA.** One CA can drive multiple DNS providers (GoDaddy for some domains, Route 53 for others) with no per-CA configuration.
* **Only invoked for CNAME DCV.** Templates configured with EMAIL validation are unaffected — no DNS publishing occurs.
* **Best-effort.** If no provider claims the zone, the publish call fails, or the factory wasn't injected (gateway pre-3.3), the enrollment still succeeds and the CNAME details remain in the Keyfactor request so a human can publish manually as a fallback.
* **Trace-logged.** Every resolution (matched/unresolved) and publish attempt (success/failure) is logged at Info/Trace level.
* **Validation type string.** The plugin passes `"cname"` to `ResolveDomainValidator`. CSC's DCV requires a **CNAME** record, which is different from ACME's `"dns-01"` challenge (a TXT record). A single DNS provider DLL can ship multiple validator classes — one advertising `"dns-01"` (publishes TXT, for ACME) and one advertising `"cname"` (publishes CNAME, for CSC). You must deploy and configure a validator that advertises `"cname"` or no provider will match.
* **Trailing dots normalized.** CSC returns FQDN-canonical names with a trailing dot (e.g. `_token.example.com.`). The plugin strips the trailing dot before resolution and publishing, because Domain Validation Configurations and DNS provider APIs expect names without it.

### Configuration in the Gateway UI

In the AnyCA Gateway REST portal, under **Domain Validation Configurations**:

1. **Add** a new configuration.
2. Pick a **Domain Validator Type** that publishes **CNAME** records and advertises validation type `cname`. For GoDaddy this is `GoDaddyCnameDomainValidator` (the `GoDaddyDomainValidator` variant publishes TXT for ACME and will **not** work for CSC).
3. Add one or more **domain patterns** (e.g. `*.example.com`).
4. Fill out the provider-specific **Configuration Settings** (API keys, base URL, etc.).
5. Save.

Once configured, any CSC enrollment for a domain matching one of those patterns will have its CNAME auto-published.

> **Common pitfall:** If you configure the TXT/`dns-01` validator (e.g. `GoDaddyDomainValidator`) for a CSC domain, the record will publish as a **TXT** and CSC's CNAME validation will never succeed. Make sure you select the **CNAME** validator variant.

## Synchronous Issuance Polling

CSC validates domain control asynchronously — after an order is submitted (and the CNAME DCV record published), CSC/Sectigo polls public DNS on its own schedule and issues the certificate once validation passes. By default this plugin returns a **pending** (`EXTERNALVALIDATION`) result immediately and the issued certificate is picked up on the next gateway **sync** cycle.

For environments where DNS is published automatically (see [DNS Auto-Publishing](#dns-auto-publishing-cname-dcv)) and validation tends to complete quickly, you can have the plugin **poll CSC synchronously** at the end of enrollment and return the issued certificate directly — avoiding the wait for the next sync.

* Set **`DcvPollTimeoutSeconds`** to the maximum number of seconds to poll (e.g. `60`). `0` (default) disables polling entirely.
* The plugin polls CSC every 10 seconds until the order is issued or the timeout is reached.
* If the certificate issues within the window, the enrollment returns it immediately with a success status.
* If the window expires, the plugin falls back to the **pending** result and the certificate arrives on the next sync — exactly as it would with polling disabled.

**Tradeoff:** Polling blocks the enrollment request for up to `DcvPollTimeoutSeconds`. CSC validation frequently takes minutes to hours, so most orders will still fall through to pending — keep the timeout small (30–90s) to catch only the fast cases without hanging callers. This applies to New enrollments, Renewals, and Reissues.

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

