<h1 align="center" style="border-bottom: none">
    CSCGlobal CAPlugin AnyCA Gateway REST Plugin
</h1>

<p align="center">
  <!-- Badges -->
<img src="https://img.shields.io/badge/integration_status-pilot-3D1973?style=flat-square" alt="Integration Status: pilot" />
<a href="https://github.com/Keyfactor/cscglobal-caplugin/releases"><img src="https://img.shields.io/github/v/release/Keyfactor/cscglobal-caplugin?style=flat-square" alt="Release" /></a>
<img src="https://img.shields.io/github/issues/Keyfactor/cscglobal-caplugin?style=flat-square" alt="Issues" />
<img src="https://img.shields.io/github/downloads/Keyfactor/cscglobal-caplugin/total?style=flat-square&label=downloads&color=28B905" alt="GitHub Downloads (all assets, all releases)" />
</p>

<p align="center">
  <!-- TOC -->
  <a href="#support">
    <b>Support</b>
  </a> 
  ·
  <a href="#requirements">
    <b>Requirements</b>
  </a>
  ·
  <a href="#installation">
    <b>Installation</b>
  </a>
  ·
  <a href="#license">
    <b>License</b>
  </a>
  ·
  <a href="https://github.com/orgs/Keyfactor/repositories?q=anycagateway">
    <b>Related Integrations</b>
  </a>
</p>


This integration allows for the Synchronization, Enrollment, and Revocation of certificates from the CSCGlobal. This is the AnyGateway REST version.

## Compatibility

The CSCGlobal CAPlugin AnyCA Gateway REST plugin is compatible with the Keyfactor AnyCA Gateway REST 24.2.0 and later.

## Support
The CSCGlobal CAPlugin AnyCA Gateway REST plugin is supported by Keyfactor for Keyfactor customers. If you have a support issue, please open a support ticket with your Keyfactor representative. If you have a support issue, please open a support ticket via the Keyfactor Support Portal at https://support.keyfactor.com. 

> To report a problem or suggest a new feature, use the **[Issues](../../issues)** tab. If you want to contribute actual bug fixes or proposed enhancements, use the **[Pull requests](../../pulls)** tab.

## Requirements

This integration is tested and confirmed as working for Anygateway REST 24.2 and above. Notice: Keyfactor Anygateway REST 24.4 requires the use of .Net 8.

## Installation

1. Install the AnyCA Gateway REST per the [official Keyfactor documentation](https://software.keyfactor.com/Guides/AnyCAGatewayREST/Content/AnyCAGatewayREST/InstallIntroduction.htm).

2. On the server hosting the AnyCA Gateway REST, download and unzip the latest [CSCGlobal CAPlugin AnyCA Gateway REST plugin](https://github.com/Keyfactor/cscglobal-caplugin/releases/latest) from GitHub.

3. Copy the unzipped directory (usually called `net6.0` or `net8.0`) to the Extensions directory:


    ```shell
    Depending on your AnyCA Gateway REST version, copy the unzipped directory to one of the following locations:
    Program Files\Keyfactor\AnyCA Gateway\AnyGatewayREST\net6.0\Extensions
    Program Files\Keyfactor\AnyCA Gateway\AnyGatewayREST\net8.0\Extensions
    ```

    > The directory containing the CSCGlobal CAPlugin AnyCA Gateway REST plugin DLLs (`net6.0` or `net8.0`) can be named anything, as long as it is unique within the `Extensions` directory.

4. Restart the AnyCA Gateway REST service.

5. Navigate to the AnyCA Gateway REST portal and verify that the Gateway recognizes the CSCGlobal CAPlugin plugin by hovering over the ⓘ symbol to the right of the Gateway on the top left of the portal.

## Configuration

1. Follow the [official AnyCA Gateway REST documentation](https://software.keyfactor.com/Guides/AnyCAGatewayREST/Content/AnyCAGatewayREST/AddCA-Gateway.htm) to define a new Certificate Authority, and use the notes below to configure the **Gateway Registration** and **CA Connection** tabs:

    * **Gateway Registration**

        The Root certificates for installation on the Anygateway server machine should be obtained from CSC.

    * **CA Connection**

        Populate using the configuration fields collected in the [requirements](#requirements) section.

        * **CscGlobalUrl** - CSCGlobal API URL 
        * **ApiKey** - CSCGlobal API Key 
        * **BearerToken** - CSCGlobal Bearer Token 
        * **DefaultPageSize** - Default page size for use with the API. Default is 100 
        * **SyncFilterDays** - Number of days from today to filter certificates by expiration date during incremental sync. 
        * **RenewalWindowDays** - Number of days before the annual order expiry within which a RenewOrReissue triggers a paid Renewal rather than a free Reissue. Default is 30. 

2. PLEASE NOTE, AT THIS TIME THE RAPID_SSL TEMPLATE IS NOT SUPPORTED BY THE CSC API AND WILL NOT WORK WITH THIS INTEGRATION

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

3. Follow the [official Keyfactor documentation](https://software.keyfactor.com/Guides/AnyCAGatewayREST/Content/AnyCAGatewayREST/AddCA-Keyfactor.htm) to add each defined Certificate Authority to Keyfactor Command and import the newly defined Certificate Templates.

4. In Keyfactor Command (v12.3+), for each imported Certificate Template, follow the [official documentation](https://software.keyfactor.com/Core-OnPrem/Current/Content/ReferenceGuide/Configuring%20Template%20Options.htm) to define enrollment fields for each of the following parameters:

    * **Term** - OPTIONAL: Certificate term (e.g. 12 or 24 months) 
    * **Applicant First Name** - OPTIONAL: Applicant First Name 
    * **Applicant Last Name** - OPTIONAL: Applicant Last Name 
    * **Applicant Email Address** - OPTIONAL: Applicant Email Address 
    * **Applicant Phone** - OPTIONAL: Applicant Phone (+nn.nnnnnnnn) 
    * **Domain Control Validation Method** - OPTIONAL: Domain Control Validation Method (e.g. EMAIL) 
    * **Organization Contact** - OPTIONAL: Organization Contact (selected from CSC configuration) 
    * **Business Unit** - OPTIONAL: Business Unit (selected from CSC configuration) 
    * **Notification Email(s) Comma Separated** - OPTIONAL: Notification Email(s), comma separated 
    * **CN DCV Email** - OPTIONAL: CN DCV Email (e.g. admin@yourdomain.com) 
    * **Organization Country** - OPTIONAL: Organization Country 
    * **Addtl Sans Comma Separated DCV Emails** - OPTIONAL: Additional SANs DCV Emails, comma separated 


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

> **Note:** DNS auto-publishing is configured by deploying provider DLLs, not via a CA setting. See [Pluggable DNS Providers](#pluggable-dns-providers).

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

## Pluggable DNS Providers

CSC supports two Domain Control Validation (DCV) methods: **EMAIL** and **CNAME**. With CNAME validation, CSC returns a CNAME record (name → target) that must exist in DNS before they will validate the order.

By default this plugin returns the CNAME details to Keyfactor Command for **manual publishing**. To fully automate enrollment, you can deploy one or more DNS provider DLLs alongside the plugin — the framework will publish each CNAME via the provider that owns the matching DNS zone.

### Behavior

* **Resolution is per record, not per CA.** When a CSC order returns CNAME details, the plugin asks each registered DNS provider `CanHandleDomain(recordName)`. The first provider that claims the zone publishes the record. One CA can drive multiple providers (e.g. Cloudflare for some domains, Route 53 for others) with no per-CA configuration.
* **Only invoked for CNAME DCV.** Templates configured with EMAIL validation are unaffected.
* **Best-effort.** If no registered provider owns the zone, or the publish call fails, the enrollment still succeeds and the CNAME details are still surfaced to Keyfactor Command so a human can publish manually as a fallback.
* **Trace-logged.** Every resolution and publish attempt (success, failure, unresolved) is logged so issues are visible without surprising end users.

### Authoring a DNS Provider

A DNS provider is a separate DLL that implements `Keyfactor.Extensions.CAPlugin.CSCGlobal.Interfaces.IDnsProvider`:

```csharp
public interface IDnsProvider
{
    string Name { get; }
    bool CanHandleDomain(string recordName);
    Task<bool> CreateCnameRecordAsync(string recordName, string cnameTarget, CancellationToken cancellationToken = default);
    Task<bool> DeleteCnameRecordAsync(string recordName, CancellationToken cancellationToken = default);
}
```

`CanHandleDomain` is the resolution hook — implementations typically list managed zones from the provider's API (cached at construction time) and return true when `recordName` falls within one of them.

To wire a provider into the gateway:

1. Build the provider as a separate DLL referencing the CSC plugin's `IDnsProvider` interface.
2. Drop the DLL into the gateway `Extensions` folder alongside this plugin.
3. Add provider-specific configuration keys to the CA Connection tab (for example `Cloudflare_ApiToken`, `Route53_AccessKey`, `Route53_SecretKey`).
4. Add a registration line to `DnsProviderFactory.LoadProviders()` that instantiates the provider when its required keys are present.

### Currently Built-In Providers

None at this time. The framework is in place; concrete provider implementations are tracked separately.


## License

Apache License 2.0, see [LICENSE](LICENSE).

## Related Integrations

See all [Keyfactor Any CA Gateways (REST)](https://github.com/orgs/Keyfactor/repositories?q=anycagateway).