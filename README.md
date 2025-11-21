<h1 align="center" style="border-bottom: none">
    CSCGlobal CA  Gateway AnyCA Gateway REST Plugin
</h1>

<p align="center">
  <!-- Badges -->
<img src="https://img.shields.io/badge/integration_status-pilot-3D1973?style=flat-square" alt="Integration Status: pilot" />
<a href="https://github.com/Keyfactor/cscglobal-caplugin-dev/releases"><img src="https://img.shields.io/github/v/release/Keyfactor/cscglobal-caplugin-dev?style=flat-square" alt="Release" /></a>
<img src="https://img.shields.io/github/issues/Keyfactor/cscglobal-caplugin-dev?style=flat-square" alt="Issues" />
<img src="https://img.shields.io/github/downloads/Keyfactor/cscglobal-caplugin-dev/total?style=flat-square&label=downloads&color=28B905" alt="GitHub Downloads (all assets, all releases)" />
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

The CSCGlobal CA  Gateway AnyCA Gateway REST plugin is compatible with the Keyfactor AnyCA Gateway REST 24.2.0 and later.

## Support
The CSCGlobal CA  Gateway AnyCA Gateway REST plugin is supported by Keyfactor for Keyfactor customers. If you have a support issue, please open a support ticket with your Keyfactor representative. If you have a support issue, please open a support ticket via the Keyfactor Support Portal at https://support.keyfactor.com. 

> To report a problem or suggest a new feature, use the **[Issues](../../issues)** tab. If you want to contribute actual bug fixes or proposed enhancements, use the **[Pull requests](../../pulls)** tab.

## Requirements

This integration is tested and confirmed as working for Anygateway REST 24.2 and above. Notice: Keyfactor Anygateway REST 24.4 requires the use of .Net 8.

## Installation

1. Install the AnyCA Gateway REST per the [official Keyfactor documentation](https://software.keyfactor.com/Guides/AnyCAGatewayREST/Content/AnyCAGatewayREST/InstallIntroduction.htm).

2. On the server hosting the AnyCA Gateway REST, download and unzip the latest [CSCGlobal CA  Gateway AnyCA Gateway REST plugin](https://github.com/Keyfactor/cscglobal-caplugin-dev/releases/latest) from GitHub.

3. Copy the unzipped directory (usually called `net6.0` or `net8.0`) to the Extensions directory:


    ```shell
    Depending on your AnyCA Gateway REST version, copy the unzipped directory to one of the following locations:
    Program Files\Keyfactor\AnyCA Gateway\AnyGatewayREST\net6.0\Extensions
    Program Files\Keyfactor\AnyCA Gateway\AnyGatewayREST\net8.0\Extensions
    ```

    > The directory containing the CSCGlobal CA  Gateway AnyCA Gateway REST plugin DLLs (`net6.0` or `net8.0`) can be named anything, as long as it is unique within the `Extensions` directory.

4. Restart the AnyCA Gateway REST service.

5. Navigate to the AnyCA Gateway REST portal and verify that the Gateway recognizes the CSCGlobal CA  Gateway plugin by hovering over the ⓘ symbol to the right of the Gateway on the top left of the portal.

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
        * **TemplateSync** - Enable template sync. 

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



## License

Apache License 2.0, see [LICENSE](LICENSE).

## Related Integrations

See all [Keyfactor Any CA Gateways (REST)](https://github.com/orgs/Keyfactor/repositories?q=anycagateway).