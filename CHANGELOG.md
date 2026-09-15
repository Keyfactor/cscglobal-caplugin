v1.2.0
- Added support for CSC TrustedSecure EV, Multiple Names; CSC TrustedSecure OV Wildcard, Multiple Names; and CSC TrustedSecure DV Wildcard, Multiple Names certificate products
- BREAKING: Renamed all certificate template product IDs to match CSC's current certificate type names (e.g. "CSC TrustedSecure Premium Certificate" is now "CSC TrustedSecure OV", "CSC TrustedSecure Domain Validated SSL" is now "CSC TrustedSecure DV"). Existing Certificate Templates in Command must have their Template Short Name updated to match.
- Removed the TemplateSync gateway registration setting. Certificate sync now always maps synced certificates back to their CSC certificate type/template.

v.1.1.1
- Added Incremental Sync that goes back X Number of days
- Fixed issue with parsing certain certificates that were in zip format
- Fixed Missing Default Values for Template Enrollment Parameters
- Fixed Issue Template Configuration Params Missing and Certificate Profile Mapping Not Present

v.1.0.2
- Warning: enrollment field/template parameter with the name "CN DCV Email (admin@boingy.com)" has been renamed to "CN DCV Email" to make it compatible with the REST gateway. "Aplicant Pgone (+nn.nnnnnnnn)" has also been renamed to "Applicant Phone".
- Updated dependencies.
- Added support for default values via enrollment parameters configured in the AnyGateway REST certificate template.
- Fixed issue with non-ASCII characters breaking the gateway.

v1.0.1 
- Fixed issue with SANs not being read correctly.

v1.0

- Initial Release.
