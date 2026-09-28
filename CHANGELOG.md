v1.2.0
- Added support for CSC TrustedSecure EV, Multiple Names; CSC TrustedSecure OV Wildcard, Multiple Names; and CSC TrustedSecure DV Wildcard, Multiple Names certificate products
- Renamed all certificate template product IDs to match CSC's current certificate type names (e.g. "CSC TrustedSecure Premium Certificate" is now "CSC TrustedSecure OV", "CSC TrustedSecure Domain Validated SSL" is now "CSC TrustedSecure DV"). Existing Certificate Templates in Command using the old names continue to work; new Templates should use the new names.
- Fixed the "Addtl Sans Comma Separated DCV Emails" enrollment field never actually being read during enrollment, due to a typo in the code looking up "DVC" instead of "DCV". Per-domain DCV emails for additional SANs on unrelated domains were silently ignored, falling back to the primary CN's DCV email - which does not have authority to validate a different domain.
- Fixed a case-sensitivity bug ("priorcertsn" vs "PriorCertSN") that prevented PriorCertSN from ever being read during Renew/Reissue enrollment.
- Fixed a crash when CSC Global returns a null "price.total" (e.g. reissuing a certificate that is not in an active status) - Price.Total is now nullable instead of causing a JSON deserialization exception.
- Added an xUnit test suite covering certificate type/SAN/EV routing, legacy product name backward compatibility, and the fixes above.

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
