// Copyright 2021 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System.Net.Mail;
using System.Text;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.CSCGlobal.Client.Models;
using Keyfactor.Extensions.CAPlugin.CSCGlobal.Interfaces;
using Keyfactor.Logging;
using Keyfactor.PKI.Enums.EJBCA;
using Microsoft.Extensions.Logging;

namespace Keyfactor.Extensions.CAPlugin.CSCGlobal;

public class RequestManager
{
    private readonly ILogger Logger = LogHandler.GetClassLogger<RequestManager>();

    public static Func<string, string> Pemify = ss =>
        ss.Length <= 64 ? ss : ss.Substring(0, 64) + "\n" + Pemify(ss.Substring(64));

    private static string GetOptionalParam(EnrollmentProductInfo productInfo, string key)
    {
        return productInfo.ProductParameters != null &&
               productInfo.ProductParameters.TryGetValue(key, out var value)
            ? value
            : string.Empty;
    }

    private List<CustomField> GetCustomFields(EnrollmentProductInfo productInfo, List<GetCustomField> customFields)
    {
        var customFieldList = new List<CustomField>();
        if (customFields == null)
        {
            Logger.LogTrace("No custom field definitions supplied; skipping custom field mapping");
            return customFieldList;
        }

        foreach (var field in customFields)
            if (productInfo.ProductParameters.ContainsKey(field.Label))
            {
                var newField = new CustomField
                {
                    Name = field.Label,
                    Value = productInfo.ProductParameters[field.Label]
                };
                customFieldList.Add(newField);
            }
            else if (field.Mandatory)
            {
                Logger.LogError($"Custom field {field.Label} is marked as mandatory, but was not supplied in the request.");
                throw new Exception(
                    $"Custom field {field.Label} is marked as mandatory, but was not supplied in the request.");
            }

        Logger.LogTrace($"Mapped {customFieldList.Count} custom field(s) for request");
        return customFieldList;
    }

    public EnrollmentResult GetRenewResponse(RenewalResponse renewResponse)
    {
        if (renewResponse == null)
        {
            Logger.LogError("Renewal failed: CSC Global returned no response");
            return new EnrollmentResult
            {
                Status = (int)EndEntityStatus.FAILED, //failure
                StatusMessage = "CSC Global returned no response for the renewal request"
            };
        }

        if (renewResponse.RegistrationError != null)
        {
            Logger.LogError($"Renewal failed: {renewResponse.RegistrationError.Description}");
            return new EnrollmentResult
            {
                Status = (int)EndEntityStatus.FAILED, //failure
                CARequestID = renewResponse.Result?.Status?.Uuid,
                StatusMessage = renewResponse.RegistrationError.Description
            };
        }

        if (renewResponse.Result == null)
        {
            Logger.LogError("Renewal failed: CSC Global reported success but returned no result");
            return new EnrollmentResult
            {
                Status = (int)EndEntityStatus.FAILED, //failure
                StatusMessage = "CSC Global reported success but returned no result"
            };
        }

        // CSC Global never returns an issued certificate on the renewal response itself - the
        // renewal is only submitted here and still needs domain control validation (email
        // confirmation or a CNAME record) before CSC actually issues the certificate. The real
        // certificate is picked up later via Synchronize. Reporting GENERATED here tells Command
        // a certificate is ready to be parsed off this result when there isn't one.
        Logger.LogInformation($"Renewal successfully submitted for {renewResponse.Result.CommonName}");
        return new EnrollmentResult
        {
            Status = (int)EndEntityStatus.EXTERNALVALIDATION, //success - pending DCV, not yet issued
            CARequestID = renewResponse.Result.Status?.Uuid,
            StatusMessage = $"Renewal Successfully Submitted For {renewResponse.Result.CommonName}",
            EnrollmentContext = BuildDcvEnrollmentContext(renewResponse.Result.DcvDetails)
        };
    }

    // Builds the CNAME/email DCV instructions CSC Global returns on a submitted order into the
    // key/value context Command surfaces to the requester, so they know what action is needed
    // (create a CNAME record, or check their email) before the certificate will actually issue.
    private static Dictionary<string, string> BuildDcvEnrollmentContext(List<DcvDetail> dcvDetails)
    {
        var cnames = new Dictionary<string, string>();
        if (dcvDetails == null) return null;

        foreach (var dcv in dcvDetails)
        {
            if (dcv.CName != null && !string.IsNullOrEmpty(dcv.CName.Name) && !string.IsNullOrEmpty(dcv.CName.Value))
            {
                cnames.Add(dcv.CName.Name, dcv.CName.Value);
            }

            if (!string.IsNullOrEmpty(dcv.Email) && !cnames.ContainsKey(dcv.Email))
            {
                cnames.Add(dcv.Email, dcv.Email);
            }
        }

        return cnames.Count > 0 ? cnames : null;
    }


    public EnrollmentResult
        GetEnrollmentResult(
            IRegistrationResponse registrationResponse)
    {
        if (registrationResponse == null)
        {
            Logger.LogError("Enrollment failed: CSC Global returned no response");
            return new EnrollmentResult
            {
                Status = (int)EndEntityStatus.FAILED, //failure
                StatusMessage = "CSC Global returned no response for the registration request"
            };
        }

        if (registrationResponse.RegistrationError != null)
        {
            Logger.LogError($"Enrollment failed: {registrationResponse.RegistrationError.Description}");
            return new EnrollmentResult
            {
                Status = (int)EndEntityStatus.FAILED, //failure
                StatusMessage = registrationResponse.RegistrationError.Description
            };
        }

        if (registrationResponse.Result == null)
        {
            Logger.LogError("Enrollment failed: CSC Global reported success but returned no result");
            return new EnrollmentResult
            {
                Status = (int)EndEntityStatus.FAILED, //failure
                StatusMessage = "CSC Global reported success but returned no result"
            };
        }

        Logger.LogInformation($"Order successfully created with order number {registrationResponse.Result.CommonName}");
        return new EnrollmentResult
        {
            Status = (int)EndEntityStatus.EXTERNALVALIDATION, //success
            CARequestID = registrationResponse.Result.Status?.Uuid,
            StatusMessage =
                $"Order Successfully Created With Order Number {registrationResponse.Result.CommonName}",
            EnrollmentContext = BuildDcvEnrollmentContext(registrationResponse.Result.DcvDetails)
        };
    }

    public int GetRevokeResult(IRevokeResponse revokeResponse)
    {
        if (revokeResponse == null)
        {
            Logger.LogError("Revoke failed: CSC Global returned no response");
            return (int)EndEntityStatus.FAILED;
        }

        if (revokeResponse.RegistrationError != null)
        {
            Logger.LogError($"Revoke failed: {revokeResponse.RegistrationError.Description}");
            return (int)EndEntityStatus.FAILED;
        }

        return (int)EndEntityStatus.REVOKED;
    }

    public EnrollmentResult GetReIssueResult(IReissueResponse reissueResponse)
    {
        if (reissueResponse == null)
        {
            Logger.LogError("Reissue failed: CSC Global returned no response");
            return new EnrollmentResult
            {
                Status = (int)EndEntityStatus.FAILED, //failure
                StatusMessage = "CSC Global returned no response for the reissue request"
            };
        }

        if (reissueResponse.RegistrationError != null)
        {
            Logger.LogError($"Reissue failed: {reissueResponse.RegistrationError.Description}");
            return new EnrollmentResult
            {
                Status = (int)EndEntityStatus.FAILED, //failure
                StatusMessage = reissueResponse.RegistrationError.Description
            };
        }

        if (reissueResponse.Result == null)
        {
            Logger.LogError("Reissue failed: CSC Global reported success but returned no result");
            return new EnrollmentResult
            {
                Status = (int)EndEntityStatus.FAILED, //failure
                StatusMessage = "CSC Global reported success but returned no result"
            };
        }

        // Same as renewal: CSC Global submits the reissue but still requires DCV before the
        // certificate is actually issued, so this must not claim GENERATED here.
        Logger.LogInformation($"Reissue successfully submitted for {reissueResponse.Result.CommonName}");
        return new EnrollmentResult
        {
            Status = (int)EndEntityStatus.EXTERNALVALIDATION, //success - pending DCV, not yet issued
            CARequestID = reissueResponse.Result.Status?.Uuid,
            StatusMessage = $"Reissue Successfully Submitted For {reissueResponse.Result.CommonName}",
            EnrollmentContext = BuildDcvEnrollmentContext(reissueResponse.Result.DcvDetails)
        };
    }

    public DomainControlValidation GetDomainControlValidation(string methodType, string[] emailAddress,
        string domainName)
    {
        if (string.IsNullOrWhiteSpace(domainName))
        {
            Logger.LogWarning("GetDomainControlValidation called with an empty domain name");
            return null;
        }

        foreach (var address in emailAddress ?? Array.Empty<string>())
        {
            if (string.IsNullOrWhiteSpace(address)) continue;

            MailAddress email;
            try
            {
                email = new MailAddress(address.Trim());
            }
            catch (FormatException fex)
            {
                Logger.LogWarning(fex, $"Skipping malformed DCV email address '{address}'");
                continue;
            }

            var hostLabels = email.Host.Split('.');
            if (hostLabels.Length > 0 && domainName.Contains(hostLabels[0]))
                return new DomainControlValidation
                {
                    MethodType = methodType,
                    EmailAddress = email.ToString()
                };
        }

        Logger.LogWarning($"No matching DCV email address found for domain {domainName}");
        return null;
    }

    public DomainControlValidation GetDomainControlValidation(string methodType, string emailAddress)
    {
        return new DomainControlValidation
        {
            MethodType = methodType,
            EmailAddress = emailAddress
        };
    }

    public RegistrationRequest GetRegistrationRequest(EnrollmentProductInfo productInfo, string csr,
        Dictionary<string, string[]> sans, List<GetCustomField> customFields)
    {
        Logger.LogTrace($"Building registration request for product {productInfo.ProductID}");
        //var cert = "-----BEGIN CERTIFICATE REQUEST-----\r\n";
        var cert = Pemify(csr);
        //cert = cert + "\r\n-----END CERTIFICATE REQUEST-----";


        var bytes = Encoding.UTF8.GetBytes(cert);
        var encodedString = Convert.ToBase64String(bytes);
        var commonNameValidationEmail = GetOptionalParam(productInfo, "CN DCV Email");
        var methodType = GetOptionalParam(productInfo, "Domain Control Validation Method");
        var certificateType = GetCertificateType(productInfo.ProductID);

        return new RegistrationRequest
        {
            Csr = encodedString,
            ServerSoftware = "-1", //Just default to other, user does not need to fill this in
            CertificateType = certificateType,
            Term = GetOptionalParam(productInfo, "Term"),
            ApplicantFirstName = GetOptionalParam(productInfo, "Applicant First Name"),
            ApplicantLastName = GetOptionalParam(productInfo, "Applicant Last Name"),
            ApplicantEmailAddress = GetOptionalParam(productInfo, "Applicant Email Address"),
            ApplicantPhoneNumber = GetOptionalParam(productInfo, "Applicant Phone"),
            DomainControlValidation = GetDomainControlValidation(methodType, commonNameValidationEmail),
            Notifications = GetNotifications(productInfo),
            OrganizationContact = GetOptionalParam(productInfo, "Organization Contact"),
            BusinessUnit = GetOptionalParam(productInfo, "Business Unit"),
            ShowPrice = true, //User should not have to fill this out
            CustomFields = GetCustomFields(productInfo, customFields),
            SubjectAlternativeNames = MultiNameCertificateTypes.Contains(certificateType) ? GetSubjectAlternativeNames(productInfo, sans) : null,
            EvCertificateDetails = EvCertificateTypes.Contains(certificateType) ? GetEvCertificateDetails(productInfo) : null
        };
    }

    private string GetCertificateType(string productId)
    {
        if (productId != null && ProductIDs.legacyProductIdAliases.TryGetValue(productId, out var canonicalProductId))
        {
            productId = canonicalProductId;
        }

        switch (productId)
        {
            case "CSC TrustedSecure OV":
                return "0";
            case "CSC TrustedSecure OV Wildcard":
                return "1";
            case "CSC TrustedSecure OV, Multiple Names":
                return "2";
            case "CSC TrustedSecure EV":
                return "3";
            case "CSC TrustedSecure DV":
                return "4";
            case "CSC TrustedSecure DV Wildcard":
                return "5";
            case "CSC TrustedSecure DV, Multiple Names":
                return "6";
            case "CSC TrustedSecure EV, Multiple Names":
                return "7";
            case "CSC TrustedSecure OV Wildcard, Multiple Names":
                return "8";
            case "CSC TrustedSecure DV Wildcard, Multiple Names":
                return "9";
        }

        Logger.LogWarning($"Unrecognized product ID '{productId}'; defaulting certificate type to -1");
        return "-1";
    }

    private static readonly HashSet<string> MultiNameCertificateTypes = new() { "2", "6", "7", "8", "9" };
    private static readonly HashSet<string> EvCertificateTypes = new() { "3", "7" };

    public Notifications GetNotifications(EnrollmentProductInfo productInfo)
    {
        var notificationEmails = GetOptionalParam(productInfo, "Notification Email(s) Comma Separated");
        return new Notifications
        {
            Enabled = true,
            AdditionalNotificationEmails = string.IsNullOrWhiteSpace(notificationEmails)
                ? new List<string>()
                : notificationEmails.Split(',').ToList()
        };
    }

    public RenewalRequest GetRenewalRequest(EnrollmentProductInfo productInfo, string uUId, string csr,
        Dictionary<string, string[]> sans, List<GetCustomField> customFields)
    {
        Logger.LogTrace($"Building renewal request for product {productInfo.ProductID}, UUID {uUId}");
        //var cert = "-----BEGIN CERTIFICATE REQUEST-----\r\n";
        var cert = Pemify(csr);
        //cert = cert + "\r\n-----END CERTIFICATE REQUEST-----";

        var bytes = Encoding.UTF8.GetBytes(cert);
        var encodedString = Convert.ToBase64String(bytes);
        var commonNameValidationEmail = GetOptionalParam(productInfo, "CN DCV Email");
        var methodType = GetOptionalParam(productInfo, "Domain Control Validation Method");
        var certificateType = GetCertificateType(productInfo.ProductID);

        return new RenewalRequest
        {
            Uuid = uUId,
            Csr = encodedString,
            ServerSoftware = "-1",
            CertificateType = certificateType,
            Term = GetOptionalParam(productInfo, "Term"),
            ApplicantFirstName = GetOptionalParam(productInfo, "Applicant First Name"),
            ApplicantLastName = GetOptionalParam(productInfo, "Applicant Last Name"),
            ApplicantEmailAddress = GetOptionalParam(productInfo, "Applicant Email Address"),
            ApplicantPhoneNumber = GetOptionalParam(productInfo, "Applicant Phone"),
            DomainControlValidation = GetDomainControlValidation(methodType, commonNameValidationEmail),
            Notifications = GetNotifications(productInfo),
            OrganizationContact = GetOptionalParam(productInfo, "Organization Contact"),
            BusinessUnit = GetOptionalParam(productInfo, "Business Unit"),
            ShowPrice = true,
            SubjectAlternativeNames = MultiNameCertificateTypes.Contains(certificateType) ? GetSubjectAlternativeNames(productInfo, sans) : null,
            CustomFields = GetCustomFields(productInfo, customFields),
            EvCertificateDetails = EvCertificateTypes.Contains(certificateType) ? GetEvCertificateDetails(productInfo) : null
        };
    }

    private List<SubjectAlternativeName> GetSubjectAlternativeNames(EnrollmentProductInfo productInfo,
        Dictionary<string, string[]> sans)
    {
        var subjectNameList = new List<SubjectAlternativeName>();
        var methodType = GetOptionalParam(productInfo, "Domain Control Validation Method");
        var commonNameValidationEmail = GetOptionalParam(productInfo, "CN DCV Email");

        string[] dnsNames = null;
        sans?.TryGetValue("dnsname", out dnsNames);
        foreach (var v in dnsNames ?? Array.Empty<string>())
        {
            var domainName = v;
            var san = new SubjectAlternativeName();
            san.DomainName = domainName;
            if (methodType.ToUpper() == "EMAIL")
            {
                productInfo.ProductParameters.TryGetValue(EnrollmentConfigConstants.AdditionalSansCommaSeparatedDcvEmails, out var addtlSansEmails);
                var emailAddresses = string.IsNullOrWhiteSpace(addtlSansEmails)
                    ? Array.Empty<string>()
                    : addtlSansEmails.Split(',');

                // Fall back to the primary CN's DCV email when no per-domain override matches;
                // CSC Global rejects the request if a SAN entry is missing domainControlValidation.
                san.DomainControlValidation = GetDomainControlValidation(methodType, emailAddresses, domainName)
                    ?? GetDomainControlValidation(methodType, commonNameValidationEmail);
            }
            else //it is a CNAME validation - mirror the primary CN's DCV, no email is needed
                san.DomainControlValidation = GetDomainControlValidation(methodType, commonNameValidationEmail);

            subjectNameList.Add(san);
        }

        return subjectNameList;
    }

    public ReissueRequest GetReissueRequest(EnrollmentProductInfo productInfo, string uUId, string csr,
        Dictionary<string, string[]> sans, List<GetCustomField> customFields)
    {
        Logger.LogTrace($"Building reissue request for product {productInfo.ProductID}, UUID {uUId}");
        //var cert = "-----BEGIN CERTIFICATE REQUEST-----\r\n";
        var cert = Pemify(csr);
        //cert = cert + "\r\n-----END CERTIFICATE REQUEST-----";

        var bytes = Encoding.UTF8.GetBytes(cert);
        var encodedString = Convert.ToBase64String(bytes);
        var commonNameValidationEmail = GetOptionalParam(productInfo, "CN DCV Email");
        var methodType = GetOptionalParam(productInfo, "Domain Control Validation Method");
        var certificateType = GetCertificateType(productInfo.ProductID);

        return new ReissueRequest
        {
            Uuid = uUId,
            Csr = encodedString,
            ServerSoftware = "-1",
            CertificateType = certificateType,
            Term = GetOptionalParam(productInfo, "Term"),
            ApplicantFirstName = GetOptionalParam(productInfo, "Applicant First Name"),
            ApplicantLastName = GetOptionalParam(productInfo, "Applicant Last Name"),
            ApplicantEmailAddress = GetOptionalParam(productInfo, "Applicant Email Address"),
            ApplicantPhoneNumber = GetOptionalParam(productInfo, "Applicant Phone"),
            DomainControlValidation = GetDomainControlValidation(methodType, commonNameValidationEmail),
            Notifications = GetNotifications(productInfo),
            OrganizationContact = GetOptionalParam(productInfo, "Organization Contact"),
            BusinessUnit = GetOptionalParam(productInfo, "Business Unit"),
            ShowPrice = true,
            SubjectAlternativeNames = MultiNameCertificateTypes.Contains(certificateType) ? GetSubjectAlternativeNames(productInfo, sans) : null,
            CustomFields = GetCustomFields(productInfo, customFields),
            EvCertificateDetails = EvCertificateTypes.Contains(certificateType) ? GetEvCertificateDetails(productInfo) : null
        };
    }

    private EvCertificateDetails GetEvCertificateDetails(EnrollmentProductInfo productInfo)
    {
        var evDetails = new EvCertificateDetails();
        evDetails.Country = GetOptionalParam(productInfo, "Organization Country");
        return evDetails;
    }

    public int MapReturnStatus(string cscGlobalStatus)
    {
        int returnStatus;

        switch (cscGlobalStatus)
        {
            case "ACTIVE":
                returnStatus = (int)EndEntityStatus.GENERATED;
                break;
            case "Initial":
                returnStatus = (int)EndEntityStatus.INITIALIZED;
                break;
            case "Pending":
                returnStatus = (int)EndEntityStatus.INPROCESS;
                break;
            case "REVOKED":
                returnStatus = (int)EndEntityStatus.REVOKED;
                break;
            default:
                Logger.LogWarning($"Unrecognized CSC Global status '{cscGlobalStatus}'; mapping to FAILED");
                returnStatus = (int)EndEntityStatus.FAILED;
                break;
        }

        return returnStatus;
    }
}