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

    private List<CustomField> GetCustomFields(EnrollmentProductInfo productInfo, List<GetCustomField> customFields)
    {
        Logger.LogTrace("GetCustomFields: productInfo is {Null}, customFields count={Count}",
            productInfo == null ? "NULL" : "present",
            customFields?.Count ?? 0);

        var customFieldList = new List<CustomField>();
        if (customFields == null || productInfo?.ProductParameters == null)
        {
            Logger.LogTrace("GetCustomFields: returning empty list (null customFields or ProductParameters).");
            return customFieldList;
        }

        foreach (var field in customFields)
        {
            if (field == null)
            {
                Logger.LogTrace("GetCustomFields: skipping null field entry.");
                continue;
            }

            Logger.LogTrace("GetCustomFields: checking field Label='{Label}', Mandatory={Mandatory}",
                field.Label ?? "(null)", field.Mandatory);

            if (string.IsNullOrEmpty(field.Label))
            {
                Logger.LogTrace("GetCustomFields: skipping field with null/empty label.");
                continue;
            }

            if (productInfo.ProductParameters.ContainsKey(field.Label))
            {
                var newField = new CustomField
                {
                    Name = field.Label,
                    Value = productInfo.ProductParameters[field.Label]
                };
                Logger.LogTrace("GetCustomFields: matched field '{Label}' = '{Value}'", field.Label, newField.Value ?? "(null)");
                customFieldList.Add(newField);
            }
            else if (field.Mandatory)
            {
                Logger.LogError("GetCustomFields: mandatory field '{Label}' was not supplied. Available keys: [{Keys}]",
                    field.Label, string.Join(", ", productInfo.ProductParameters.Keys));
                throw new Exception(
                    $"Custom field {field.Label} is marked as mandatory, but was not supplied in the request.");
            }
            else
            {
                Logger.LogTrace("GetCustomFields: optional field '{Label}' not found in ProductParameters, skipping.", field.Label);
            }
        }

        Logger.LogTrace("GetCustomFields: returning {Count} custom fields.", customFieldList.Count);
        return customFieldList;
    }

    public EnrollmentResult GetRenewResponse(RenewalResponse renewResponse)
    {
        Logger.LogTrace("GetRenewResponse: renewResponse is {Null}", renewResponse == null ? "NULL" : "present");

        if (renewResponse == null)
        {
            Logger.LogError("GetRenewResponse: renewResponse is null.");
            return new EnrollmentResult
            {
                Status = (int)EndEntityStatus.FAILED,
                StatusMessage = "Renewal failed: received null response from CSC."
            };
        }

        if (renewResponse.RegistrationError != null)
        {
            Logger.LogWarning("GetRenewResponse: RegistrationError present. Description='{Desc}'",
                renewResponse.RegistrationError.Description ?? "(null)");
            return new EnrollmentResult
            {
                Status = (int)EndEntityStatus.FAILED,
                CARequestID = renewResponse.Result?.Status?.Uuid,
                StatusMessage = renewResponse.RegistrationError.Description ?? "Renewal failed with unknown error."
            };
        }

        var commonName = renewResponse.Result?.CommonName ?? "(unknown)";
        Logger.LogTrace("GetRenewResponse: renewal succeeded for CommonName='{CommonName}'", commonName);
        return new EnrollmentResult
        {
            Status = (int)EndEntityStatus.GENERATED,
            StatusMessage = $"Renewal Successfully Completed For {commonName}"
        };
    }


    public EnrollmentResult
        GetEnrollmentResult(
            IRegistrationResponse registrationResponse)
    {
        Logger.LogTrace("GetEnrollmentResult: registrationResponse is {Null}", registrationResponse == null ? "NULL" : "present");

        if (registrationResponse == null)
        {
            Logger.LogError("GetEnrollmentResult: registrationResponse is null.");
            return new EnrollmentResult
            {
                Status = (int)EndEntityStatus.FAILED,
                StatusMessage = "Enrollment failed: received null response from CSC."
            };
        }

        if (registrationResponse.RegistrationError != null)
        {
            Logger.LogWarning("GetEnrollmentResult: RegistrationError present. Description='{Desc}'",
                registrationResponse.RegistrationError.Description ?? "(null)");
            return new EnrollmentResult
            {
                Status = (int)EndEntityStatus.FAILED,
                StatusMessage = registrationResponse.RegistrationError.Description ?? "Enrollment failed with unknown error."
            };
        }

        if (registrationResponse.Result == null)
        {
            Logger.LogError("GetEnrollmentResult: Result is null but no RegistrationError present.");
            return new EnrollmentResult
            {
                Status = (int)EndEntityStatus.FAILED,
                StatusMessage = "Enrollment failed: response Result is null."
            };
        }

        var cnames = new Dictionary<string, string>();
        if (registrationResponse.Result.DcvDetails != null && registrationResponse.Result.DcvDetails.Count > 0)
        {
            Logger.LogTrace("GetEnrollmentResult: processing {Count} DcvDetails.", registrationResponse.Result.DcvDetails.Count);
            foreach (var dcv in registrationResponse.Result.DcvDetails)
            {
                if (dcv == null)
                {
                    Logger.LogTrace("GetEnrollmentResult: skipping null DcvDetail.");
                    continue;
                }

                if (dcv.CName != null && !string.IsNullOrEmpty(dcv.CName.Name) && !string.IsNullOrEmpty(dcv.CName.Value))
                {
                    if (!cnames.ContainsKey(dcv.CName.Name))
                    {
                        Logger.LogTrace("GetEnrollmentResult: adding CName '{Name}'='{Value}'", dcv.CName.Name, dcv.CName.Value);
                        cnames.Add(dcv.CName.Name, dcv.CName.Value);
                    }
                    else
                    {
                        Logger.LogTrace("GetEnrollmentResult: duplicate CName key '{Name}', skipping.", dcv.CName.Name);
                    }
                }

                if (!string.IsNullOrEmpty(dcv.Email))
                {
                    if (!cnames.ContainsKey(dcv.Email))
                    {
                        Logger.LogTrace("GetEnrollmentResult: adding DCV email '{Email}'", dcv.Email);
                        cnames.Add(dcv.Email, dcv.Email);
                    }
                    else
                    {
                        Logger.LogTrace("GetEnrollmentResult: duplicate email key '{Email}', skipping.", dcv.Email);
                    }
                }
            }
        }
        else
        {
            Logger.LogTrace("GetEnrollmentResult: no DcvDetails to process.");
        }

        var uuid = registrationResponse.Result.Status?.Uuid;
        var commonName = registrationResponse.Result.CommonName ?? "(unknown)";
        Logger.LogTrace("GetEnrollmentResult: success. UUID='{Uuid}', CommonName='{CommonName}', cnames count={Count}",
            uuid ?? "(null)", commonName, cnames.Count);

        return new EnrollmentResult
        {
            Status = (int)EndEntityStatus.EXTERNALVALIDATION,
            CARequestID = uuid,
            StatusMessage =
                $"Order Successfully Created With Order Number {commonName}",
            EnrollmentContext = cnames.Count > 0 ? cnames : null
        };
    }

    public int GetRevokeResult(IRevokeResponse revokeResponse)
    {
        Logger.LogTrace("GetRevokeResult: revokeResponse is {Null}", revokeResponse == null ? "NULL" : "present");

        if (revokeResponse == null)
        {
            Logger.LogError("GetRevokeResult: revokeResponse is null, returning FAILED.");
            return (int)EndEntityStatus.FAILED;
        }

        if (revokeResponse.RegistrationError != null)
        {
            Logger.LogWarning("GetRevokeResult: RegistrationError present. Description='{Desc}'",
                revokeResponse.RegistrationError.Description ?? "(null)");
            return (int)EndEntityStatus.FAILED;
        }

        Logger.LogTrace("GetRevokeResult: returning REVOKED.");
        return (int)EndEntityStatus.REVOKED;
    }

    public EnrollmentResult GetReIssueResult(IReissueResponse reissueResponse)
    {
        Logger.LogTrace("GetReIssueResult: reissueResponse is {Null}", reissueResponse == null ? "NULL" : "present");

        if (reissueResponse == null)
        {
            Logger.LogError("GetReIssueResult: reissueResponse is null.");
            return new EnrollmentResult
            {
                Status = (int)EndEntityStatus.FAILED,
                StatusMessage = "Reissue failed: received null response from CSC."
            };
        }

        if (reissueResponse.RegistrationError != null)
        {
            Logger.LogWarning("GetReIssueResult: RegistrationError present. Description='{Desc}'",
                reissueResponse.RegistrationError.Description ?? "(null)");
            return new EnrollmentResult
            {
                Status = (int)EndEntityStatus.FAILED,
                StatusMessage = reissueResponse.RegistrationError.Description ?? "Reissue failed with unknown error."
            };
        }

        if (reissueResponse.Result == null)
        {
            Logger.LogError("GetReIssueResult: Result is null but no RegistrationError present.");
            return new EnrollmentResult
            {
                Status = (int)EndEntityStatus.FAILED,
                StatusMessage = "Reissue failed: response Result is null."
            };
        }

        var uuid = reissueResponse.Result.Status?.Uuid;
        var commonName = reissueResponse.Result.CommonName ?? "(unknown)";
        Logger.LogTrace("GetReIssueResult: success. UUID='{Uuid}', CommonName='{CommonName}'", uuid ?? "(null)", commonName);

        return new EnrollmentResult
        {
            Status = (int)EndEntityStatus.GENERATED,
            CARequestID = uuid,
            StatusMessage = $"Reissue Successfully Completed For {commonName}"
        };
    }

    public DomainControlValidation GetDomainControlValidation(string methodType, string[] emailAddress,
        string domainName)
    {
        Logger.LogTrace("GetDomainControlValidation(array): methodType='{MethodType}', domainName='{DomainName}', emailAddress count={Count}",
            methodType ?? "(null)", domainName ?? "(null)", emailAddress?.Length ?? 0);

        if (emailAddress == null || emailAddress.Length == 0)
        {
            Logger.LogTrace("GetDomainControlValidation(array): no email addresses provided, returning null.");
            return null;
        }

        foreach (var address in emailAddress)
        {
            if (string.IsNullOrEmpty(address))
            {
                Logger.LogTrace("GetDomainControlValidation(array): skipping null/empty email address.");
                continue;
            }

            try
            {
                var email = new MailAddress(address);
                var hostPart = email.Host?.Split('.')[0] ?? "";
                Logger.LogTrace("GetDomainControlValidation(array): checking email='{Email}', hostPart='{HostPart}' against domain='{Domain}'",
                    address, hostPart, domainName);

                if (!string.IsNullOrEmpty(domainName) && domainName.Contains(hostPart))
                {
                    Logger.LogTrace("GetDomainControlValidation(array): matched! Returning email='{Email}'", email.ToString());
                    return new DomainControlValidation
                    {
                        MethodType = methodType,
                        EmailAddress = email.ToString()
                    };
                }
            }
            catch (FormatException fex)
            {
                Logger.LogWarning("GetDomainControlValidation(array): invalid email address '{Address}': {Message}", address, fex.Message);
            }
        }

        Logger.LogTrace("GetDomainControlValidation(array): no matching email found, returning null.");
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
        Logger.LogTrace("GetRegistrationRequest: building registration request. ProductID='{ProductId}'", productInfo?.ProductID ?? "(null)");

        if (productInfo?.ProductParameters == null)
            throw new ArgumentNullException(nameof(productInfo), "productInfo or ProductParameters cannot be null.");
        if (string.IsNullOrEmpty(csr))
            throw new ArgumentNullException(nameof(csr), "CSR cannot be null or empty.");

        var cert = Pemify(csr);
        var bytes = Encoding.UTF8.GetBytes(cert);
        var encodedString = Convert.ToBase64String(bytes);
        Logger.LogTrace("GetRegistrationRequest: CSR encoded, length={Length}", encodedString.Length);

        var commonNameValidationEmail = productInfo.ProductParameters.ContainsKey("CN DCV Email")
            ? productInfo.ProductParameters["CN DCV Email"] : null;
        var methodType = productInfo.ProductParameters.ContainsKey("Domain Control Validation Method")
            ? productInfo.ProductParameters["Domain Control Validation Method"] : null;
        var certificateType = GetCertificateType(productInfo.ProductID);

        Logger.LogTrace("GetRegistrationRequest: cnDcvEmail='{Email}', methodType='{Method}', certType='{CertType}'",
            commonNameValidationEmail ?? "(null)", methodType ?? "(null)", certificateType);

        return new RegistrationRequest
        {
            Csr = encodedString,
            ServerSoftware = "-1",
            CertificateType = certificateType,
            Term = productInfo.ProductParameters.ContainsKey("Term") ? productInfo.ProductParameters["Term"] : null,
            ApplicantFirstName = productInfo.ProductParameters.ContainsKey("Applicant First Name") ? productInfo.ProductParameters["Applicant First Name"] : null,
            ApplicantLastName = productInfo.ProductParameters.ContainsKey("Applicant Last Name") ? productInfo.ProductParameters["Applicant Last Name"] : null,
            ApplicantEmailAddress = productInfo.ProductParameters.ContainsKey("Applicant Email Address") ? productInfo.ProductParameters["Applicant Email Address"] : null,
            ApplicantPhoneNumber = productInfo.ProductParameters.ContainsKey("Applicant Phone") ? productInfo.ProductParameters["Applicant Phone"] : null,
            DomainControlValidation = GetDomainControlValidation(methodType, commonNameValidationEmail),
            Notifications = GetNotifications(productInfo),
            OrganizationContact = productInfo.ProductParameters.ContainsKey("Organization Contact") ? productInfo.ProductParameters["Organization Contact"] : null,
            BusinessUnit = productInfo.ProductParameters.ContainsKey("Business Unit") ? productInfo.ProductParameters["Business Unit"] : null,
            ShowPrice = true,
            CustomFields = GetCustomFields(productInfo, customFields),
            SubjectAlternativeNames = certificateType == "2" ? GetSubjectAlternativeNames(productInfo, sans) : null,
            EvCertificateDetails = certificateType == "3" ? GetEvCertificateDetails(productInfo) : null
        };
    }

    // Maps Keyfactor product ID -> CSC API certificate type code (used for enrollment requests)
    private static readonly Dictionary<string, string> ProductIdToCodeMap = new(StringComparer.OrdinalIgnoreCase)
    {
        ["CSC TrustedSecure Premium Certificate"] = "0",
        ["CSC TrustedSecure Premium Wildcard Certificate"] = "1",
        ["CSC TrustedSecure UC Certificate"] = "2",
        ["CSC TrustedSecure EV Certificate"] = "3",
        ["CSC TrustedSecure Domain Validated SSL"] = "4",
        ["CSC Trusted Secure Domain Validated SSL"] = "4",
        ["CSC TrustedSecure Domain Validated Wildcard SSL"] = "5",
        ["CSC Trusted Secure Domain Validated Wildcard SSL"] = "5",
        ["CSC TrustedSecure Domain Validated UC Certificate"] = "6",
        ["CSC Trusted Secure Domain Validated UC Certificate"] = "6",
    };

    // Reverse map: CSC API certificate type string -> Keyfactor product ID (used during sync)
    // CSC may return numeric codes ("0","1") or descriptive strings ("Premium","EV","UC", etc.)
    private static readonly Dictionary<string, string> CodeToProductIdMap = new(StringComparer.OrdinalIgnoreCase)
    {
        ["0"] = "CSC TrustedSecure Premium Certificate",
        ["Premium"] = "CSC TrustedSecure Premium Certificate",
        ["CSC TrustedSecure Premium Certificate"] = "CSC TrustedSecure Premium Certificate",
        ["1"] = "CSC TrustedSecure Premium Wildcard Certificate",
        ["Wildcard"] = "CSC TrustedSecure Premium Wildcard Certificate",
        ["Premium Wildcard"] = "CSC TrustedSecure Premium Wildcard Certificate",
        ["CSC TrustedSecure Premium Wildcard Certificate"] = "CSC TrustedSecure Premium Wildcard Certificate",
        ["2"] = "CSC TrustedSecure UC Certificate",
        ["UC"] = "CSC TrustedSecure UC Certificate",
        ["CSC TrustedSecure UC Certificate"] = "CSC TrustedSecure UC Certificate",
        ["3"] = "CSC TrustedSecure EV Certificate",
        ["EV"] = "CSC TrustedSecure EV Certificate",
        ["CSC TrustedSecure EV Certificate"] = "CSC TrustedSecure EV Certificate",
        ["4"] = "CSC TrustedSecure Domain Validated SSL",
        ["DV"] = "CSC TrustedSecure Domain Validated SSL",
        ["Domain Validated SSL"] = "CSC TrustedSecure Domain Validated SSL",
        ["CSC TrustedSecure Domain Validated SSL"] = "CSC TrustedSecure Domain Validated SSL",
        ["5"] = "CSC TrustedSecure Domain Validated Wildcard SSL",
        ["DV Wildcard"] = "CSC TrustedSecure Domain Validated Wildcard SSL",
        ["Domain Validated Wildcard SSL"] = "CSC TrustedSecure Domain Validated Wildcard SSL",
        ["CSC TrustedSecure Domain Validated Wildcard SSL"] = "CSC TrustedSecure Domain Validated Wildcard SSL",
        ["6"] = "CSC TrustedSecure Domain Validated UC Certificate",
        ["DV UC"] = "CSC TrustedSecure Domain Validated UC Certificate",
        ["Domain Validated UC Certificate"] = "CSC TrustedSecure Domain Validated UC Certificate",
        ["CSC TrustedSecure Domain Validated UC Certificate"] = "CSC TrustedSecure Domain Validated UC Certificate",
    };

    private string GetCertificateType(string productId)
    {
        Logger.LogTrace("GetCertificateType: productId='{ProductId}'", productId ?? "(null)");
        if (!string.IsNullOrEmpty(productId) && ProductIdToCodeMap.TryGetValue(productId, out var code))
        {
            Logger.LogTrace("GetCertificateType: mapped '{ProductId}' -> '{Code}'", productId, code);
            return code;
        }
        Logger.LogWarning("GetCertificateType: no mapping found for '{ProductId}', returning -1.", productId);
        return "-1";
    }

    /// <summary>
    ///     Maps a CSC API certificateType value back to a Keyfactor product ID.
    ///     Handles numeric codes, descriptive strings, and passthrough of already-correct values.
    /// </summary>
    public string MapCertificateTypeToProductId(string cscCertificateType)
    {
        Logger.LogTrace("MapCertificateTypeToProductId: input='{CscCertType}'", cscCertificateType ?? "(null)");
        if (!string.IsNullOrEmpty(cscCertificateType) && CodeToProductIdMap.TryGetValue(cscCertificateType, out var productId))
        {
            Logger.LogTrace("MapCertificateTypeToProductId: mapped '{CscCertType}' -> '{ProductId}'", cscCertificateType, productId);
            return productId;
        }
        Logger.LogWarning("MapCertificateTypeToProductId: no mapping for '{CscCertType}', passing through as-is.", cscCertificateType);
        return cscCertificateType ?? "CscGlobal";
    }

    public Notifications GetNotifications(EnrollmentProductInfo productInfo)
    {
        Logger.LogTrace("GetNotifications: building notifications.");
        var emailsRaw = productInfo?.ProductParameters != null
            && productInfo.ProductParameters.ContainsKey("Notification Email(s) Comma Separated")
            ? productInfo.ProductParameters["Notification Email(s) Comma Separated"]
            : null;

        Logger.LogTrace("GetNotifications: raw notification emails='{Emails}'", emailsRaw ?? "(null)");

        var emailList = !string.IsNullOrEmpty(emailsRaw)
            ? emailsRaw.Split(',').Where(e => !string.IsNullOrWhiteSpace(e)).ToList()
            : new List<string>();

        Logger.LogTrace("GetNotifications: parsed {Count} notification emails.", emailList.Count);

        return new Notifications
        {
            Enabled = true,
            AdditionalNotificationEmails = emailList
        };
    }

    public RenewalRequest GetRenewalRequest(EnrollmentProductInfo productInfo, string uUId, string csr,
        Dictionary<string, string[]> sans, List<GetCustomField> customFields)
    {
        Logger.LogTrace("GetRenewalRequest: building renewal request. UUID='{Uuid}', ProductID='{ProductId}'",
            uUId ?? "(null)", productInfo?.ProductID ?? "(null)");

        if (productInfo?.ProductParameters == null)
            throw new ArgumentNullException(nameof(productInfo), "productInfo or ProductParameters cannot be null.");
        if (string.IsNullOrEmpty(csr))
            throw new ArgumentNullException(nameof(csr), "CSR cannot be null or empty.");
        if (string.IsNullOrEmpty(uUId))
            throw new ArgumentNullException(nameof(uUId), "uUId cannot be null or empty.");

        var cert = Pemify(csr);
        var bytes = Encoding.UTF8.GetBytes(cert);
        var encodedString = Convert.ToBase64String(bytes);

        var commonNameValidationEmail = productInfo.ProductParameters.ContainsKey("CN DCV Email")
            ? productInfo.ProductParameters["CN DCV Email"] : null;
        var methodType = productInfo.ProductParameters.ContainsKey("Domain Control Validation Method")
            ? productInfo.ProductParameters["Domain Control Validation Method"] : null;
        var certificateType = GetCertificateType(productInfo.ProductID);

        Logger.LogTrace("GetRenewalRequest: cnDcvEmail='{Email}', methodType='{Method}', certType='{CertType}'",
            commonNameValidationEmail ?? "(null)", methodType ?? "(null)", certificateType);

        return new RenewalRequest
        {
            Uuid = uUId,
            Csr = encodedString,
            ServerSoftware = "-1",
            CertificateType = certificateType,
            Term = productInfo.ProductParameters.ContainsKey("Term") ? productInfo.ProductParameters["Term"] : null,
            ApplicantFirstName = productInfo.ProductParameters.ContainsKey("Applicant First Name") ? productInfo.ProductParameters["Applicant First Name"] : null,
            ApplicantLastName = productInfo.ProductParameters.ContainsKey("Applicant Last Name") ? productInfo.ProductParameters["Applicant Last Name"] : null,
            ApplicantEmailAddress = productInfo.ProductParameters.ContainsKey("Applicant Email Address") ? productInfo.ProductParameters["Applicant Email Address"] : null,
            ApplicantPhoneNumber = productInfo.ProductParameters.ContainsKey("Applicant Phone") ? productInfo.ProductParameters["Applicant Phone"] : null,
            DomainControlValidation = GetDomainControlValidation(methodType, commonNameValidationEmail),
            Notifications = GetNotifications(productInfo),
            OrganizationContact = productInfo.ProductParameters.ContainsKey("Organization Contact") ? productInfo.ProductParameters["Organization Contact"] : null,
            BusinessUnit = productInfo.ProductParameters.ContainsKey("Business Unit") ? productInfo.ProductParameters["Business Unit"] : null,
            ShowPrice = true,
            SubjectAlternativeNames = certificateType == "2" ? GetSubjectAlternativeNames(productInfo, sans) : null,
            CustomFields = GetCustomFields(productInfo, customFields),
            EvCertificateDetails = certificateType == "3" ? GetEvCertificateDetails(productInfo) : null
        };
    }

    private List<SubjectAlternativeName> GetSubjectAlternativeNames(EnrollmentProductInfo productInfo,
        Dictionary<string, string[]> sans)
    {
        Logger.LogTrace("GetSubjectAlternativeNames: building SANs.");
        var subjectNameList = new List<SubjectAlternativeName>();

        if (sans == null || !sans.ContainsKey("dnsname"))
        {
            Logger.LogTrace("GetSubjectAlternativeNames: no 'dnsname' key in SANs dictionary, returning empty list.");
            return subjectNameList;
        }

        var dnsNames = sans["dnsname"];
        if (dnsNames == null || dnsNames.Length == 0)
        {
            Logger.LogTrace("GetSubjectAlternativeNames: 'dnsname' array is null or empty, returning empty list.");
            return subjectNameList;
        }

        var methodType = productInfo?.ProductParameters != null
            && productInfo.ProductParameters.ContainsKey("Domain Control Validation Method")
            ? productInfo.ProductParameters["Domain Control Validation Method"]
            : null;

        Logger.LogTrace("GetSubjectAlternativeNames: processing {Count} DNS names, methodType='{MethodType}'",
            dnsNames.Length, methodType ?? "(null)");

        foreach (var v in dnsNames)
        {
            if (string.IsNullOrEmpty(v))
            {
                Logger.LogTrace("GetSubjectAlternativeNames: skipping null/empty DNS name.");
                continue;
            }

            var domainName = v;
            var san = new SubjectAlternativeName();
            san.DomainName = domainName;
            Logger.LogTrace("GetSubjectAlternativeNames: processing domain='{Domain}'", domainName);

            if (!string.IsNullOrEmpty(methodType) && methodType.ToUpper() == "EMAIL")
            {
                var emailsRaw = productInfo.ProductParameters.ContainsKey("Addtl Sans Comma Separated DVC Emails")
                    ? productInfo.ProductParameters["Addtl Sans Comma Separated DVC Emails"]
                    : null;
                var emailAddresses = !string.IsNullOrEmpty(emailsRaw) ? emailsRaw.Split(',') : Array.Empty<string>();
                Logger.LogTrace("GetSubjectAlternativeNames: EMAIL validation, {Count} email addresses for domain='{Domain}'",
                    emailAddresses.Length, domainName);
                san.DomainControlValidation = GetDomainControlValidation(methodType, emailAddresses, domainName);
            }
            else
            {
                Logger.LogTrace("GetSubjectAlternativeNames: CNAME/other validation for domain='{Domain}'", domainName);
                san.DomainControlValidation = GetDomainControlValidation(methodType, "");
            }

            subjectNameList.Add(san);
        }

        Logger.LogTrace("GetSubjectAlternativeNames: returning {Count} SANs.", subjectNameList.Count);
        return subjectNameList;
    }

    public ReissueRequest GetReissueRequest(EnrollmentProductInfo productInfo, string uUId, string csr,
        Dictionary<string, string[]> sans, List<GetCustomField> customFields)
    {
        Logger.LogTrace("GetReissueRequest: building reissue request. UUID='{Uuid}', ProductID='{ProductId}'",
            uUId ?? "(null)", productInfo?.ProductID ?? "(null)");

        if (productInfo?.ProductParameters == null)
            throw new ArgumentNullException(nameof(productInfo), "productInfo or ProductParameters cannot be null.");
        if (string.IsNullOrEmpty(csr))
            throw new ArgumentNullException(nameof(csr), "CSR cannot be null or empty.");
        if (string.IsNullOrEmpty(uUId))
            throw new ArgumentNullException(nameof(uUId), "uUId cannot be null or empty.");

        var cert = Pemify(csr);
        var bytes = Encoding.UTF8.GetBytes(cert);
        var encodedString = Convert.ToBase64String(bytes);

        var commonNameValidationEmail = productInfo.ProductParameters.ContainsKey("CN DCV Email")
            ? productInfo.ProductParameters["CN DCV Email"] : null;
        var methodType = productInfo.ProductParameters.ContainsKey("Domain Control Validation Method")
            ? productInfo.ProductParameters["Domain Control Validation Method"] : null;
        var certificateType = GetCertificateType(productInfo.ProductID);

        Logger.LogTrace("GetReissueRequest: cnDcvEmail='{Email}', methodType='{Method}', certType='{CertType}'",
            commonNameValidationEmail ?? "(null)", methodType ?? "(null)", certificateType);

        return new ReissueRequest
        {
            Uuid = uUId,
            Csr = encodedString,
            ServerSoftware = "-1",
            CertificateType = certificateType,
            Term = productInfo.ProductParameters.ContainsKey("Term") ? productInfo.ProductParameters["Term"] : null,
            ApplicantFirstName = productInfo.ProductParameters.ContainsKey("Applicant First Name") ? productInfo.ProductParameters["Applicant First Name"] : null,
            ApplicantLastName = productInfo.ProductParameters.ContainsKey("Applicant Last Name") ? productInfo.ProductParameters["Applicant Last Name"] : null,
            ApplicantEmailAddress = productInfo.ProductParameters.ContainsKey("Applicant Email Address") ? productInfo.ProductParameters["Applicant Email Address"] : null,
            ApplicantPhoneNumber = productInfo.ProductParameters.ContainsKey("Applicant Phone") ? productInfo.ProductParameters["Applicant Phone"] : null,
            DomainControlValidation = GetDomainControlValidation(methodType, commonNameValidationEmail),
            Notifications = GetNotifications(productInfo),
            OrganizationContact = productInfo.ProductParameters.ContainsKey("Organization Contact") ? productInfo.ProductParameters["Organization Contact"] : null,
            BusinessUnit = productInfo.ProductParameters.ContainsKey("Business Unit") ? productInfo.ProductParameters["Business Unit"] : null,
            ShowPrice = true,
            SubjectAlternativeNames = certificateType == "2" ? GetSubjectAlternativeNames(productInfo, sans) : null,
            CustomFields = GetCustomFields(productInfo, customFields),
            EvCertificateDetails = certificateType == "3" ? GetEvCertificateDetails(productInfo) : null
        };
    }

    private EvCertificateDetails GetEvCertificateDetails(EnrollmentProductInfo productInfo)
    {
        Logger.LogTrace("GetEvCertificateDetails: building EV details.");
        var country = productInfo?.ProductParameters != null
            && productInfo.ProductParameters.ContainsKey("Organization Country")
            ? productInfo.ProductParameters["Organization Country"]
            : null;
        Logger.LogTrace("GetEvCertificateDetails: country='{Country}'", country ?? "(null)");
        var evDetails = new EvCertificateDetails();
        evDetails.Country = country;
        return evDetails;
    }

    public int MapReturnStatus(string cscGlobalStatus)
    {
        Logger.LogTrace("MapReturnStatus: input status='{Status}'", cscGlobalStatus ?? "(null)");

        if (string.IsNullOrEmpty(cscGlobalStatus))
        {
            Logger.LogWarning("MapReturnStatus: status is null or empty, returning FAILED.");
            return (int)EndEntityStatus.FAILED;
        }

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
                Logger.LogWarning("MapReturnStatus: unrecognized status '{Status}', returning FAILED.", cscGlobalStatus);
                returnStatus = (int)EndEntityStatus.FAILED;
                break;
        }

        Logger.LogTrace("MapReturnStatus: mapped '{Status}' to {Result}", cscGlobalStatus, returnStatus);
        return returnStatus;
    }
}