// Copyright 2021 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.

using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.CSCGlobal;
using Keyfactor.Extensions.CAPlugin.CSCGlobal.Client.Models;
using Newtonsoft.Json;
using Xunit;

namespace CscGlobalCAPluginTests;

public class RequestManagerTests
{
    private const string SampleCsr = "sample-csr-body";

    private static EnrollmentProductInfo ProductInfo(string productId, Dictionary<string, string>? parameters = null) =>
        new EnrollmentProductInfo
        {
            ProductID = productId,
            ProductParameters = parameters ?? new Dictionary<string, string>()
        };

    private static RequestManager Manager => new RequestManager();

    // ---------------------------------------------------------------------
    // Certificate type routing - canonical (1.2.0+) names, all 10 products.
    // ---------------------------------------------------------------------

    [Theory]
    [InlineData("CSC TrustedSecure OV", "0", false, false)]
    [InlineData("CSC TrustedSecure OV Wildcard", "1", false, false)]
    [InlineData("CSC TrustedSecure OV, Multiple Names", "2", true, false)]
    [InlineData("CSC TrustedSecure EV", "3", false, true)]
    [InlineData("CSC TrustedSecure DV", "4", false, false)]
    [InlineData("CSC TrustedSecure DV Wildcard", "5", false, false)]
    [InlineData("CSC TrustedSecure DV, Multiple Names", "6", true, false)]
    [InlineData("CSC TrustedSecure EV, Multiple Names", "7", true, true)]
    [InlineData("CSC TrustedSecure OV Wildcard, Multiple Names", "8", true, false)]
    [InlineData("CSC TrustedSecure DV Wildcard, Multiple Names", "9", true, false)]
    [InlineData("Some Unrecognized Product", "-1", false, false)]
    public void GetRegistrationRequest_CanonicalProductNames_RoutesCertificateTypeAndOptionalSections(
        string productId, string expectedType, bool expectSans, bool expectEv)
    {
        var sans = new Dictionary<string, string[]> { ["dnsname"] = new[] { "www.example.com" } };
        var productInfo = ProductInfo(productId, new Dictionary<string, string>
        {
            ["Domain Control Validation Method"] = "CNAME",
            ["Organization Country"] = "US"
        });

        var request = Manager.GetRegistrationRequest(productInfo, SampleCsr, sans, new List<GetCustomField>());

        Assert.Equal(expectedType, request.CertificateType);
        Assert.Equal(expectSans, request.SubjectAlternativeNames != null);
        Assert.Equal(expectEv, request.EvCertificateDetails != null);
    }

    // ---------------------------------------------------------------------
    // Certificate type routing - pre-1.2.0 legacy names must resolve identically to their
    // canonical replacement, so existing Certificate Templates in Command keep working.
    // ---------------------------------------------------------------------

    [Theory]
    [InlineData("CSC TrustedSecure Premium Certificate", "0", false, false)]
    [InlineData("CSC TrustedSecure Premium Wildcard Certificate", "1", false, false)]
    [InlineData("CSC TrustedSecure UC Certificate", "2", true, false)]
    [InlineData("CSC TrustedSecure EV Certificate", "3", false, true)]
    [InlineData("CSC TrustedSecure Domain Validated SSL", "4", false, false)]
    [InlineData("CSC Trusted Secure Domain Validated Wildcard SSL", "5", false, false)]
    [InlineData("CSC Trusted Secure Domain Validated UC Certificate", "6", true, false)]
    public void GetRegistrationRequest_LegacyProductNames_ResolveToSameCertificateType(
        string legacyProductId, string expectedType, bool expectSans, bool expectEv)
    {
        var sans = new Dictionary<string, string[]> { ["dnsname"] = new[] { "www.example.com" } };
        var productInfo = ProductInfo(legacyProductId, new Dictionary<string, string>
        {
            ["Domain Control Validation Method"] = "CNAME",
            ["Organization Country"] = "US"
        });

        var request = Manager.GetRegistrationRequest(productInfo, SampleCsr, sans, new List<GetCustomField>());

        Assert.Equal(expectedType, request.CertificateType);
        Assert.Equal(expectSans, request.SubjectAlternativeNames != null);
        Assert.Equal(expectEv, request.EvCertificateDetails != null);
    }

    [Fact]
    public void GetRegistrationRequest_LegacyAndCanonicalName_ProduceIdenticalCertificateType()
    {
        var legacy = ProductInfo("CSC TrustedSecure UC Certificate");
        var canonical = ProductInfo("CSC TrustedSecure OV, Multiple Names");

        var legacyRequest = Manager.GetRegistrationRequest(legacy, SampleCsr, new Dictionary<string, string[]>(), new List<GetCustomField>());
        var canonicalRequest = Manager.GetRegistrationRequest(canonical, SampleCsr, new Dictionary<string, string[]>(), new List<GetCustomField>());

        Assert.Equal(canonicalRequest.CertificateType, legacyRequest.CertificateType);
    }

    // ---------------------------------------------------------------------
    // IsKnownProductId - backs ValidateProductInfo. Must recognize both canonical and legacy
    // names from the same source of truth GetCertificateType uses, so the two can't drift.
    // ---------------------------------------------------------------------

    [Theory]
    [InlineData("CSC TrustedSecure DV")]
    [InlineData("CSC TrustedSecure DV Wildcard, Multiple Names")]
    [InlineData("CSC TrustedSecure Domain Validated SSL")]
    [InlineData("csc trustedsecure dv")]
    public void IsKnownProductId_RecognizedName_ReturnsTrue(string productId)
    {
        Assert.True(Manager.IsKnownProductId(productId));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("Not A Real Product")]
    public void IsKnownProductId_UnrecognizedOrEmpty_ReturnsFalse(string? productId)
    {
        Assert.False(Manager.IsKnownProductId(productId!));
    }

    // ---------------------------------------------------------------------
    // GetSubjectAlternativeNames (exercised via GetRegistrationRequest) - DCV email resolution.
    // ---------------------------------------------------------------------

    [Fact]
    public void GetRegistrationRequest_MultiNameEmailMethod_MatchesAdditionalSanEmail()
    {
        var sans = new Dictionary<string, string[]> { ["dnsname"] = new[] { "www.example.com" } };
        var productInfo = ProductInfo("CSC TrustedSecure OV, Multiple Names", new Dictionary<string, string>
        {
            ["Domain Control Validation Method"] = "EMAIL",
            [EnrollmentConfigConstants.AdditionalSansCommaSeparatedDcvEmails] = "admin@example.com,admin@other.com"
        });

        var request = Manager.GetRegistrationRequest(productInfo, SampleCsr, sans, new List<GetCustomField>());

        Assert.Single(request.SubjectAlternativeNames);
        var san = request.SubjectAlternativeNames[0];
        Assert.Equal("www.example.com", san.DomainName);
        Assert.NotNull(san.DomainControlValidation);
        Assert.Equal("admin@example.com", san.DomainControlValidation.EmailAddress);
    }

    [Fact]
    public void GetRegistrationRequest_MultiNameEmailMethodNoAddtlSanMatch_FallsBackToCommonNameDcvEmail()
    {
        // CSC Global rejects the request if a SAN entry has no domainControlValidation, so a SAN
        // domain unrelated to any configured "Addtl Sans" email must fall back to the primary
        // CN's DCV email rather than being left null.
        var sans = new Dictionary<string, string[]> { ["dnsname"] = new[] { "www.unrelated-domain.io" } };
        var productInfo = ProductInfo("CSC TrustedSecure OV, Multiple Names", new Dictionary<string, string>
        {
            ["Domain Control Validation Method"] = "EMAIL",
            [EnrollmentConfigConstants.CnDcvEmail] = "cn@example.com"
        });

        var request = Manager.GetRegistrationRequest(productInfo, SampleCsr, sans, new List<GetCustomField>());

        Assert.Single(request.SubjectAlternativeNames);
        var san = request.SubjectAlternativeNames[0];
        Assert.NotNull(san.DomainControlValidation);
        Assert.Equal("cn@example.com", san.DomainControlValidation.EmailAddress);
    }

    [Fact]
    public void GetRegistrationRequest_MultiNameCnameMethod_MirrorsCommonNameDcv()
    {
        var sans = new Dictionary<string, string[]> { ["dnsname"] = new[] { "www.example.com" } };
        var productInfo = ProductInfo("CSC TrustedSecure OV, Multiple Names", new Dictionary<string, string>
        {
            ["Domain Control Validation Method"] = "CNAME"
        });

        var request = Manager.GetRegistrationRequest(productInfo, SampleCsr, sans, new List<GetCustomField>());

        Assert.Single(request.SubjectAlternativeNames);
        Assert.NotNull(request.SubjectAlternativeNames[0].DomainControlValidation);
        Assert.Equal("CNAME", request.SubjectAlternativeNames[0].DomainControlValidation.MethodType);
    }

    [Fact]
    public void GetRegistrationRequest_WildcardMultiNameProduct_AcceptsUnrelatedDomainSans()
    {
        // Types 8/9 are wildcard + multi-name (the underlying Sectigo Multi-Domain Wildcard
        // product) - additional SANs are not restricted to the CN's own base domain.
        var sans = new Dictionary<string, string[]>
        {
            ["dnsname"] = new[] { "*.example2.com", "*.example3.com" }
        };
        var productInfo = ProductInfo("CSC TrustedSecure DV Wildcard, Multiple Names", new Dictionary<string, string>
        {
            ["Domain Control Validation Method"] = "CNAME"
        });

        var request = Manager.GetRegistrationRequest(productInfo, SampleCsr, sans, new List<GetCustomField>());

        Assert.Equal(2, request.SubjectAlternativeNames.Count);
        Assert.Equal("*.example2.com", request.SubjectAlternativeNames[0].DomainName);
        Assert.Equal("*.example3.com", request.SubjectAlternativeNames[1].DomainName);
    }

    // ---------------------------------------------------------------------
    // Price.Total nullability - CSC Global returns "price.total": null for orders that cannot
    // be processed. Total must be nullable or Newtonsoft throws mid-deserialization, before the
    // caller ever sees the RegistrationError/order status CSC was actually trying to report.
    // ---------------------------------------------------------------------

    [Fact]
    public void RegistrationResponse_NullPriceTotal_DeserializesWithoutThrowing()
    {
        const string json = "{\"result\":{\"commonName\":\"order-1\",\"price\":{\"currency\":\"\",\"total\":null}}}";

        var response = JsonConvert.DeserializeObject<RegistrationResponse>(json);

        Assert.NotNull(response?.Result?.Price);
        Assert.Null(response!.Result!.Price!.Total);
    }

    // ---------------------------------------------------------------------
    // GetRenewResponse / GetReIssueResult - CSC never returns an issued certificate on these
    // responses (only order/DCV status), so success must report EXTERNALVALIDATION, not
    // GENERATED, or the gateway host will try to parse a certificate that doesn't exist.
    // ---------------------------------------------------------------------

    [Fact]
    public void GetRenewResponse_Success_ReturnsExternalValidation()
    {
        var response = new RenewalResponse
        {
            Result = new Result { CommonName = "renewed.example.com", Status = new Status { Uuid = "uuid-1" } }
        };

        var result = Manager.GetRenewResponse(response);

        Assert.Equal((int)Keyfactor.PKI.Enums.EJBCA.EndEntityStatus.EXTERNALVALIDATION, result.Status);
        Assert.Equal("uuid-1", result.CARequestID);
    }

    [Fact]
    public void GetReIssueResult_Success_ReturnsExternalValidation()
    {
        var response = new ReissueResponse
        {
            Result = new Result { CommonName = "reissued.example.com", Status = new Status { Uuid = "uuid-2" } }
        };

        var result = Manager.GetReIssueResult(response);

        Assert.Equal((int)Keyfactor.PKI.Enums.EJBCA.EndEntityStatus.EXTERNALVALIDATION, result.Status);
        Assert.Equal("uuid-2", result.CARequestID);
    }

    [Fact]
    public void GetReIssueResult_NullResponse_ReturnsFailed()
    {
        var result = Manager.GetReIssueResult(null);
        Assert.Equal((int)Keyfactor.PKI.Enums.EJBCA.EndEntityStatus.FAILED, result.Status);
    }

    [Fact]
    public void GetReIssueResult_RegistrationError_ReturnsFailedWithDescription()
    {
        var response = new ReissueResponse { RegistrationError = new RegistrationError { Description = "rejected" } };
        var result = Manager.GetReIssueResult(response);
        Assert.Equal((int)Keyfactor.PKI.Enums.EJBCA.EndEntityStatus.FAILED, result.Status);
        Assert.Equal("rejected", result.StatusMessage);
    }

    [Fact]
    public void GetReIssueResult_NullResult_ReturnsFailed()
    {
        var response = new ReissueResponse { Result = null };
        var result = Manager.GetReIssueResult(response);
        Assert.Equal((int)Keyfactor.PKI.Enums.EJBCA.EndEntityStatus.FAILED, result.Status);
    }

    [Fact]
    public void GetRenewResponse_NullResponse_ReturnsFailed()
    {
        var result = Manager.GetRenewResponse(null);
        Assert.Equal((int)Keyfactor.PKI.Enums.EJBCA.EndEntityStatus.FAILED, result.Status);
    }

    [Fact]
    public void GetRenewResponse_RegistrationError_ReturnsFailedWithDescription()
    {
        var response = new RenewalResponse
        {
            RegistrationError = new RegistrationError { Description = "boom" },
            Result = new Result { Status = new Status { Uuid = "abc-123" } }
        };
        var result = Manager.GetRenewResponse(response);
        Assert.Equal((int)Keyfactor.PKI.Enums.EJBCA.EndEntityStatus.FAILED, result.Status);
        Assert.Equal("abc-123", result.CARequestID);
        Assert.Equal("boom", result.StatusMessage);
    }

    [Fact]
    public void GetRenewResponse_NullResult_StillReturnsExternalValidation()
    {
        // Unlike GetEnrollmentResult/GetReIssueResult, GetRenewResponse has no explicit
        // Result==null guard - it just null-conditionals through to "(unknown)"/null.
        var response = new RenewalResponse { Result = null };
        var result = Manager.GetRenewResponse(response);
        Assert.Equal((int)Keyfactor.PKI.Enums.EJBCA.EndEntityStatus.EXTERNALVALIDATION, result.Status);
        Assert.Contains("(unknown)", result.StatusMessage);
    }

    [Fact]
    public void GetEnrollmentResult_NullResponse_ReturnsFailed()
    {
        var result = Manager.GetEnrollmentResult(null);
        Assert.Equal((int)Keyfactor.PKI.Enums.EJBCA.EndEntityStatus.FAILED, result.Status);
    }

    [Fact]
    public void GetEnrollmentResult_RegistrationError_ReturnsFailed()
    {
        var response = new RegistrationResponse { RegistrationError = new RegistrationError { Description = "denied" } };
        var result = Manager.GetEnrollmentResult(response);
        Assert.Equal((int)Keyfactor.PKI.Enums.EJBCA.EndEntityStatus.FAILED, result.Status);
        Assert.Equal("denied", result.StatusMessage);
    }

    [Fact]
    public void GetEnrollmentResult_NullResult_ReturnsFailed()
    {
        var response = new RegistrationResponse { Result = null };
        var result = Manager.GetEnrollmentResult(response);
        Assert.Equal((int)Keyfactor.PKI.Enums.EJBCA.EndEntityStatus.FAILED, result.Status);
    }

    [Fact]
    public void GetEnrollmentResult_SuccessNoDcvDetails_ReturnsExternalValidationWithNullContext()
    {
        var response = new RegistrationResponse
        {
            Result = new Result { CommonName = "order-1", Status = new Status { Uuid = "uuid-1" } }
        };
        var result = Manager.GetEnrollmentResult(response);
        Assert.Equal((int)Keyfactor.PKI.Enums.EJBCA.EndEntityStatus.EXTERNALVALIDATION, result.Status);
        Assert.Equal("uuid-1", result.CARequestID);
        Assert.Null(result.EnrollmentContext);
    }

    [Fact]
    public void GetEnrollmentResult_WithCNameAndEmailDcvDetails_PopulatesEnrollmentContext()
    {
        var response = new RegistrationResponse
        {
            Result = new Result
            {
                CommonName = "order-2",
                Status = new Status { Uuid = "uuid-2" },
                DcvDetails = new List<DcvDetail>
                {
                    new DcvDetail { CName = new CName { Name = "_dnsauth.example.com", Value = "token" } },
                    new DcvDetail { Email = "admin@example.com" },
                    // Duplicate keys should not throw and should not be added twice.
                    new DcvDetail { CName = new CName { Name = "_dnsauth.example.com", Value = "token" } },
                    new DcvDetail { Email = "admin@example.com" },
                    // Entry with neither CName nor Email contributes nothing. Null entries are skipped.
                    new DcvDetail(),
                    null!
                }
            }
        };

        var result = Manager.GetEnrollmentResult(response);

        Assert.NotNull(result.EnrollmentContext);
        Assert.Equal(2, result.EnrollmentContext.Count);
        Assert.Equal("token", result.EnrollmentContext["_dnsauth.example.com"]);
        Assert.Equal("admin@example.com", result.EnrollmentContext["admin@example.com"]);
    }

    // ---------------------------------------------------------------------
    // GetRevokeResult
    // ---------------------------------------------------------------------

    [Fact]
    public void GetRevokeResult_NullResponse_ReturnsFailed()
    {
        Assert.Equal((int)Keyfactor.PKI.Enums.EJBCA.EndEntityStatus.FAILED, Manager.GetRevokeResult(null));
    }

    [Fact]
    public void GetRevokeResult_RegistrationError_ReturnsFailed()
    {
        var response = new RevokeResponse { RegistrationError = new RegistrationError { Description = "denied" } };
        Assert.Equal((int)Keyfactor.PKI.Enums.EJBCA.EndEntityStatus.FAILED, Manager.GetRevokeResult(response));
    }

    [Fact]
    public void GetRevokeResult_Success_ReturnsRevoked()
    {
        var response = new RevokeResponse { RevokeSuccess = new RevokeSuccessResponse { Status = "REVOKED" } };
        Assert.Equal((int)Keyfactor.PKI.Enums.EJBCA.EndEntityStatus.REVOKED, Manager.GetRevokeResult(response));
    }

    // ---------------------------------------------------------------------
    // MapReturnStatus / MapCertificateTypeToProductId
    // ---------------------------------------------------------------------

    [Theory]
    [InlineData("ACTIVE", Keyfactor.PKI.Enums.EJBCA.EndEntityStatus.GENERATED)]
    [InlineData("Initial", Keyfactor.PKI.Enums.EJBCA.EndEntityStatus.INITIALIZED)]
    [InlineData("Pending", Keyfactor.PKI.Enums.EJBCA.EndEntityStatus.INPROCESS)]
    [InlineData("REVOKED", Keyfactor.PKI.Enums.EJBCA.EndEntityStatus.REVOKED)]
    [InlineData("SomethingUnexpected", Keyfactor.PKI.Enums.EJBCA.EndEntityStatus.FAILED)]
    [InlineData(null, Keyfactor.PKI.Enums.EJBCA.EndEntityStatus.FAILED)]
    public void MapReturnStatus_MapsExpectedStatus(string? cscStatus, Keyfactor.PKI.Enums.EJBCA.EndEntityStatus expected)
    {
        Assert.Equal((int)expected, Manager.MapReturnStatus(cscStatus!));
    }

    [Theory]
    [InlineData("4", "CSC TrustedSecure Domain Validated SSL")]
    [InlineData("CSC TrustedSecure Domain Validated SSL", "CSC TrustedSecure Domain Validated SSL")]
    [InlineData("CSC Trusted Secure Domain Validated SSL", "CSC TrustedSecure Domain Validated SSL")]
    [InlineData("9", "CSC TrustedSecure DV Wildcard, Multiple Names")]
    public void MapCertificateTypeToProductId_KnownValue_MapsToProductId(string cscType, string expectedProductId)
    {
        Assert.Equal(expectedProductId, Manager.MapCertificateTypeToProductId(cscType));
    }

    [Fact]
    public void MapCertificateTypeToProductId_UnknownValue_PassesThrough()
    {
        Assert.Equal("SomeUnknownType", Manager.MapCertificateTypeToProductId("SomeUnknownType"));
    }

    [Fact]
    public void MapCertificateTypeToProductId_Null_ReturnsFallback()
    {
        Assert.Equal("CscGlobal", Manager.MapCertificateTypeToProductId(null!));
    }

    // ---------------------------------------------------------------------
    // GetNotifications
    // ---------------------------------------------------------------------

    [Fact]
    public void GetNotifications_NoEmailsConfigured_ReturnsEmptyList()
    {
        var notifications = Manager.GetNotifications(ProductInfo("CSC TrustedSecure DV"));
        Assert.True(notifications.Enabled);
        Assert.Empty(notifications.AdditionalNotificationEmails);
    }

    [Fact]
    public void GetNotifications_EmailsConfigured_SplitsOnComma()
    {
        var productInfo = ProductInfo("CSC TrustedSecure DV",
            new Dictionary<string, string> { ["Notification Email(s) Comma Separated"] = "a@example.com,b@example.com" });

        var notifications = Manager.GetNotifications(productInfo);

        Assert.Equal(2, notifications.AdditionalNotificationEmails.Count);
        Assert.Contains("a@example.com", notifications.AdditionalNotificationEmails);
    }

    // ---------------------------------------------------------------------
    // GetDomainControlValidation
    // ---------------------------------------------------------------------

    [Fact]
    public void GetDomainControlValidation_EmptyEmailArray_ReturnsNull()
    {
        Assert.Null(Manager.GetDomainControlValidation("EMAIL", Array.Empty<string>(), "example.com"));
    }

    [Fact]
    public void GetDomainControlValidation_NullEmailArray_ReturnsNull()
    {
        Assert.Null(Manager.GetDomainControlValidation("EMAIL", null!, "example.com"));
    }

    [Fact]
    public void GetDomainControlValidation_MatchingHostFound_ReturnsValidation()
    {
        var result = Manager.GetDomainControlValidation("EMAIL", new[] { "not-an-email", "admin@example.com" }, "www.example.com");
        Assert.NotNull(result);
        Assert.Equal("EMAIL", result.MethodType);
        Assert.Contains("admin@example.com", result.EmailAddress);
    }

    [Fact]
    public void GetDomainControlValidation_NoMatchingHost_ReturnsNull()
    {
        Assert.Null(Manager.GetDomainControlValidation("EMAIL", new[] { "admin@other.com" }, "www.example.com"));
    }

    [Fact]
    public void GetDomainControlValidation_SingleEmailOverload_ReturnsValidationVerbatim()
    {
        var result = Manager.GetDomainControlValidation("CNAME", "admin@example.com");
        Assert.Equal("CNAME", result.MethodType);
        Assert.Equal("admin@example.com", result.EmailAddress);
    }

    // ---------------------------------------------------------------------
    // GetCustomFields (exercised via GetRegistrationRequest)
    // ---------------------------------------------------------------------

    [Fact]
    public void GetRegistrationRequest_MandatoryCustomFieldMissing_Throws()
    {
        var productInfo = ProductInfo("CSC TrustedSecure DV");
        var customFields = new List<GetCustomField> { new GetCustomField { Label = "Required Field", Mandatory = true } };

        Assert.Throws<Exception>(() =>
            Manager.GetRegistrationRequest(productInfo, SampleCsr, new Dictionary<string, string[]>(), customFields));
    }

    [Fact]
    public void GetRegistrationRequest_OptionalCustomFieldMissing_DoesNotThrow()
    {
        var productInfo = ProductInfo("CSC TrustedSecure DV");
        var customFields = new List<GetCustomField> { new GetCustomField { Label = "Optional Field", Mandatory = false } };

        var request = Manager.GetRegistrationRequest(productInfo, SampleCsr, new Dictionary<string, string[]>(), customFields);
        Assert.Empty(request.CustomFields);
    }

    [Fact]
    public void GetRegistrationRequest_CustomFieldPresent_IsMapped()
    {
        var productInfo = ProductInfo("CSC TrustedSecure DV", new Dictionary<string, string> { ["Custom Field"] = "value" });
        var customFields = new List<GetCustomField> { new GetCustomField { Label = "Custom Field", Mandatory = false } };

        var request = Manager.GetRegistrationRequest(productInfo, SampleCsr, new Dictionary<string, string[]>(), customFields);

        Assert.Single(request.CustomFields);
        Assert.Equal("value", request.CustomFields[0].Value);
    }

    [Fact]
    public void GetRegistrationRequest_NullCustomFieldsList_ReturnsEmptyCustomFields()
    {
        var request = Manager.GetRegistrationRequest(ProductInfo("CSC TrustedSecure DV"), SampleCsr,
            new Dictionary<string, string[]>(), null!);
        Assert.Empty(request.CustomFields);
    }

    [Fact]
    public void GetRegistrationRequest_CustomFieldsWithNullEntryAndBlankLabel_SkipsBoth()
    {
        var productInfo = ProductInfo("CSC TrustedSecure DV", new Dictionary<string, string> { ["Custom Field"] = "value" });
        var customFields = new List<GetCustomField>
        {
            null!,
            new GetCustomField { Label = "", Mandatory = false },
            new GetCustomField { Label = "Custom Field", Mandatory = false }
        };

        var request = Manager.GetRegistrationRequest(productInfo, SampleCsr, new Dictionary<string, string[]>(), customFields);

        Assert.Single(request.CustomFields);
        Assert.Equal("value", request.CustomFields[0].Value);
    }

    // ---------------------------------------------------------------------
    // GetRenewalRequest / GetReissueRequest - parity with GetRegistrationRequest
    // ---------------------------------------------------------------------

    [Fact]
    public void GetRenewalRequest_EvProduct_PopulatesEvDetailsNoSans()
    {
        var productInfo = ProductInfo("CSC TrustedSecure EV", new Dictionary<string, string> { ["Organization Country"] = "CA" });
        var request = Manager.GetRenewalRequest(productInfo, "uuid-456", SampleCsr, new Dictionary<string, string[]>(), new List<GetCustomField>());

        Assert.Equal("3", request.CertificateType);
        Assert.Null(request.SubjectAlternativeNames);
        Assert.NotNull(request.EvCertificateDetails);
        Assert.Equal("CA", request.EvCertificateDetails.Country);
    }

    [Fact]
    public void GetReissueRequest_EvMultiNameProduct_PopulatesBothSansAndEvDetails()
    {
        var sans = new Dictionary<string, string[]> { ["dnsname"] = new[] { "www.example.com" } };
        var productInfo = ProductInfo("CSC TrustedSecure EV, Multiple Names", new Dictionary<string, string>
        {
            ["Domain Control Validation Method"] = "CNAME",
            ["Organization Country"] = "GB"
        });

        var request = Manager.GetReissueRequest(productInfo, "uuid-000", SampleCsr, sans, new List<GetCustomField>());

        Assert.Equal("7", request.CertificateType);
        Assert.Single(request.SubjectAlternativeNames);
        Assert.NotNull(request.EvCertificateDetails);
        Assert.Equal("GB", request.EvCertificateDetails.Country);
    }

    [Fact]
    public void GetRegistrationRequest_AllOptionalParametersSupplied_MapsEachField()
    {
        var productInfo = ProductInfo("CSC TrustedSecure DV", new Dictionary<string, string>
        {
            ["Term"] = "12",
            ["Applicant First Name"] = "Jane",
            ["Applicant Last Name"] = "Doe",
            ["Applicant Email Address"] = "jane.doe@example.com",
            ["Applicant Phone"] = "555-1234",
            ["Organization Contact"] = "contact-1",
            ["Business Unit"] = "IT"
        });

        var request = Manager.GetRegistrationRequest(productInfo, SampleCsr, new Dictionary<string, string[]>(), new List<GetCustomField>());

        Assert.Equal("12", request.Term);
        Assert.Equal("Jane", request.ApplicantFirstName);
        Assert.Equal("Doe", request.ApplicantLastName);
        Assert.Equal("jane.doe@example.com", request.ApplicantEmailAddress);
        Assert.Equal("555-1234", request.ApplicantPhoneNumber);
        Assert.Equal("contact-1", request.OrganizationContact);
        Assert.Equal("IT", request.BusinessUnit);
    }

    [Fact]
    public void GetRenewalRequest_AllOptionalParametersSupplied_MapsEachField()
    {
        var productInfo = ProductInfo("CSC TrustedSecure DV", new Dictionary<string, string>
        {
            ["Term"] = "24",
            ["Applicant First Name"] = "John",
            ["Applicant Last Name"] = "Smith",
            ["Applicant Email Address"] = "john.smith@example.com",
            ["Applicant Phone"] = "555-5678",
            ["Organization Contact"] = "contact-2",
            ["Business Unit"] = "Legal"
        });

        var request = Manager.GetRenewalRequest(productInfo, "uuid-renewal", SampleCsr, new Dictionary<string, string[]>(), new List<GetCustomField>());

        Assert.Equal("24", request.Term);
        Assert.Equal("John", request.ApplicantFirstName);
        Assert.Equal("Smith", request.ApplicantLastName);
        Assert.Equal("john.smith@example.com", request.ApplicantEmailAddress);
        Assert.Equal("555-5678", request.ApplicantPhoneNumber);
        Assert.Equal("contact-2", request.OrganizationContact);
        Assert.Equal("Legal", request.BusinessUnit);
    }

    [Fact]
    public void GetReissueRequest_AllOptionalParametersSupplied_MapsEachField()
    {
        var productInfo = ProductInfo("CSC TrustedSecure DV", new Dictionary<string, string>
        {
            ["Term"] = "36",
            ["Applicant First Name"] = "Alex",
            ["Applicant Last Name"] = "Nguyen",
            ["Applicant Email Address"] = "alex.nguyen@example.com",
            ["Applicant Phone"] = "555-9012",
            ["Organization Contact"] = "contact-3",
            ["Business Unit"] = "Finance"
        });

        var request = Manager.GetReissueRequest(productInfo, "uuid-reissue", SampleCsr, new Dictionary<string, string[]>(), new List<GetCustomField>());

        Assert.Equal("36", request.Term);
        Assert.Equal("Alex", request.ApplicantFirstName);
        Assert.Equal("Nguyen", request.ApplicantLastName);
        Assert.Equal("alex.nguyen@example.com", request.ApplicantEmailAddress);
        Assert.Equal("555-9012", request.ApplicantPhoneNumber);
        Assert.Equal("contact-3", request.OrganizationContact);
        Assert.Equal("Finance", request.BusinessUnit);
    }

    [Fact]
    public void GetRegistrationRequest_NullProductParameters_Throws()
    {
        var productInfo = new EnrollmentProductInfo { ProductID = "CSC TrustedSecure DV", ProductParameters = null! };
        Assert.Throws<ArgumentNullException>(() =>
            Manager.GetRegistrationRequest(productInfo, SampleCsr, new Dictionary<string, string[]>(), new List<GetCustomField>()));
    }

    [Fact]
    public void GetRegistrationRequest_NullProductInfo_Throws()
    {
        Assert.Throws<ArgumentNullException>(() =>
            Manager.GetRegistrationRequest(null!, SampleCsr, new Dictionary<string, string[]>(), new List<GetCustomField>()));
    }

    [Fact]
    public void GetRegistrationRequest_NullCsr_Throws()
    {
        Assert.Throws<ArgumentNullException>(() =>
            Manager.GetRegistrationRequest(ProductInfo("CSC TrustedSecure DV"), null!, new Dictionary<string, string[]>(), new List<GetCustomField>()));
    }

    [Fact]
    public void GetRegistrationRequest_CsrLongerThan64Chars_WrapsWithPemify()
    {
        var longCsr = new string('X', 130);
        var request = Manager.GetRegistrationRequest(ProductInfo("CSC TrustedSecure DV"), longCsr, new Dictionary<string, string[]>(), new List<GetCustomField>());
        var decoded = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(request.Csr));
        Assert.Contains("\n", decoded);
    }

    [Fact]
    public void GetRenewalRequest_NullUuid_Throws()
    {
        Assert.Throws<ArgumentNullException>(() =>
            Manager.GetRenewalRequest(ProductInfo("CSC TrustedSecure DV"), null!, SampleCsr, new Dictionary<string, string[]>(), new List<GetCustomField>()));
    }

    [Fact]
    public void EvCertificateDetails_AllPropertiesSettable()
    {
        var details = new EvCertificateDetails
        {
            Country = "US",
            City = "Independence",
            State = "OH",
            DateOfIncorporation = "2020-01-01",
            DoingBusinessAs = "Keyfactor",
            BusinessCategory = "Private Organization"
        };

        Assert.Equal("US", details.Country);
        Assert.Equal("Independence", details.City);
        Assert.Equal("OH", details.State);
        Assert.Equal("2020-01-01", details.DateOfIncorporation);
        Assert.Equal("Keyfactor", details.DoingBusinessAs);
        Assert.Equal("Private Organization", details.BusinessCategory);
    }

    [Fact]
    public void GetRegistrationRequest_EncodesCsrAsBase64()
    {
        var request = Manager.GetRegistrationRequest(ProductInfo("CSC TrustedSecure DV"), "hello", new Dictionary<string, string[]>(), new List<GetCustomField>());
        var decoded = Convert.FromBase64String(request.Csr);
        Assert.Contains("hello", System.Text.Encoding.UTF8.GetString(decoded));
    }
}
