// Copyright 2021 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.

using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.CSCGlobal;
using Keyfactor.Extensions.CAPlugin.CSCGlobal.Client.Models;
using Keyfactor.PKI.Enums.EJBCA;
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
    // GetRenewResponse
    // ---------------------------------------------------------------------

    [Fact]
    public void GetRenewResponse_NullResponse_ReturnsFailed()
    {
        var result = Manager.GetRenewResponse(null);
        Assert.Equal((int)EndEntityStatus.FAILED, result.Status);
        Assert.Contains("no response", result.StatusMessage);
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

        Assert.Equal((int)EndEntityStatus.FAILED, result.Status);
        Assert.Equal("boom", result.StatusMessage);
        Assert.Equal("abc-123", result.CARequestID);
    }

    [Fact]
    public void GetRenewResponse_NullResult_ReturnsFailed()
    {
        var response = new RenewalResponse { Result = null };
        var result = Manager.GetRenewResponse(response);
        Assert.Equal((int)EndEntityStatus.FAILED, result.Status);
        Assert.Contains("no result", result.StatusMessage);
    }

    [Fact]
    public void GetRenewResponse_Success_ReturnsGenerated()
    {
        var response = new RenewalResponse { Result = new Result { CommonName = "renewed.example.com" } };
        var result = Manager.GetRenewResponse(response);
        Assert.Equal((int)EndEntityStatus.GENERATED, result.Status);
        Assert.Contains("renewed.example.com", result.StatusMessage);
    }

    // ---------------------------------------------------------------------
    // GetEnrollmentResult
    // ---------------------------------------------------------------------

    [Fact]
    public void GetEnrollmentResult_NullResponse_ReturnsFailed()
    {
        var result = Manager.GetEnrollmentResult(null);
        Assert.Equal((int)EndEntityStatus.FAILED, result.Status);
    }

    [Fact]
    public void GetEnrollmentResult_RegistrationError_ReturnsFailed()
    {
        var response = new RegistrationResponse { RegistrationError = new RegistrationError { Description = "bad request" } };
        var result = Manager.GetEnrollmentResult(response);
        Assert.Equal((int)EndEntityStatus.FAILED, result.Status);
        Assert.Equal("bad request", result.StatusMessage);
    }

    [Fact]
    public void GetEnrollmentResult_NullResult_ReturnsFailed()
    {
        var response = new RegistrationResponse { Result = null };
        var result = Manager.GetEnrollmentResult(response);
        Assert.Equal((int)EndEntityStatus.FAILED, result.Status);
    }

    [Fact]
    public void GetEnrollmentResult_SuccessNoDcvDetails_ReturnsExternalValidationWithNullContext()
    {
        var response = new RegistrationResponse
        {
            Result = new Result { CommonName = "order-1", Status = new Status { Uuid = "uuid-1" } }
        };

        var result = Manager.GetEnrollmentResult(response);

        Assert.Equal((int)EndEntityStatus.EXTERNALVALIDATION, result.Status);
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
                    // Duplicate email key should not throw and should not be added twice.
                    new DcvDetail { Email = "admin@example.com" },
                    // Entry with neither CName nor Email contributes nothing.
                    new DcvDetail()
                }
            }
        };

        var result = Manager.GetEnrollmentResult(response);

        Assert.NotNull(result.EnrollmentContext);
        Assert.Equal("token", result.EnrollmentContext["_dnsauth.example.com"]);
        Assert.Equal("admin@example.com", result.EnrollmentContext["admin@example.com"]);
        Assert.Equal(2, result.EnrollmentContext.Count);
    }

    // ---------------------------------------------------------------------
    // GetRevokeResult
    // ---------------------------------------------------------------------

    [Fact]
    public void GetRevokeResult_NullResponse_ReturnsFailed()
    {
        Assert.Equal((int)EndEntityStatus.FAILED, Manager.GetRevokeResult(null));
    }

    [Fact]
    public void GetRevokeResult_RegistrationError_ReturnsFailed()
    {
        var response = new RevokeResponse { RegistrationError = new RegistrationError { Description = "nope" } };
        Assert.Equal((int)EndEntityStatus.FAILED, Manager.GetRevokeResult(response));
    }

    [Fact]
    public void GetRevokeResult_Success_ReturnsRevoked()
    {
        var response = new RevokeResponse();
        Assert.Equal((int)EndEntityStatus.REVOKED, Manager.GetRevokeResult(response));
    }

    // ---------------------------------------------------------------------
    // GetReIssueResult
    // ---------------------------------------------------------------------

    [Fact]
    public void GetReIssueResult_NullResponse_ReturnsFailed()
    {
        var result = Manager.GetReIssueResult(null);
        Assert.Equal((int)EndEntityStatus.FAILED, result.Status);
    }

    [Fact]
    public void GetReIssueResult_RegistrationError_ReturnsFailed()
    {
        var response = new ReissueResponse { RegistrationError = new RegistrationError { Description = "rejected" } };
        var result = Manager.GetReIssueResult(response);
        Assert.Equal((int)EndEntityStatus.FAILED, result.Status);
        Assert.Equal("rejected", result.StatusMessage);
    }

    [Fact]
    public void GetReIssueResult_NullResult_ReturnsFailed()
    {
        var response = new ReissueResponse { Result = null };
        var result = Manager.GetReIssueResult(response);
        Assert.Equal((int)EndEntityStatus.FAILED, result.Status);
    }

    [Fact]
    public void GetReIssueResult_Success_ReturnsGenerated()
    {
        var response = new ReissueResponse
        {
            Result = new Result { CommonName = "reissued.example.com", Status = new Status { Uuid = "uuid-3" } }
        };
        var result = Manager.GetReIssueResult(response);
        Assert.Equal((int)EndEntityStatus.GENERATED, result.Status);
        Assert.Equal("uuid-3", result.CARequestID);
    }

    // ---------------------------------------------------------------------
    // GetDomainControlValidation (email-list overload)
    // ---------------------------------------------------------------------

    [Fact]
    public void GetDomainControlValidation_EmptyDomainName_ReturnsNull()
    {
        var result = Manager.GetDomainControlValidation("EMAIL", new[] { "admin@example.com" }, "");
        Assert.Null(result);
    }

    [Fact]
    public void GetDomainControlValidation_NullEmailArray_ReturnsNull()
    {
        var result = Manager.GetDomainControlValidation("EMAIL", null!, "example.com");
        Assert.Null(result);
    }

    [Fact]
    public void GetDomainControlValidation_MalformedEmailSkipped_NoMatchReturnsNull()
    {
        var result = Manager.GetDomainControlValidation("EMAIL", new[] { "not-an-email", "  " }, "example.com");
        Assert.Null(result);
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
        var result = Manager.GetDomainControlValidation("EMAIL", new[] { "admin@other.com" }, "www.example.com");
        Assert.Null(result);
    }

    // ---------------------------------------------------------------------
    // GetDomainControlValidation (single-email overload)
    // ---------------------------------------------------------------------

    [Fact]
    public void GetDomainControlValidation_SingleEmail_ReturnsValidationVerbatim()
    {
        var result = Manager.GetDomainControlValidation("CNAME", "admin@example.com");
        Assert.Equal("CNAME", result.MethodType);
        Assert.Equal("admin@example.com", result.EmailAddress);
    }

    // ---------------------------------------------------------------------
    // MapReturnStatus
    // ---------------------------------------------------------------------

    public static IEnumerable<object?[]> MapReturnStatusCases()
    {
        yield return new object?[] { "ACTIVE", (int)EndEntityStatus.GENERATED };
        yield return new object?[] { "Initial", (int)EndEntityStatus.INITIALIZED };
        yield return new object?[] { "Pending", (int)EndEntityStatus.INPROCESS };
        yield return new object?[] { "REVOKED", (int)EndEntityStatus.REVOKED };
        yield return new object?[] { "SOMETHING_ELSE", (int)EndEntityStatus.FAILED };
        yield return new object?[] { null, (int)EndEntityStatus.FAILED };
    }

    [Theory]
    [MemberData(nameof(MapReturnStatusCases))]
    public void MapReturnStatus_MapsExpectedStatus(string? cscStatus, int expected)
    {
        Assert.Equal(expected, Manager.MapReturnStatus(cscStatus!));
    }

    // ---------------------------------------------------------------------
    // GetRegistrationRequest - certificate type routing
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
    [InlineData("Some Unknown Product", "-1", false, false)]
    public void GetRegistrationRequest_RoutesCertificateTypeAndOptionalSections(
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
        if (expectEv)
            Assert.Equal("US", request.EvCertificateDetails.Country);
    }

    [Fact]
    public void GetRegistrationRequest_EncodesCsrAsBase64()
    {
        var productInfo = ProductInfo("CSC TrustedSecure OV");
        var request = Manager.GetRegistrationRequest(productInfo, "hello", new Dictionary<string, string[]>(), new List<GetCustomField>());

        var decoded = Convert.FromBase64String(request.Csr);
        Assert.Equal("hello", System.Text.Encoding.UTF8.GetString(decoded));
    }

    [Fact]
    public void GetRegistrationRequest_MandatoryCustomFieldMissing_Throws()
    {
        var productInfo = ProductInfo("CSC TrustedSecure OV");
        var customFields = new List<GetCustomField> { new GetCustomField { Label = "Required Field", Mandatory = true } };

        Assert.Throws<Exception>(() =>
            Manager.GetRegistrationRequest(productInfo, SampleCsr, new Dictionary<string, string[]>(), customFields));
    }

    [Fact]
    public void GetRegistrationRequest_NullCustomFields_ReturnsEmptyList()
    {
        var productInfo = ProductInfo("CSC TrustedSecure OV");

        var request = Manager.GetRegistrationRequest(productInfo, SampleCsr, new Dictionary<string, string[]>(), null!);

        Assert.Empty(request.CustomFields);
    }

    [Fact]
    public void GetRegistrationRequest_OptionalCustomFieldMissing_Skipped()
    {
        var productInfo = ProductInfo("CSC TrustedSecure OV");
        var customFields = new List<GetCustomField> { new GetCustomField { Label = "Optional Field", Mandatory = false } };

        var request = Manager.GetRegistrationRequest(productInfo, SampleCsr, new Dictionary<string, string[]>(), customFields);

        Assert.Empty(request.CustomFields);
    }

    [Fact]
    public void GetRegistrationRequest_CustomFieldPresent_IsMapped()
    {
        var productInfo = ProductInfo("CSC TrustedSecure OV", new Dictionary<string, string> { ["Custom Field"] = "value" });
        var customFields = new List<GetCustomField> { new GetCustomField { Label = "Custom Field", Mandatory = false } };

        var request = Manager.GetRegistrationRequest(productInfo, SampleCsr, new Dictionary<string, string[]>(), customFields);

        Assert.Single(request.CustomFields);
        Assert.Equal("value", request.CustomFields[0].Value);
    }

    // ---------------------------------------------------------------------
    // GetSubjectAlternativeNames (exercised via GetRegistrationRequest)
    // ---------------------------------------------------------------------

    [Fact]
    public void GetRegistrationRequest_MultiNameEmailMethod_MatchesAdditionalSanEmail()
    {
        var sans = new Dictionary<string, string[]> { ["dnsname"] = new[] { "www.example.com" } };
        var productInfo = ProductInfo("CSC TrustedSecure OV, Multiple Names", new Dictionary<string, string>
        {
            ["Domain Control Validation Method"] = "EMAIL",
            ["Addtl Sans Comma Separated DVC Emails"] = "admin@example.com,admin@other.com"
        });

        var request = Manager.GetRegistrationRequest(productInfo, SampleCsr, sans, new List<GetCustomField>());

        Assert.Single(request.SubjectAlternativeNames);
        var san = request.SubjectAlternativeNames[0];
        Assert.Equal("www.example.com", san.DomainName);
        Assert.NotNull(san.DomainControlValidation);
        Assert.Equal("admin@example.com", san.DomainControlValidation.EmailAddress);
    }

    [Fact]
    public void GetRegistrationRequest_MultiNameEmailMethodNoAddtlEmailsConfigured_NoDcvMatch()
    {
        var sans = new Dictionary<string, string[]> { ["dnsname"] = new[] { "www.example.com" } };
        var productInfo = ProductInfo("CSC TrustedSecure OV, Multiple Names", new Dictionary<string, string>
        {
            ["Domain Control Validation Method"] = "EMAIL"
        });

        var request = Manager.GetRegistrationRequest(productInfo, SampleCsr, sans, new List<GetCustomField>());

        Assert.Single(request.SubjectAlternativeNames);
        Assert.Null(request.SubjectAlternativeNames[0].DomainControlValidation);
    }

    [Fact]
    public void GetRegistrationRequest_MultiNameCnameMethod_UsesEmptyEmailValidation()
    {
        var sans = new Dictionary<string, string[]> { ["dnsname"] = new[] { "www.example.com" } };
        var productInfo = ProductInfo("CSC TrustedSecure OV, Multiple Names", new Dictionary<string, string>
        {
            ["Domain Control Validation Method"] = "CNAME"
        });

        var request = Manager.GetRegistrationRequest(productInfo, SampleCsr, sans, new List<GetCustomField>());

        Assert.Single(request.SubjectAlternativeNames);
        var san = request.SubjectAlternativeNames[0];
        Assert.NotNull(san.DomainControlValidation);
        Assert.Equal(string.Empty, san.DomainControlValidation.EmailAddress);
    }

    [Fact]
    public void GetRegistrationRequest_MultiNameProductWithNoDnsNameKey_ReturnsEmptySanList()
    {
        var productInfo = ProductInfo("CSC TrustedSecure OV, Multiple Names", new Dictionary<string, string>
        {
            ["Domain Control Validation Method"] = "CNAME"
        });

        var request = Manager.GetRegistrationRequest(productInfo, SampleCsr, new Dictionary<string, string[]>(), new List<GetCustomField>());

        Assert.NotNull(request.SubjectAlternativeNames);
        Assert.Empty(request.SubjectAlternativeNames);
    }

    [Fact]
    public void GetRegistrationRequest_MultiNameProductWithNullSans_ReturnsEmptySanList()
    {
        var productInfo = ProductInfo("CSC TrustedSecure OV, Multiple Names", new Dictionary<string, string>
        {
            ["Domain Control Validation Method"] = "CNAME"
        });

        var request = Manager.GetRegistrationRequest(productInfo, SampleCsr, null!, new List<GetCustomField>());

        Assert.NotNull(request.SubjectAlternativeNames);
        Assert.Empty(request.SubjectAlternativeNames);
    }

    // ---------------------------------------------------------------------
    // GetNotifications
    // ---------------------------------------------------------------------

    [Fact]
    public void GetNotifications_NoEmailsConfigured_ReturnsEmptyList()
    {
        var productInfo = ProductInfo("CSC TrustedSecure OV");
        var notifications = Manager.GetNotifications(productInfo);
        Assert.True(notifications.Enabled);
        Assert.Empty(notifications.AdditionalNotificationEmails);
    }

    [Fact]
    public void GetNotifications_EmailsConfigured_SplitsOnComma()
    {
        var productInfo = ProductInfo("CSC TrustedSecure OV",
            new Dictionary<string, string> { ["Notification Email(s) Comma Separated"] = "a@example.com,b@example.com" });

        var notifications = Manager.GetNotifications(productInfo);

        Assert.Equal(2, notifications.AdditionalNotificationEmails.Count);
        Assert.Contains("a@example.com", notifications.AdditionalNotificationEmails);
    }

    // ---------------------------------------------------------------------
    // GetRenewalRequest / GetReissueRequest - basic parity with GetRegistrationRequest
    // ---------------------------------------------------------------------

    [Fact]
    public void GetRenewalRequest_MultiNameProduct_PopulatesUuidAndSans()
    {
        var sans = new Dictionary<string, string[]> { ["dnsname"] = new[] { "www.example.com" } };
        var productInfo = ProductInfo("CSC TrustedSecure DV, Multiple Names", new Dictionary<string, string>
        {
            ["Domain Control Validation Method"] = "CNAME"
        });

        var request = Manager.GetRenewalRequest(productInfo, "uuid-123", SampleCsr, sans, new List<GetCustomField>());

        Assert.Equal("uuid-123", request.Uuid);
        Assert.Equal("6", request.CertificateType);
        Assert.Single(request.SubjectAlternativeNames);
        Assert.Null(request.EvCertificateDetails);
    }

    [Fact]
    public void GetRenewalRequest_EvProduct_PopulatesEvDetailsNoSans()
    {
        var productInfo = ProductInfo("CSC TrustedSecure EV", new Dictionary<string, string>
        {
            ["Organization Country"] = "CA"
        });

        var request = Manager.GetRenewalRequest(productInfo, "uuid-456", SampleCsr, new Dictionary<string, string[]>(), new List<GetCustomField>());

        Assert.Equal("3", request.CertificateType);
        Assert.Null(request.SubjectAlternativeNames);
        Assert.NotNull(request.EvCertificateDetails);
        Assert.Equal("CA", request.EvCertificateDetails.Country);
    }

    [Fact]
    public void GetReissueRequest_MultiNameProduct_PopulatesUuidAndSans()
    {
        var sans = new Dictionary<string, string[]> { ["dnsname"] = new[] { "www.example.com" } };
        var productInfo = ProductInfo("CSC TrustedSecure OV Wildcard, Multiple Names", new Dictionary<string, string>
        {
            ["Domain Control Validation Method"] = "CNAME"
        });

        var request = Manager.GetReissueRequest(productInfo, "uuid-789", SampleCsr, sans, new List<GetCustomField>());

        Assert.Equal("uuid-789", request.Uuid);
        Assert.Equal("8", request.CertificateType);
        Assert.Single(request.SubjectAlternativeNames);
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
}
