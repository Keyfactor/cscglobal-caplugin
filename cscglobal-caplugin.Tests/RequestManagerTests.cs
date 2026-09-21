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
}
