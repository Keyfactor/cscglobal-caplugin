// Copyright 2021 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Keyfactor.Extensions.CAPlugin.CSCGlobal.Client.Models;

namespace CscGlobalCAPluginTests;

/// <summary>
///     Mock CSC "mid-cycle reissue" API responses, reproducing a real-world scenario: CSC
///     silently reissues a certificate partway through its order term - same uuid, a new
///     certificate/key pair CSC generated itself (not from Keyfactor's CSR), and
///     isLifeCycleReIssueCertificate set to true on the next list/get response. Keyfactor never
///     holds the private key for the reissued certificate, since it didn't come from our CSR.
///
///     As of this fixture, the plugin does not special-case this flag anywhere - these fixtures
///     exist to let that gap be exercised and tested before any handling is decided/implemented.
///
///     Metadata (uuid, commonName, certificateType, dates) is taken from real CSC API responses;
///     only the certificate/key material is synthetic (freshly generated per test run).
/// </summary>
public static class MidCycleReissueFixtures
{
    private static (string Pem, string ApiBase64) MakeApiCertificate(string commonName)
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest($"CN={commonName}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(365));
        var pem = "-----BEGIN CERTIFICATE-----\n" +
                  Convert.ToBase64String(cert.RawData, Base64FormattingOptions.InsertLineBreaks) +
                  "\n-----END CERTIFICATE-----\n";
        return (pem, Convert.ToBase64String(Encoding.UTF8.GetBytes(pem)));
    }

    /// <summary>
    ///     Single-name DV certificate (cnn.keyfactortestb.com). Real uuid/metadata from a CSC
    ///     sample response; standard mid-order-term sync, no reissue involved.
    /// </summary>
    public static CertificateResponse SingleNameBaseline()
    {
        var (_, apiCert) = MakeApiCertificate("cnn.keyfactortestb.com");
        return new CertificateResponse
        {
            Uuid = "96d8802a-94f5-4616-a27d-bd51bb6eca18",
            CommonName = "cnn.keyfactortestb.com",
            AdditionalNames = new List<string>(),
            CertificateType = "CSC TrustedSecure DV",
            Status = "ACTIVE",
            EffectiveDate = "21-Sep-2026",
            ExpirationDate = "08-Apr-2027",
            OrderValidityStartDate = "21-Sep-2026",
            OrderValidityEndDate = "21-Sep-2027",
            IsRenewed = false,
            IsLifeCycleReIssueCertificate = false,
            BusinessUnit = "Keyfactor API",
            OrderedBy = "Brian Hill",
            OrderDate = "21-Sep-2026",
            ServerSoftware = "OTHER",
            Certificate = apiCert
        };
    }

    /// <summary>
    ///     Same uuid/order as <see cref="SingleNameBaseline" />, reappearing with a CSC-generated
    ///     reissue mid-term: isLifeCycleReIssueCertificate is true, effective/expiration shifted
    ///     forward to the reissue date, order validity window unchanged, and a certificate whose
    ///     key Keyfactor never saw.
    /// </summary>
    public static CertificateResponse SingleNameMidCycleReissue()
    {
        var baseline = SingleNameBaseline();
        var (_, apiCert) = MakeApiCertificate(baseline.CommonName);
        baseline.Certificate = apiCert;
        baseline.EffectiveDate = "05-Nov-2026";
        baseline.ExpirationDate = "23-May-2027";
        baseline.OrderDate = "05-Nov-2026";
        baseline.IsLifeCycleReIssueCertificate = true;
        return baseline;
    }

    /// <summary>
    ///     Wildcard, multi-name DV certificate (*.boingy.com). Real uuid/metadata from a CSC
    ///     sample response; covers the multi-name product type, not just single-name DV.
    /// </summary>
    public static CertificateResponse WildcardMultiNameBaseline()
    {
        var (_, apiCert) = MakeApiCertificate("*.boingy.com");
        return new CertificateResponse
        {
            Uuid = "7db327f6-34a0-4919-9af1-1a76277cc2a7",
            CommonName = "*.boingy.com",
            AdditionalNames = new List<string>(),
            CertificateType = "CSC TrustedSecure DV Wildcard, Multiple Names",
            Status = "ACTIVE",
            EffectiveDate = "16-Sep-2026",
            ExpirationDate = "03-Apr-2027",
            OrderValidityStartDate = "13-Sep-2026",
            OrderValidityEndDate = "13-Sep-2027",
            IsRenewed = false,
            IsLifeCycleReIssueCertificate = false,
            BusinessUnit = "Keyfactor API",
            OrderedBy = "Brian Hill",
            OrderDate = "17-Sep-2026",
            ServerSoftware = "OTHER",
            Certificate = apiCert
        };
    }

    /// <summary>Mid-cycle reissue of <see cref="WildcardMultiNameBaseline" />.</summary>
    public static CertificateResponse WildcardMultiNameMidCycleReissue()
    {
        var baseline = WildcardMultiNameBaseline();
        var (_, apiCert) = MakeApiCertificate(baseline.CommonName);
        baseline.Certificate = apiCert;
        baseline.EffectiveDate = "02-Dec-2026";
        baseline.ExpirationDate = "20-Jun-2027";
        baseline.OrderDate = "02-Dec-2026";
        baseline.IsLifeCycleReIssueCertificate = true;
        return baseline;
    }
}
