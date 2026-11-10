// Copyright 2021 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Keyfactor.Extensions.CAPlugin.CSCGlobal.Client.Models;

namespace Keyfactor.Extensions.CAPlugin.CSCGlobal.MockData;

/// <summary>
///     Mock CSC "mid-cycle reissue" API responses, reproducing a real-world scenario: CSC
///     silently reissues a certificate partway through its order term - same uuid, re-signed
///     with the *same* key pair as the original (new serial number, shifted validity dates),
///     and isLifeCycleReIssueCertificate set to true on the next list/get response.
///
///     As of this fixture, the plugin does not special-case this flag anywhere - these fixtures
///     exist to let that gap be exercised and tested before any handling is decided/implemented.
///
///     Metadata (uuid, commonName, certificateType, dates) is taken from real CSC API responses;
///     only the certificate material is synthetic (freshly generated per test run), though the
///     baseline and its reissue deliberately share one RSA key pair, re-signed twice.
/// </summary>
public static class MidCycleReissueFixtures
{
    // Keyed by scenario uuid so the baseline and its mid-cycle reissue are re-signed from the
    // same key pair, as they would be if CSC reissued the certificate without a new CSR.
    private static readonly Dictionary<string, RSA> ScenarioKeys = new();

    private static RSA GetOrCreateKey(string uuid)
    {
        if (!ScenarioKeys.TryGetValue(uuid, out var key))
        {
            key = RSA.Create(2048);
            ScenarioKeys[uuid] = key;
        }
        return key;
    }

    private static string MakeApiCertificate(string commonName, RSA key, DateTimeOffset notBefore, DateTimeOffset notAfter)
    {
        var req = new CertificateRequest($"CN={commonName}", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(notBefore, notAfter);
        var pem = "-----BEGIN CERTIFICATE-----\n" +
                  Convert.ToBase64String(cert.RawData, Base64FormattingOptions.InsertLineBreaks) +
                  "\n-----END CERTIFICATE-----\n";
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(pem));
    }

    /// <summary>
    ///     Single-name DV certificate (cnn.keyfactortestb.com). Real uuid/metadata from a CSC
    ///     sample response; standard mid-order-term sync, no reissue involved.
    /// </summary>
    public static CertificateResponse SingleNameBaseline()
    {
        const string uuid = "96d8802a-94f5-4616-a27d-bd51bb6eca18";
        var key = GetOrCreateKey(uuid);
        var apiCert = MakeApiCertificate("cnn.keyfactortestb.com", key,
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(365));
        return new CertificateResponse
        {
            Uuid = uuid,
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
    ///     Same uuid/order/key pair as <see cref="SingleNameBaseline" />, reappearing with a
    ///     mid-term reissue: isLifeCycleReIssueCertificate is true, effective/expiration shifted
    ///     forward to the reissue date, order validity window unchanged, and a *new certificate
    ///     re-signed from the same key* - a new serial number, not a new key pair.
    /// </summary>
    public static CertificateResponse SingleNameMidCycleReissue()
    {
        var baseline = SingleNameBaseline();
        var key = GetOrCreateKey(baseline.Uuid);
        baseline.Certificate = MakeApiCertificate(baseline.CommonName, key,
            DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(366));
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
        const string uuid = "7db327f6-34a0-4919-9af1-1a76277cc2a7";
        var key = GetOrCreateKey(uuid);
        var apiCert = MakeApiCertificate("*.boingy.com", key,
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(365));
        return new CertificateResponse
        {
            Uuid = uuid,
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

    /// <summary>Mid-cycle reissue of <see cref="WildcardMultiNameBaseline" />, re-signed from the same key.</summary>
    public static CertificateResponse WildcardMultiNameMidCycleReissue()
    {
        var baseline = WildcardMultiNameBaseline();
        var key = GetOrCreateKey(baseline.Uuid);
        baseline.Certificate = MakeApiCertificate(baseline.CommonName, key,
            DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(366));
        baseline.EffectiveDate = "02-Dec-2026";
        baseline.ExpirationDate = "20-Jun-2027";
        baseline.OrderDate = "02-Dec-2026";
        baseline.IsLifeCycleReIssueCertificate = true;
        return baseline;
    }
}
