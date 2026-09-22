// Copyright 2021 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.

using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.CSCGlobal;
using Keyfactor.Extensions.CAPlugin.CSCGlobal.Client.Models;
using Keyfactor.Extensions.CAPlugin.CSCGlobal.Interfaces;
using Keyfactor.PKI.Enums.EJBCA;
using Moq;
using Xunit;

namespace CscGlobalCAPluginTests;

public class CSCGlobalCAPluginTests
{
    private sealed class FakeConfigProvider : IAnyCAPluginConfigProvider
    {
        public Dictionary<string, object> CAConnectionData { get; set; } = new();
    }

    private static Dictionary<string, object> ValidConnectionData() => new()
    {
        [Constants.CscGlobalUrl] = "https://api.csc.test",
        [Constants.CscGlobalApiKey] = "test-api-key",
        [Constants.BearerToken] = "test-bearer-token"
    };

    private static CSCGlobalCAPlugin MakePlugin(Mock<ICscGlobalClient>? client = null,
        Mock<ICertificateDataReader>? certDataReader = null, Dictionary<string, object>? connectionData = null)
    {
        var plugin = new CSCGlobalCAPlugin();
        plugin.Initialize(new FakeConfigProvider { CAConnectionData = connectionData ?? ValidConnectionData() },
            (certDataReader ?? new Mock<ICertificateDataReader>()).Object);
        if (client != null)
            plugin.ClientFactory = _ => client.Object;
        return plugin;
    }

    private static EnrollmentProductInfo ProductInfo(string productId = "CSC TrustedSecure OV",
        Dictionary<string, string>? parameters = null) => new EnrollmentProductInfo
    {
        ProductID = productId,
        ProductParameters = parameters ?? new Dictionary<string, string>()
    };

    private static (X509Certificate2 Cert, string Pem) MakeSelfSignedCert(string cn = "test.example.com", bool isCa = false)
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest($"CN={cn}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(isCa, false, 0, true));
        var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(365));
        var pem = "-----BEGIN CERTIFICATE-----\n" +
                  Convert.ToBase64String(cert.RawData, Base64FormattingOptions.InsertLineBreaks) +
                  "\n-----END CERTIFICATE-----\n";
        return (cert, pem);
    }

    private static string ToApiBase64(string pemText) => Convert.ToBase64String(Encoding.UTF8.GetBytes(pemText));

    // ---------------------------------------------------------------------
    // Initialize
    // ---------------------------------------------------------------------

    [Fact]
    public void Initialize_NullConfigProvider_Throws()
    {
        var plugin = new CSCGlobalCAPlugin();
        Assert.Throws<ArgumentNullException>(() => plugin.Initialize(null!, Mock.Of<ICertificateDataReader>()));
    }

    [Fact]
    public void Initialize_NullCertDataReader_Throws()
    {
        var plugin = new CSCGlobalCAPlugin();
        Assert.Throws<ArgumentNullException>(() =>
            plugin.Initialize(new FakeConfigProvider { CAConnectionData = ValidConnectionData() }, null!));
    }

    [Fact]
    public void Initialize_MissingEnabled_DefaultsToTrue()
    {
        var plugin = new CSCGlobalCAPlugin();
        plugin.Initialize(new FakeConfigProvider { CAConnectionData = ValidConnectionData() }, Mock.Of<ICertificateDataReader>());
        Assert.True(plugin.Enabled);
    }

    [Fact]
    public void Initialize_ExplicitlyDisabled_ParsesFalse()
    {
        var data = ValidConnectionData();
        data[Constants.Enabled] = "false";
        var plugin = new CSCGlobalCAPlugin();
        plugin.Initialize(new FakeConfigProvider { CAConnectionData = data }, Mock.Of<ICertificateDataReader>());
        Assert.False(plugin.Enabled);
    }

    [Fact]
    public void Initialize_UnparsableEnabled_DefaultsToTrue()
    {
        var data = ValidConnectionData();
        data[Constants.Enabled] = "not-a-bool";
        var plugin = new CSCGlobalCAPlugin();
        plugin.Initialize(new FakeConfigProvider { CAConnectionData = data }, Mock.Of<ICertificateDataReader>());
        Assert.True(plugin.Enabled);
    }

    [Fact]
    public void Initialize_ValidSyncFilterDays_ParsesValue()
    {
        var data = ValidConnectionData();
        data[Constants.SyncFilterDays] = "10";
        var plugin = new CSCGlobalCAPlugin();
        plugin.Initialize(new FakeConfigProvider { CAConnectionData = data }, Mock.Of<ICertificateDataReader>());
        Assert.Equal(10, plugin.SyncFilterDays);
    }

    [Fact]
    public void Initialize_UnparsableSyncFilterDays_LeavesDefault()
    {
        var data = ValidConnectionData();
        data[Constants.SyncFilterDays] = "not-a-number";
        var plugin = new CSCGlobalCAPlugin();
        plugin.Initialize(new FakeConfigProvider { CAConnectionData = data }, Mock.Of<ICertificateDataReader>());
        Assert.Equal(0, plugin.SyncFilterDays);
    }

    [Fact]
    public void Initialize_MissingSyncFilterDays_LeavesDefault()
    {
        var plugin = new CSCGlobalCAPlugin();
        plugin.Initialize(new FakeConfigProvider { CAConnectionData = ValidConnectionData() }, Mock.Of<ICertificateDataReader>());
        Assert.Equal(0, plugin.SyncFilterDays);
    }

    [Fact]
    public void Initialize_ValidRenewalWindowDays_ParsesValue()
    {
        var data = ValidConnectionData();
        data[Constants.RenewalWindowDays] = "45";
        var plugin = new CSCGlobalCAPlugin();
        plugin.Initialize(new FakeConfigProvider { CAConnectionData = data }, Mock.Of<ICertificateDataReader>());
        Assert.Equal(45, plugin.RenewalWindowDays);
    }

    [Fact]
    public void Initialize_MissingRenewalWindowDays_DefaultsTo30()
    {
        var plugin = new CSCGlobalCAPlugin();
        plugin.Initialize(new FakeConfigProvider { CAConnectionData = ValidConnectionData() }, Mock.Of<ICertificateDataReader>());
        Assert.Equal(30, plugin.RenewalWindowDays);
    }

    [Theory]
    [InlineData("not-a-number")]
    [InlineData("-5")]
    [InlineData("0")]
    public void Initialize_InvalidRenewalWindowDays_DefaultsTo30(string raw)
    {
        var data = ValidConnectionData();
        data[Constants.RenewalWindowDays] = raw;
        var plugin = new CSCGlobalCAPlugin();
        plugin.Initialize(new FakeConfigProvider { CAConnectionData = data }, Mock.Of<ICertificateDataReader>());
        Assert.Equal(30, plugin.RenewalWindowDays);
    }

    // ---------------------------------------------------------------------
    // GetSingleRecord
    // ---------------------------------------------------------------------

    [Fact]
    public async Task GetSingleRecord_ShortCaRequestId_ThrowsWrappedException()
    {
        var plugin = MakePlugin();
        await Assert.ThrowsAsync<Exception>(() => plugin.GetSingleRecord("too-short"));
    }

    [Fact]
    public async Task GetSingleRecord_NullCaRequestId_ThrowsWrappedException()
    {
        var plugin = MakePlugin();
        await Assert.ThrowsAsync<Exception>(() => plugin.GetSingleRecord(null!));
    }

    [Fact]
    public async Task GetSingleRecord_ValidId_ReturnsMappedCertificate()
    {
        var uuid = Guid.NewGuid().ToString();
        var (cert, pem) = MakeSelfSignedCert();
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitGetCertificateAsync(uuid)).ReturnsAsync(new CertificateResponse
        {
            Certificate = Convert.ToBase64String(Encoding.ASCII.GetBytes(pem)),
            Status = "ACTIVE"
        });

        var plugin = MakePlugin(mockClient);
        var result = await plugin.GetSingleRecord(uuid);

        Assert.Equal(uuid, result.CARequestID);
        Assert.Equal((int)EndEntityStatus.GENERATED, result.Status);
        Assert.Equal(Convert.ToBase64String(cert.RawData), result.Certificate);
    }

    [Fact]
    public async Task GetSingleRecord_ClientThrows_WrapsException()
    {
        var uuid = Guid.NewGuid().ToString();
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitGetCertificateAsync(uuid)).ThrowsAsync(new InvalidOperationException("boom"));

        var plugin = MakePlugin(mockClient);
        await Assert.ThrowsAsync<Exception>(() => plugin.GetSingleRecord(uuid));
    }

    // ---------------------------------------------------------------------
    // Synchronize
    // ---------------------------------------------------------------------

    [Fact]
    public async Task Synchronize_FullSync_QueuesActiveAndRevokedOnly()
    {
        var (cert, pem) = MakeSelfSignedCert();
        var apiCert = ToApiBase64(pem);

        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitCertificateListRequestAsync(null)).ReturnsAsync(new CertificateListResponse
        {
            Results = new List<CertificateResponse>
            {
                new CertificateResponse { Uuid = "cert-1", Status = "ACTIVE", CertificateType = "CSC TrustedSecure OV", Certificate = apiCert },
                new CertificateResponse { Uuid = "cert-2", Status = "REVOKED", CertificateType = "CSC TrustedSecure DV", Certificate = apiCert },
                new CertificateResponse { Uuid = "cert-3", Status = "Pending", CertificateType = "CSC TrustedSecure OV", Certificate = apiCert }
            }
        });

        var plugin = MakePlugin(mockClient);
        var buffer = new BlockingCollection<AnyCAPluginCertificate>();

        await plugin.Synchronize(buffer, null, true, CancellationToken.None);

        var items = buffer.ToList();
        Assert.Equal(2, items.Count);
        Assert.Contains(items, i => i.CARequestID == "cert-1" && i.ProductID == "CSC TrustedSecure OV");
        Assert.Contains(items, i => i.CARequestID == "cert-2" && i.ProductID == "CSC TrustedSecure DV");
    }

    [Fact]
    public async Task Synchronize_IncrementalSync_UsesConfiguredFilterDays()
    {
        var mockClient = new Mock<ICscGlobalClient>();
        string? capturedFilter = null;
        mockClient.Setup(c => c.SubmitCertificateListRequestAsync(It.IsAny<string?>()))
            .Callback<string?>(f => capturedFilter = f)
            .ReturnsAsync(new CertificateListResponse { Results = new List<CertificateResponse>() });

        var data = ValidConnectionData();
        data[Constants.SyncFilterDays] = "10";
        var plugin = MakePlugin(mockClient, connectionData: data);
        var buffer = new BlockingCollection<AnyCAPluginCertificate>();

        await plugin.Synchronize(buffer, DateTime.UtcNow, false, CancellationToken.None);

        Assert.NotNull(capturedFilter);
        Assert.Equal(DateTime.Today.Subtract(TimeSpan.FromDays(10)).ToString("yyyy/MM/dd"), capturedFilter);
    }

    [Fact]
    public async Task Synchronize_IncrementalSync_DefaultsToFiveDaysWhenUnset()
    {
        var mockClient = new Mock<ICscGlobalClient>();
        string? capturedFilter = null;
        mockClient.Setup(c => c.SubmitCertificateListRequestAsync(It.IsAny<string?>()))
            .Callback<string?>(f => capturedFilter = f)
            .ReturnsAsync(new CertificateListResponse { Results = new List<CertificateResponse>() });

        var plugin = MakePlugin(mockClient);
        var buffer = new BlockingCollection<AnyCAPluginCertificate>();

        await plugin.Synchronize(buffer, DateTime.UtcNow, false, CancellationToken.None);

        Assert.Equal(DateTime.Today.Subtract(TimeSpan.FromDays(5)).ToString("yyyy/MM/dd"), capturedFilter);
    }

    [Fact]
    public async Task Synchronize_NullResultsCollection_CompletesWithoutQueueing()
    {
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitCertificateListRequestAsync(It.IsAny<string?>()))
            .ReturnsAsync(new CertificateListResponse { Results = null });

        var plugin = MakePlugin(mockClient);
        var buffer = new BlockingCollection<AnyCAPluginCertificate>();

        await plugin.Synchronize(buffer, null, true, CancellationToken.None);

        Assert.Empty(buffer.ToList());
        Assert.True(buffer.IsAddingCompleted);
    }

    [Fact]
    public async Task Synchronize_EmptyCertificateContent_SkipsRecord()
    {
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitCertificateListRequestAsync(It.IsAny<string?>()))
            .ReturnsAsync(new CertificateListResponse
            {
                Results = new List<CertificateResponse>
                {
                    new CertificateResponse { Uuid = "cert-empty", Status = "ACTIVE", Certificate = "" }
                }
            });

        var plugin = MakePlugin(mockClient);
        var buffer = new BlockingCollection<AnyCAPluginCertificate>();

        await plugin.Synchronize(buffer, null, true, CancellationToken.None);

        Assert.Empty(buffer.ToList());
    }

    [Fact]
    public async Task Synchronize_UnparsableCertificateContent_SkipsRecord()
    {
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitCertificateListRequestAsync(It.IsAny<string?>()))
            .ReturnsAsync(new CertificateListResponse
            {
                Results = new List<CertificateResponse>
                {
                    new CertificateResponse
                    {
                        Uuid = "cert-bad",
                        Status = "ACTIVE",
                        Certificate = ToApiBase64("not a valid pem block at all")
                    }
                }
            });

        var plugin = MakePlugin(mockClient);
        var buffer = new BlockingCollection<AnyCAPluginCertificate>();

        await plugin.Synchronize(buffer, null, true, CancellationToken.None);

        Assert.Empty(buffer.ToList());
    }

    [Fact]
    public async Task Synchronize_MissingProductIdFromCsc_LeavesProductIdNull()
    {
        var (_, pem) = MakeSelfSignedCert();
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitCertificateListRequestAsync(It.IsAny<string?>()))
            .ReturnsAsync(new CertificateListResponse
            {
                Results = new List<CertificateResponse>
                {
                    new CertificateResponse { Uuid = "cert-1", Status = "ACTIVE", CertificateType = null, Certificate = ToApiBase64(pem) }
                }
            });

        var plugin = MakePlugin(mockClient);
        var buffer = new BlockingCollection<AnyCAPluginCertificate>();

        await plugin.Synchronize(buffer, null, true, CancellationToken.None);

        var item = Assert.Single(buffer.ToList());
        Assert.Null(item.ProductID);
    }

    [Fact]
    public async Task Synchronize_CancellationRequested_ThrowsAndCompletesBuffer()
    {
        var (_, pem) = MakeSelfSignedCert();
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitCertificateListRequestAsync(It.IsAny<string?>()))
            .ReturnsAsync(new CertificateListResponse
            {
                Results = new List<CertificateResponse>
                {
                    new CertificateResponse { Uuid = "cert-1", Status = "ACTIVE", Certificate = ToApiBase64(pem) }
                }
            });

        var plugin = MakePlugin(mockClient);
        var buffer = new BlockingCollection<AnyCAPluginCertificate>();
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAsync<OperationCanceledException>(() =>
            plugin.Synchronize(buffer, null, true, cts.Token));

        Assert.True(buffer.IsAddingCompleted);
    }

    [Fact]
    public async Task Synchronize_ClientThrows_CompletesBufferAndRethrows()
    {
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitCertificateListRequestAsync(It.IsAny<string?>()))
            .ThrowsAsync(new InvalidOperationException("network down"));

        var plugin = MakePlugin(mockClient);
        var buffer = new BlockingCollection<AnyCAPluginCertificate>();

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            plugin.Synchronize(buffer, null, true, CancellationToken.None));

        Assert.True(buffer.IsAddingCompleted);
    }

    [Fact]
    public async Task Synchronize_Disabled_CompletesBufferWithoutCallingClient()
    {
        var mockClient = new Mock<ICscGlobalClient>();
        var data = ValidConnectionData();
        data[Constants.Enabled] = "false";
        var plugin = MakePlugin(mockClient, connectionData: data);
        var buffer = new BlockingCollection<AnyCAPluginCertificate>();

        await plugin.Synchronize(buffer, null, true, CancellationToken.None);

        Assert.True(buffer.IsAddingCompleted);
        Assert.Empty(buffer);
        mockClient.Verify(c => c.SubmitCertificateListRequestAsync(It.IsAny<string?>()), Times.Never);
    }

    // ---------------------------------------------------------------------
    // Revoke
    // ---------------------------------------------------------------------

    [Fact]
    public async Task Revoke_ShortCaRequestId_ThrowsWrappedException()
    {
        var plugin = MakePlugin();
        await Assert.ThrowsAsync<Exception>(() => plugin.Revoke("short", "AB12", 0));
    }

    [Fact]
    public async Task Revoke_Success_ReturnsRevokedStatus()
    {
        var uuid = Guid.NewGuid().ToString();
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitRevokeCertificateAsync(uuid)).ReturnsAsync(new RevokeResponse());

        var plugin = MakePlugin(mockClient);
        var status = await plugin.Revoke(uuid, "AB12", 0);

        Assert.Equal((int)EndEntityStatus.REVOKED, status);
    }

    [Fact]
    public async Task Revoke_ErrorWithDescription_ThrowsWrappedException()
    {
        var uuid = Guid.NewGuid().ToString();
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitRevokeCertificateAsync(uuid)).ReturnsAsync(new RevokeResponse
        {
            RegistrationError = new RegistrationError { Description = "already revoked" }
        });

        var plugin = MakePlugin(mockClient);
        await Assert.ThrowsAsync<Exception>(() => plugin.Revoke(uuid, "AB12", 0));
    }

    [Fact]
    public async Task Revoke_FailedWithNoErrorDescription_ReturnsFailedStatus()
    {
        var uuid = Guid.NewGuid().ToString();
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitRevokeCertificateAsync(uuid)).ReturnsAsync((RevokeResponse)null!);

        var plugin = MakePlugin(mockClient);
        var status = await plugin.Revoke(uuid, "AB12", 0);

        Assert.Equal((int)EndEntityStatus.FAILED, status);
    }

    [Fact]
    public async Task Revoke_Disabled_ThrowsInvalidOperationException()
    {
        var mockClient = new Mock<ICscGlobalClient>();
        var data = ValidConnectionData();
        data[Constants.Enabled] = "false";
        var plugin = MakePlugin(mockClient, connectionData: data);

        await Assert.ThrowsAsync<InvalidOperationException>(() => plugin.Revoke(Guid.NewGuid().ToString(), "AB12", 0));
        mockClient.Verify(c => c.SubmitRevokeCertificateAsync(It.IsAny<string>()), Times.Never);
    }

    // ---------------------------------------------------------------------
    // Enroll
    // ---------------------------------------------------------------------

    [Fact]
    public async Task Enroll_NullProductInfo_ThrowsArgumentNullException()
    {
        var plugin = MakePlugin();
        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            plugin.Enroll("csr", "subject", new Dictionary<string, string[]>(), null!, RequestFormat.PKCS10, EnrollmentType.New));
    }

    [Fact]
    public async Task Enroll_Disabled_ReturnsFailedWithoutCallingClient()
    {
        var mockClient = new Mock<ICscGlobalClient>();
        var data = ValidConnectionData();
        data[Constants.Enabled] = "false";
        var plugin = MakePlugin(mockClient, connectionData: data);

        var result = await plugin.Enroll("csr", "CN=test", new Dictionary<string, string[]>(), ProductInfo(),
            RequestFormat.PKCS10, EnrollmentType.New);

        Assert.Equal((int)EndEntityStatus.FAILED, result!.Status);
        Assert.Contains("Disabled", result.StatusMessage);
        mockClient.Verify(c => c.SubmitGetCustomFields(), Times.Never);
    }

    [Fact]
    public async Task Enroll_New_Success_ReturnsExternalValidation()
    {
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitGetCustomFields()).ReturnsAsync(new List<GetCustomField>());
        mockClient.Setup(c => c.SubmitRegistrationAsync(It.IsAny<RegistrationRequest>())).ReturnsAsync(new RegistrationResponse
        {
            Result = new Result { CommonName = "order-1", Status = new Status { Uuid = "uuid-1" } }
        });

        var plugin = MakePlugin(mockClient);
        var result = await plugin.Enroll("csr", "CN=test", new Dictionary<string, string[]>(), ProductInfo(), RequestFormat.PKCS10, EnrollmentType.New);

        Assert.Equal((int)EndEntityStatus.EXTERNALVALIDATION, result!.Status);
        Assert.Equal("uuid-1", result.CARequestID);
    }

    [Fact]
    public async Task Enroll_New_CscReturnsError_ReturnsFailedStatus()
    {
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitGetCustomFields()).ReturnsAsync(new List<GetCustomField>());
        mockClient.Setup(c => c.SubmitRegistrationAsync(It.IsAny<RegistrationRequest>())).ReturnsAsync(new RegistrationResponse
        {
            RegistrationError = new RegistrationError { Description = "duplicate order" }
        });

        var plugin = MakePlugin(mockClient);
        var result = await plugin.Enroll("csr", "CN=test", new Dictionary<string, string[]>(), ProductInfo(),
            RequestFormat.PKCS10, EnrollmentType.New);

        Assert.Equal((int)EndEntityStatus.FAILED, result!.Status);
        Assert.Contains("Flow: Enroll", result.StatusMessage);
        Assert.Contains("duplicate order", result.StatusMessage);
    }

    [Fact]
    public async Task Enroll_NewWithPriorCertSn_ReturnsFailureWithoutCallingClient()
    {
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitGetCustomFields()).ReturnsAsync(new List<GetCustomField>());

        var plugin = MakePlugin(mockClient);
        var productInfo = ProductInfo(parameters: new Dictionary<string, string> { ["PriorCertSN"] = "ABC123" });

        var result = await plugin.Enroll("csr", "CN=test", new Dictionary<string, string[]>(), productInfo, RequestFormat.PKCS10, EnrollmentType.New);

        Assert.Equal((int)EndEntityStatus.FAILED, result!.Status);
        mockClient.Verify(c => c.SubmitRegistrationAsync(It.IsAny<RegistrationRequest>()), Times.Never);
    }

    [Fact]
    public async Task Enroll_RenewOrReissue_MissingPriorCertSn_ReturnsFailure()
    {
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitGetCustomFields()).ReturnsAsync(new List<GetCustomField>());

        var plugin = MakePlugin(mockClient);
        var result = await plugin.Enroll("csr", "CN=test", new Dictionary<string, string[]>(), ProductInfo(),
            RequestFormat.PKCS10, EnrollmentType.RenewOrReissue);

        Assert.Equal((int)EndEntityStatus.FAILED, result!.Status);
        Assert.Contains("no prior certificate serial number", result.StatusMessage);
    }

    [Fact]
    public async Task Enroll_RenewOrReissue_NoRequestIdFoundForSerial_ReturnsFailure()
    {
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitGetCustomFields()).ReturnsAsync(new List<GetCustomField>());
        var certDataReader = new Mock<ICertificateDataReader>();
        certDataReader.Setup(r => r.GetRequestIDBySerialNumber("ABC123")).ReturnsAsync(string.Empty);

        var plugin = MakePlugin(mockClient, certDataReader);
        var productInfo = ProductInfo(parameters: new Dictionary<string, string> { ["PriorCertSN"] = "ABC123" });

        var result = await plugin.Enroll("csr", "CN=test", new Dictionary<string, string[]>(), productInfo,
            RequestFormat.PKCS10, EnrollmentType.RenewOrReissue);

        Assert.Equal((int)EndEntityStatus.FAILED, result!.Status);
        Assert.Contains("no prior request found", result.StatusMessage);
    }

    [Fact]
    public async Task Enroll_RenewOrReissue_NullExpirationDate_FallsBackToGetSingleRecordThenReissues()
    {
        var orderUuid = Guid.NewGuid().ToString();
        var (_, pem) = MakeSelfSignedCert();
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitGetCustomFields()).ReturnsAsync(new List<GetCustomField>());
        mockClient.Setup(c => c.SubmitGetCertificateAsync(orderUuid)).ReturnsAsync(new CertificateResponse
        {
            Certificate = Convert.ToBase64String(Encoding.ASCII.GetBytes(pem)),
            Status = "ACTIVE"
        });
        mockClient.Setup(c => c.SubmitReissueAsync(It.IsAny<ReissueRequest>())).ReturnsAsync(new ReissueResponse
        {
            Result = new Result { CommonName = "reissued.example.com" }
        });

        var certDataReader = new Mock<ICertificateDataReader>();
        certDataReader.Setup(r => r.GetRequestIDBySerialNumber("ABC123")).ReturnsAsync(orderUuid);
        certDataReader.Setup(r => r.GetExpirationDateByRequestId(orderUuid)).Returns((DateTime?)null);

        var plugin = MakePlugin(mockClient, certDataReader);
        var productInfo = ProductInfo(parameters: new Dictionary<string, string>
        {
            ["PriorCertSN"] = "ABC123",
            ["Applicant Last Name"] = "Doe"
        });

        var result = await plugin.Enroll("csr", "CN=test", new Dictionary<string, string[]>(), productInfo,
            RequestFormat.PKCS10, EnrollmentType.RenewOrReissue);

        Assert.Equal((int)EndEntityStatus.EXTERNALVALIDATION, result!.Status);
        mockClient.Verify(c => c.SubmitReissueAsync(It.IsAny<ReissueRequest>()), Times.Once);
    }

    [Fact]
    public async Task Enroll_Renewal_ExpiredCertWithApplicantLastName_Succeeds()
    {
        var uuid = Guid.NewGuid().ToString();
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitGetCustomFields()).ReturnsAsync(new List<GetCustomField>());
        mockClient.Setup(c => c.SubmitRenewalAsync(It.IsAny<RenewalRequest>())).ReturnsAsync(new RenewalResponse
        {
            Result = new Result { CommonName = "renewed.example.com" }
        });

        var certDataReader = new Mock<ICertificateDataReader>();
        certDataReader.Setup(r => r.GetRequestIDBySerialNumber("ABC123")).ReturnsAsync(uuid);
        certDataReader.Setup(r => r.GetExpirationDateByRequestId(uuid)).Returns(DateTime.Now.AddDays(-1));

        var plugin = MakePlugin(mockClient, certDataReader);
        var productInfo = ProductInfo(parameters: new Dictionary<string, string>
        {
            ["PriorCertSN"] = "ABC123",
            ["Applicant Last Name"] = "Doe"
        });

        var result = await plugin.Enroll("csr", "CN=test", new Dictionary<string, string[]>(), productInfo,
            RequestFormat.PKCS10, EnrollmentType.RenewOrReissue);

        Assert.Equal((int)EndEntityStatus.EXTERNALVALIDATION, result!.Status);
    }

    [Fact]
    public async Task Enroll_Renewal_ExpiredCertMissingApplicantLastName_ReturnsFailure()
    {
        var uuid = Guid.NewGuid().ToString();
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitGetCustomFields()).ReturnsAsync(new List<GetCustomField>());

        var certDataReader = new Mock<ICertificateDataReader>();
        certDataReader.Setup(r => r.GetRequestIDBySerialNumber("ABC123")).ReturnsAsync(uuid);
        certDataReader.Setup(r => r.GetExpirationDateByRequestId(uuid)).Returns(DateTime.Now.AddDays(-1));

        var plugin = MakePlugin(mockClient, certDataReader);
        var productInfo = ProductInfo(parameters: new Dictionary<string, string> { ["PriorCertSN"] = "ABC123" });

        var result = await plugin.Enroll("csr", "CN=test", new Dictionary<string, string[]>(), productInfo,
            RequestFormat.PKCS10, EnrollmentType.RenewOrReissue);

        Assert.Equal((int)EndEntityStatus.FAILED, result!.Status);
        Assert.Contains("One click Renew Is Not Available", result.StatusMessage);
    }

    [Fact]
    public async Task Enroll_Reissue_ValidCertWithApplicantLastName_Succeeds()
    {
        var uuid = Guid.NewGuid().ToString();
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitGetCustomFields()).ReturnsAsync(new List<GetCustomField>());
        mockClient.Setup(c => c.SubmitReissueAsync(It.IsAny<ReissueRequest>())).ReturnsAsync(new ReissueResponse
        {
            Result = new Result { CommonName = "reissued.example.com", Status = new Status { Uuid = uuid } }
        });

        var certDataReader = new Mock<ICertificateDataReader>();
        certDataReader.Setup(r => r.GetRequestIDBySerialNumber("ABC123")).ReturnsAsync(uuid);
        certDataReader.Setup(r => r.GetExpirationDateByRequestId(uuid)).Returns(DateTime.Now.AddDays(30));

        var plugin = MakePlugin(mockClient, certDataReader);
        var productInfo = ProductInfo(parameters: new Dictionary<string, string>
        {
            ["PriorCertSN"] = "ABC123",
            ["Applicant Last Name"] = "Doe"
        });

        var result = await plugin.Enroll("csr", "CN=test", new Dictionary<string, string[]>(), productInfo,
            RequestFormat.PKCS10, EnrollmentType.RenewOrReissue);

        Assert.Equal((int)EndEntityStatus.EXTERNALVALIDATION, result!.Status);
        Assert.NotNull(result.EnrollmentContext);
        Assert.Contains(result.EnrollmentContext.Keys, k => k.StartsWith("Flow: Enroll"));
        Assert.Contains(result.EnrollmentContext.Keys, k => k.Contains("SubmitReissue"));
    }

    // ---------------------------------------------------------------------
    // RenewOrReissue - order-expiry-window decision ("200 day" fix)
    //
    // CSC's order is a fixed 1-year paid subscription; a shorter-lived certificate (e.g.
    // ~200 days) issued under it can still have plenty of runway left on the order itself.
    // The decision must be based on the order's expiry (orderDate + 1 year, vs
    // RenewalWindowDays), not the certificate's own expiration date.
    // ---------------------------------------------------------------------

    [Fact]
    public async Task Enroll_RenewOrReissue_OrderNearExpiryWithinWindow_TriggersRenewalEvenThoughCertNotExpired()
    {
        var uuid = Guid.NewGuid().ToString();
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitGetCustomFields()).ReturnsAsync(new List<GetCustomField>());
        // Order was placed 350 days ago -> expires in 15 days, inside the default 30-day window.
        mockClient.Setup(c => c.SubmitGetCertificateAsync(uuid)).ReturnsAsync(new CertificateResponse
        {
            OrderDate = DateTime.UtcNow.AddDays(-350).ToString("o")
        });
        mockClient.Setup(c => c.SubmitRenewalAsync(It.IsAny<RenewalRequest>())).ReturnsAsync(new RenewalResponse
        {
            Result = new Result { CommonName = "renewed.example.com" }
        });

        var certDataReader = new Mock<ICertificateDataReader>();
        certDataReader.Setup(r => r.GetRequestIDBySerialNumber("ABC123")).ReturnsAsync(uuid);
        // The certificate itself still has 60 days left - under the old cert-expiry-only
        // logic this would incorrectly route to Reissue.
        certDataReader.Setup(r => r.GetExpirationDateByRequestId(uuid)).Returns(DateTime.Now.AddDays(60));

        var plugin = MakePlugin(mockClient, certDataReader);
        var productInfo = ProductInfo(parameters: new Dictionary<string, string>
        {
            ["PriorCertSN"] = "ABC123",
            ["Applicant Last Name"] = "Doe"
        });

        var result = await plugin.Enroll("csr", "CN=test", new Dictionary<string, string[]>(), productInfo,
            RequestFormat.PKCS10, EnrollmentType.RenewOrReissue);

        Assert.Equal((int)EndEntityStatus.EXTERNALVALIDATION, result!.Status);
        mockClient.Verify(c => c.SubmitRenewalAsync(It.IsAny<RenewalRequest>()), Times.Once);
        mockClient.Verify(c => c.SubmitReissueAsync(It.IsAny<ReissueRequest>()), Times.Never);
    }

    [Fact]
    public async Task Enroll_RenewOrReissue_OrderFarFromExpiry_TriggersReissueEvenThoughCertExpirationLooksExpired()
    {
        var uuid = Guid.NewGuid().ToString();
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitGetCustomFields()).ReturnsAsync(new List<GetCustomField>());
        // Order was placed 30 days ago -> expires in ~335 days, nowhere near the 30-day window.
        mockClient.Setup(c => c.SubmitGetCertificateAsync(uuid)).ReturnsAsync(new CertificateResponse
        {
            OrderDate = DateTime.UtcNow.AddDays(-30).ToString("o")
        });
        mockClient.Setup(c => c.SubmitReissueAsync(It.IsAny<ReissueRequest>())).ReturnsAsync(new ReissueResponse
        {
            Result = new Result { CommonName = "reissued.example.com" }
        });

        var certDataReader = new Mock<ICertificateDataReader>();
        certDataReader.Setup(r => r.GetRequestIDBySerialNumber("ABC123")).ReturnsAsync(uuid);
        // The locally-recorded cert expiration looks expired - under the old cert-expiry-only
        // logic this would incorrectly route to a paid Renewal.
        certDataReader.Setup(r => r.GetExpirationDateByRequestId(uuid)).Returns(DateTime.Now.AddDays(-5));

        var plugin = MakePlugin(mockClient, certDataReader);
        var productInfo = ProductInfo(parameters: new Dictionary<string, string>
        {
            ["PriorCertSN"] = "ABC123",
            ["Applicant Last Name"] = "Doe"
        });

        var result = await plugin.Enroll("csr", "CN=test", new Dictionary<string, string[]>(), productInfo,
            RequestFormat.PKCS10, EnrollmentType.RenewOrReissue);

        Assert.Equal((int)EndEntityStatus.EXTERNALVALIDATION, result!.Status);
        mockClient.Verify(c => c.SubmitReissueAsync(It.IsAny<ReissueRequest>()), Times.Once);
        mockClient.Verify(c => c.SubmitRenewalAsync(It.IsAny<RenewalRequest>()), Times.Never);
    }

    [Fact]
    public async Task Enroll_RenewOrReissue_LiveCertFetchThrows_FallsBackToCertExpiryCheck()
    {
        var uuid = Guid.NewGuid().ToString();
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitGetCustomFields()).ReturnsAsync(new List<GetCustomField>());
        mockClient.Setup(c => c.SubmitGetCertificateAsync(uuid)).ThrowsAsync(new InvalidOperationException("network error"));
        mockClient.Setup(c => c.SubmitReissueAsync(It.IsAny<ReissueRequest>())).ReturnsAsync(new ReissueResponse
        {
            Result = new Result { CommonName = "reissued.example.com" }
        });

        var certDataReader = new Mock<ICertificateDataReader>();
        certDataReader.Setup(r => r.GetRequestIDBySerialNumber("ABC123")).ReturnsAsync(uuid);
        certDataReader.Setup(r => r.GetExpirationDateByRequestId(uuid)).Returns(DateTime.Now.AddDays(30));

        var plugin = MakePlugin(mockClient, certDataReader);
        var productInfo = ProductInfo(parameters: new Dictionary<string, string>
        {
            ["PriorCertSN"] = "ABC123",
            ["Applicant Last Name"] = "Doe"
        });

        var result = await plugin.Enroll("csr", "CN=test", new Dictionary<string, string[]>(), productInfo,
            RequestFormat.PKCS10, EnrollmentType.RenewOrReissue);

        Assert.Equal((int)EndEntityStatus.EXTERNALVALIDATION, result!.Status);
        mockClient.Verify(c => c.SubmitReissueAsync(It.IsAny<ReissueRequest>()), Times.Once);
    }

    [Fact]
    public async Task Enroll_RenewOrReissue_LiveCertOrderDateUnparsable_FallsBackToCertExpiryCheck()
    {
        var uuid = Guid.NewGuid().ToString();
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitGetCustomFields()).ReturnsAsync(new List<GetCustomField>());
        mockClient.Setup(c => c.SubmitGetCertificateAsync(uuid)).ReturnsAsync(new CertificateResponse { OrderDate = null });
        mockClient.Setup(c => c.SubmitRenewalAsync(It.IsAny<RenewalRequest>())).ReturnsAsync(new RenewalResponse
        {
            Result = new Result { CommonName = "renewed.example.com" }
        });

        var certDataReader = new Mock<ICertificateDataReader>();
        certDataReader.Setup(r => r.GetRequestIDBySerialNumber("ABC123")).ReturnsAsync(uuid);
        certDataReader.Setup(r => r.GetExpirationDateByRequestId(uuid)).Returns(DateTime.Now.AddDays(-1));

        var plugin = MakePlugin(mockClient, certDataReader);
        var productInfo = ProductInfo(parameters: new Dictionary<string, string>
        {
            ["PriorCertSN"] = "ABC123",
            ["Applicant Last Name"] = "Doe"
        });

        var result = await plugin.Enroll("csr", "CN=test", new Dictionary<string, string[]>(), productInfo,
            RequestFormat.PKCS10, EnrollmentType.RenewOrReissue);

        Assert.Equal((int)EndEntityStatus.EXTERNALVALIDATION, result!.Status);
        mockClient.Verify(c => c.SubmitRenewalAsync(It.IsAny<RenewalRequest>()), Times.Once);
    }

    [Fact]
    public async Task Enroll_RenewOrReissue_FlowSummaryIncludesRenewalAnalysisDetail()
    {
        var uuid = Guid.NewGuid().ToString();
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitGetCustomFields()).ReturnsAsync(new List<GetCustomField>());
        mockClient.Setup(c => c.SubmitGetCertificateAsync(uuid)).ReturnsAsync(new CertificateResponse
        {
            OrderDate = DateTime.UtcNow.AddDays(-350).ToString("o")
        });
        mockClient.Setup(c => c.SubmitRenewalAsync(It.IsAny<RenewalRequest>())).ReturnsAsync(new RenewalResponse
        {
            Result = new Result { CommonName = "renewed.example.com" }
        });

        var certDataReader = new Mock<ICertificateDataReader>();
        certDataReader.Setup(r => r.GetRequestIDBySerialNumber("ABC123")).ReturnsAsync(uuid);
        certDataReader.Setup(r => r.GetExpirationDateByRequestId(uuid)).Returns(DateTime.Now.AddDays(60));

        var plugin = MakePlugin(mockClient, certDataReader);
        var productInfo = ProductInfo(parameters: new Dictionary<string, string>
        {
            ["PriorCertSN"] = "ABC123",
            ["Applicant Last Name"] = "Doe"
        });

        var result = await plugin.Enroll("csr", "CN=test", new Dictionary<string, string[]>(), productInfo,
            RequestFormat.PKCS10, EnrollmentType.RenewOrReissue);

        Assert.NotNull(result.EnrollmentContext);
        var decisionEntry = result.EnrollmentContext.Single(e => e.Key.Contains("DetermineRenewOrReissue"));
        Assert.Contains("orderDate=", decisionEntry.Value);
        Assert.Contains("isRenewal=True", decisionEntry.Value);
        Assert.Contains(result.EnrollmentContext.Keys, k => k.Contains("FetchLiveCertForDecision"));
    }

    [Fact]
    public async Task Enroll_New_Success_AttachesFlowSummaryAlongsideDcvContext()
    {
        // On success, StatusMessage isn't surfaced by Command's enrollment UI - only
        // EnrollmentContext is - so the flow summary must ride alongside whatever DCV
        // instructions came back, not replace them.
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitGetCustomFields()).ReturnsAsync(new List<GetCustomField>());
        mockClient.Setup(c => c.SubmitRegistrationAsync(It.IsAny<RegistrationRequest>())).ReturnsAsync(new RegistrationResponse
        {
            Result = new Result
            {
                CommonName = "new.example.com",
                Status = new Status { Uuid = "uuid-new" },
                DcvDetails = new List<DcvDetail> { new DcvDetail { Email = "admin@example.com" } }
            }
        });

        var plugin = MakePlugin(mockClient);
        var result = await plugin.Enroll("csr", "CN=test", new Dictionary<string, string[]>(), ProductInfo(),
            RequestFormat.PKCS10, EnrollmentType.New);

        Assert.Equal((int)EndEntityStatus.EXTERNALVALIDATION, result!.Status);
        Assert.NotNull(result.EnrollmentContext);
        Assert.Equal("admin@example.com", result.EnrollmentContext["admin@example.com"]);
        Assert.Contains(result.EnrollmentContext.Keys, k => k.StartsWith("Flow: Enroll"));
        Assert.Contains(result.EnrollmentContext.Keys, k => k.Contains("SubmitRegistration"));
    }

    [Fact]
    public async Task Enroll_Reissue_LegacyProductName_SendsResolvedCertificateType()
    {
        // Full end-to-end proof that a Certificate Template still configured with a
        // pre-1.2.0 product name reissues correctly against the current extension.
        var uuid = Guid.NewGuid().ToString();
        ReissueRequest capturedRequest = null!;
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitGetCustomFields()).ReturnsAsync(new List<GetCustomField>());
        mockClient.Setup(c => c.SubmitReissueAsync(It.IsAny<ReissueRequest>()))
            .Callback<ReissueRequest>(r => capturedRequest = r)
            .ReturnsAsync(new ReissueResponse
            {
                Result = new Result { CommonName = "reissued.example.com", Status = new Status { Uuid = uuid } }
            });

        var certDataReader = new Mock<ICertificateDataReader>();
        certDataReader.Setup(r => r.GetRequestIDBySerialNumber("ABC123")).ReturnsAsync(uuid);
        certDataReader.Setup(r => r.GetExpirationDateByRequestId(uuid)).Returns(DateTime.Now.AddDays(30));

        var plugin = MakePlugin(mockClient, certDataReader);
        var productInfo = ProductInfo("CSC TrustedSecure UC Certificate", new Dictionary<string, string>
        {
            ["PriorCertSN"] = "ABC123",
            ["Applicant Last Name"] = "Doe"
        });

        var result = await plugin.Enroll("csr", "CN=test", new Dictionary<string, string[]>(), productInfo,
            RequestFormat.PKCS10, EnrollmentType.RenewOrReissue);

        Assert.Equal((int)EndEntityStatus.EXTERNALVALIDATION, result!.Status);
        Assert.Equal("2", capturedRequest.CertificateType);
    }

    [Fact]
    public async Task Enroll_Reissue_MissingApplicantLastName_ReturnsFailure()
    {
        var uuid = Guid.NewGuid().ToString();
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitGetCustomFields()).ReturnsAsync(new List<GetCustomField>());

        var certDataReader = new Mock<ICertificateDataReader>();
        certDataReader.Setup(r => r.GetRequestIDBySerialNumber("ABC123")).ReturnsAsync(uuid);
        certDataReader.Setup(r => r.GetExpirationDateByRequestId(uuid)).Returns(DateTime.Now.AddDays(30));

        var plugin = MakePlugin(mockClient, certDataReader);
        var productInfo = ProductInfo(parameters: new Dictionary<string, string> { ["PriorCertSN"] = "ABC123" });

        var result = await plugin.Enroll("csr", "CN=test", new Dictionary<string, string[]>(), productInfo,
            RequestFormat.PKCS10, EnrollmentType.RenewOrReissue);

        Assert.Equal((int)EndEntityStatus.FAILED, result!.Status);
        Assert.Contains("One click Reissue Is Not Available", result.StatusMessage);
    }

    [Fact]
    public async Task Enroll_Reissue_RequestIdTooShort_ReturnsFailure()
    {
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitGetCustomFields()).ReturnsAsync(new List<GetCustomField>());

        var certDataReader = new Mock<ICertificateDataReader>();
        certDataReader.Setup(r => r.GetRequestIDBySerialNumber("ABC123")).ReturnsAsync("short-id");
        certDataReader.Setup(r => r.GetExpirationDateByRequestId("short-id")).Returns(DateTime.Now.AddDays(30));

        var plugin = MakePlugin(mockClient, certDataReader);
        var productInfo = ProductInfo(parameters: new Dictionary<string, string>
        {
            ["PriorCertSN"] = "ABC123",
            ["Applicant Last Name"] = "Doe"
        });

        var result = await plugin.Enroll("csr", "CN=test", new Dictionary<string, string[]>(), productInfo,
            RequestFormat.PKCS10, EnrollmentType.RenewOrReissue);

        Assert.Equal((int)EndEntityStatus.FAILED, result!.Status);
        Assert.Contains("no prior request found", result.StatusMessage);
    }

    [Fact]
    public async Task Enroll_UnhandledEnrollmentType_ReturnsNull()
    {
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitGetCustomFields()).ReturnsAsync(new List<GetCustomField>());

        var plugin = MakePlugin(mockClient);
        var result = await plugin.Enroll("csr", "CN=test", new Dictionary<string, string[]>(), ProductInfo(),
            RequestFormat.PKCS10, EnrollmentType.Renew);

        Assert.Null(result);
    }

    [Fact]
    public async Task Enroll_ClientThrows_ReturnsFailureWithFlowSummaryAndErrorDetail()
    {
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitGetCustomFields()).ThrowsAsync(new InvalidOperationException("boom"));

        var plugin = MakePlugin(mockClient);
        var result = await plugin.Enroll("csr", "CN=test", new Dictionary<string, string[]>(), ProductInfo(), RequestFormat.PKCS10, EnrollmentType.New);

        Assert.Equal((int)EndEntityStatus.FAILED, result!.Status);
        Assert.Contains("Flow: Enroll", result.StatusMessage);
        Assert.Contains("SubmitGetCustomFields", result.StatusMessage);
        Assert.Contains("boom", result.StatusMessage);
    }

    // ---------------------------------------------------------------------
    // Ping / ValidateCAConnectionInfo / ValidateProductInfo
    // ---------------------------------------------------------------------

    [Fact]
    public async Task Ping_DoesNotThrow()
    {
        var plugin = MakePlugin();
        await plugin.Ping();
    }

    [Fact]
    public async Task Ping_Disabled_DoesNotThrow()
    {
        var data = ValidConnectionData();
        data[Constants.Enabled] = "false";
        var plugin = MakePlugin(connectionData: data);
        await plugin.Ping();
    }

    [Fact]
    public async Task ValidateCAConnectionInfo_NullConnectionInfo_DoesNotThrow()
    {
        var plugin = MakePlugin();
        await plugin.ValidateCAConnectionInfo(null!);
    }

    [Fact]
    public async Task ValidateCAConnectionInfo_WithConnectionInfo_DoesNotThrow()
    {
        var plugin = MakePlugin();
        await plugin.ValidateCAConnectionInfo(new Dictionary<string, object> { ["Key"] = "Value" });
    }

    [Fact]
    public async Task ValidateCAConnectionInfo_ExplicitlyDisabled_DoesNotThrow()
    {
        var plugin = MakePlugin();
        await plugin.ValidateCAConnectionInfo(new Dictionary<string, object> { [Constants.Enabled] = "false" });
    }

    [Fact]
    public async Task ValidateProductInfo_KnownProduct_DoesNotThrow()
    {
        var plugin = MakePlugin();
        await plugin.ValidateProductInfo(ProductInfo("CSC TrustedSecure OV"), new Dictionary<string, object>());
    }

    [Fact]
    public async Task ValidateProductInfo_KnownProductDifferentCase_DoesNotThrow()
    {
        var plugin = MakePlugin();
        await plugin.ValidateProductInfo(ProductInfo("csc trustedsecure ov"), new Dictionary<string, object>());
    }

    [Fact]
    public async Task ValidateProductInfo_UnknownProduct_Throws()
    {
        var plugin = MakePlugin();
        await Assert.ThrowsAsync<ArgumentException>(() =>
            plugin.ValidateProductInfo(ProductInfo("Not A Real Product"), new Dictionary<string, object>()));
    }

    [Fact]
    public async Task ValidateProductInfo_LegacyProductName_DoesNotThrow()
    {
        var plugin = MakePlugin();
        await plugin.ValidateProductInfo(ProductInfo("CSC TrustedSecure UC Certificate"), new Dictionary<string, object>());
    }

    [Fact]
    public async Task ValidateProductInfo_DisabledConnector_SkipsValidationEvenForUnknownProduct()
    {
        var plugin = MakePlugin();
        var connectionInfo = new Dictionary<string, object> { [Constants.Enabled] = "false" };

        // Should not throw even though the product is unknown - Enabled=false short-circuits
        // validation entirely (pre-configuration workflow).
        await plugin.ValidateProductInfo(ProductInfo("Not A Real Product"), connectionInfo);
    }

    [Fact]
    public async Task ValidateProductInfo_NullConnectionInfo_TreatsAsEnabled()
    {
        var plugin = MakePlugin();
        await Assert.ThrowsAsync<ArgumentException>(() =>
            plugin.ValidateProductInfo(ProductInfo("Not A Real Product"), null!));
    }

    // ---------------------------------------------------------------------
    // GetCAConnectorAnnotations / GetTemplateParameterAnnotations / GetProductIds
    // ---------------------------------------------------------------------

    [Fact]
    public void GetCAConnectorAnnotations_ContainsExpectedKeys()
    {
        var plugin = MakePlugin();
        var annotations = plugin.GetCAConnectorAnnotations();

        Assert.Equal(7, annotations.Count);
        Assert.Contains(Constants.Enabled, annotations.Keys);
        Assert.Contains(Constants.CscGlobalUrl, annotations.Keys);
        Assert.Contains(Constants.CscGlobalApiKey, annotations.Keys);
        Assert.Contains(Constants.BearerToken, annotations.Keys);
        Assert.Contains(Constants.DefaultPageSize, annotations.Keys);
        Assert.Contains(Constants.SyncFilterDays, annotations.Keys);
        Assert.Contains(Constants.RenewalWindowDays, annotations.Keys);
        Assert.True(annotations[Constants.CscGlobalApiKey].Hidden);
    }

    [Fact]
    public void GetTemplateParameterAnnotations_ContainsExpectedKeys()
    {
        var plugin = MakePlugin();
        var annotations = plugin.GetTemplateParameterAnnotations();

        Assert.Equal(12, annotations.Count);
        Assert.Contains(EnrollmentConfigConstants.Term, annotations.Keys);
        Assert.Contains(EnrollmentConfigConstants.AdditionalSansCommaSeparatedDcvEmails, annotations.Keys);
    }

    [Fact]
    public void GetProductIds_ReturnsFullList()
    {
        var plugin = MakePlugin();
        var ids = plugin.GetProductIds();

        Assert.Equal(10, ids.Count);
        Assert.Contains("CSC TrustedSecure OV", ids);
        Assert.Contains("CSC TrustedSecure DV Wildcard, Multiple Names", ids);
    }

    // ---------------------------------------------------------------------
    // GetEndEntityCertificate
    // ---------------------------------------------------------------------

    [Fact]
    public void GetEndEntityCertificate_EmptyInput_ReturnsEmptyString()
    {
        var plugin = MakePlugin();
        Assert.Equal(string.Empty, plugin.GetEndEntityCertificate(""));
        Assert.Equal(string.Empty, plugin.GetEndEntityCertificate("   "));
        Assert.Equal(string.Empty, plugin.GetEndEntityCertificate(null!));
    }

    [Fact]
    public void GetEndEntityCertificate_NoValidPemBlocks_ReturnsEmptyString()
    {
        var plugin = MakePlugin();
        Assert.Equal(string.Empty, plugin.GetEndEntityCertificate("this is not a certificate"));
    }

    [Fact]
    public void GetEndEntityCertificate_SingleLeafCert_ReturnsBase64Der()
    {
        var (cert, pem) = MakeSelfSignedCert();
        var plugin = MakePlugin();

        var result = plugin.GetEndEntityCertificate(pem);

        Assert.Equal(Convert.ToBase64String(cert.RawData), result);
    }

    [Fact]
    public void GetEndEntityCertificate_MalformedBase64Block_SkipsBlockReturnsEmpty()
    {
        var pem = "-----BEGIN CERTIFICATE-----\nNOT-VALID-BASE64!!!\n-----END CERTIFICATE-----\n";
        var plugin = MakePlugin();

        Assert.Equal(string.Empty, plugin.GetEndEntityCertificate(pem));
    }

    [Fact]
    public void GetEndEntityCertificate_EmptyBlockContent_Skipped()
    {
        var pem = "-----BEGIN CERTIFICATE-----\n\n-----END CERTIFICATE-----\n";
        var plugin = MakePlugin();

        Assert.Equal(string.Empty, plugin.GetEndEntityCertificate(pem));
    }

    [Fact]
    public void GetEndEntityCertificate_ValidBase64ButNotACertificate_SkipsBlockReturnsEmpty()
    {
        var notACert = Convert.ToBase64String(Encoding.UTF8.GetBytes("this is not a certificate, just text"));
        var pem = $"-----BEGIN CERTIFICATE-----\n{notACert}\n-----END CERTIFICATE-----\n";
        var plugin = MakePlugin();

        Assert.Equal(string.Empty, plugin.GetEndEntityCertificate(pem));
    }

    [Fact]
    public void GetEndEntityCertificate_TwoIndependentLeafCerts_ReturnsOneOfThem()
    {
        var (certA, pemA) = MakeSelfSignedCert("a.example.com");
        var (certB, pemB) = MakeSelfSignedCert("b.example.com");
        var plugin = MakePlugin();

        var result = plugin.GetEndEntityCertificate(pemA + pemB);

        Assert.True(result == Convert.ToBase64String(certA.RawData) || result == Convert.ToBase64String(certB.RawData));
    }

    [Fact]
    public void GetEndEntityCertificate_LeafAndCaChain_ReturnsLeafOnly()
    {
        using var rsaCa = RSA.Create(2048);
        var caReq = new CertificateRequest("CN=Test CA", rsaCa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        caReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        var caCert = caReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(365));

        using var rsaLeaf = RSA.Create(2048);
        var leafReq = new CertificateRequest("CN=leaf.example.com", rsaLeaf, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        leafReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        var leafCert = leafReq.Create(caCert, DateTimeOffset.UtcNow.AddDays(-1), caCert.NotAfter.AddDays(-1),
            Guid.NewGuid().ToByteArray());

        string ToPemBlock(X509Certificate2 c) => "-----BEGIN CERTIFICATE-----\n" +
            Convert.ToBase64String(c.RawData, Base64FormattingOptions.InsertLineBreaks) +
            "\n-----END CERTIFICATE-----\n";

        var chainPem = ToPemBlock(caCert) + ToPemBlock(leafCert);
        var plugin = MakePlugin();

        var result = plugin.GetEndEntityCertificate(chainPem);

        Assert.Equal(Convert.ToBase64String(leafCert.RawData), result);
    }
}
