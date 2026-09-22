// Copyright 2021 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.

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
    private static EnrollmentProductInfo ProductInfo(string productId = "CSC TrustedSecure DV",
        Dictionary<string, string>? parameters = null) => new EnrollmentProductInfo
    {
        ProductID = productId,
        ProductParameters = parameters ?? new Dictionary<string, string>()
    };

    private static Mock<IAnyCAPluginConfigProvider> ConfigProviderMock(Dictionary<string, object>? overrides = null)
    {
        var data = new Dictionary<string, object>
        {
            [Constants.CscGlobalApiKey] = "api-key",
            [Constants.CscGlobalUrl] = "https://example.invalid/",
            [Constants.BearerToken] = "bearer-token"
        };
        if (overrides != null)
            foreach (var kv in overrides)
                data[kv.Key] = kv.Value;

        var mock = new Mock<IAnyCAPluginConfigProvider>();
        mock.Setup(c => c.CAConnectionData).Returns(data);
        return mock;
    }

    private static CSCGlobalCAPlugin MakePlugin(Mock<ICscGlobalClient>? client = null,
        Mock<ICertificateDataReader>? certDataReader = null, Dictionary<string, object>? configOverrides = null,
        IDomainValidatorFactory? validatorFactory = null)
    {
        var plugin = validatorFactory != null ? new CSCGlobalCAPlugin(validatorFactory) : new CSCGlobalCAPlugin();
        plugin.Initialize(ConfigProviderMock(configOverrides).Object,
            (certDataReader ?? new Mock<ICertificateDataReader>()).Object);
        plugin.CscGlobalClient = (client ?? new Mock<ICscGlobalClient>()).Object;
        return plugin;
    }

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
    public void Initialize_NullCertificateDataReader_Throws()
    {
        var plugin = new CSCGlobalCAPlugin();
        Assert.Throws<ArgumentNullException>(() => plugin.Initialize(ConfigProviderMock().Object, null!));
    }

    [Fact]
    public void Initialize_NullCAConnectionData_Throws()
    {
        var plugin = new CSCGlobalCAPlugin();
        var mock = new Mock<IAnyCAPluginConfigProvider>();
        mock.Setup(c => c.CAConnectionData).Returns((Dictionary<string, object>)null!);
        Assert.Throws<InvalidOperationException>(() => plugin.Initialize(mock.Object, Mock.Of<ICertificateDataReader>()));
    }

    [Fact]
    public void Initialize_EnabledDefault_ConstructsRealClient()
    {
        var plugin = new CSCGlobalCAPlugin();
        plugin.Initialize(ConfigProviderMock().Object, Mock.Of<ICertificateDataReader>());
        Assert.True(plugin.Enabled);
        Assert.NotNull(plugin.CscGlobalClient);
    }

    [Fact]
    public void Initialize_ExplicitlyDisabled_SkipsClientCreation()
    {
        var plugin = new CSCGlobalCAPlugin();
        plugin.Initialize(ConfigProviderMock(new Dictionary<string, object> { [Constants.Enabled] = "false" }).Object,
            Mock.Of<ICertificateDataReader>());
        Assert.False(plugin.Enabled);
        Assert.Null(plugin.CscGlobalClient);
    }

    [Fact]
    public void Initialize_UnparsableEnabled_DefaultsToTrue()
    {
        var plugin = new CSCGlobalCAPlugin();
        plugin.Initialize(ConfigProviderMock(new Dictionary<string, object> { [Constants.Enabled] = "not-a-bool" }).Object,
            Mock.Of<ICertificateDataReader>());
        Assert.True(plugin.Enabled);
    }

    [Fact]
    public void Initialize_EnabledButMissingApiKey_Throws()
    {
        var plugin = new CSCGlobalCAPlugin();
        var mock = new Mock<IAnyCAPluginConfigProvider>();
        mock.Setup(c => c.CAConnectionData).Returns(new Dictionary<string, object>());
        Assert.Throws<InvalidOperationException>(() => plugin.Initialize(mock.Object, Mock.Of<ICertificateDataReader>()));
    }

    [Theory]
    [InlineData("10", 10)]
    [InlineData("not-a-number", 0)]
    public void Initialize_SyncFilterDays_ParsesOrDefaults(string raw, int expected)
    {
        var plugin = new CSCGlobalCAPlugin();
        plugin.Initialize(ConfigProviderMock(new Dictionary<string, object> { [Constants.SyncFilterDays] = raw }).Object,
            Mock.Of<ICertificateDataReader>());
        Assert.Equal(expected, plugin.SyncFilterDays);
    }

    [Theory]
    [InlineData("45", 45)]
    [InlineData("not-a-number", 30)]
    [InlineData("-5", 30)]
    public void Initialize_RenewalWindowDays_ParsesOrDefaults(string raw, int expected)
    {
        var plugin = new CSCGlobalCAPlugin();
        plugin.Initialize(ConfigProviderMock(new Dictionary<string, object> { [Constants.RenewalWindowDays] = raw }).Object,
            Mock.Of<ICertificateDataReader>());
        Assert.Equal(expected, plugin.RenewalWindowDays);
    }

    [Fact]
    public void Initialize_RenewalWindowDaysNotConfigured_DefaultsTo30()
    {
        var plugin = new CSCGlobalCAPlugin();
        plugin.Initialize(ConfigProviderMock().Object, Mock.Of<ICertificateDataReader>());
        Assert.Equal(30, plugin.RenewalWindowDays);
    }

    [Theory]
    [InlineData("5", 5)]
    [InlineData("not-a-number", 0)]
    [InlineData("-1", 0)]
    public void Initialize_DcvPollTimeoutSeconds_ParsesOrDefaults(string raw, int expected)
    {
        var plugin = new CSCGlobalCAPlugin();
        plugin.Initialize(ConfigProviderMock(new Dictionary<string, object> { [Constants.DcvPollTimeoutSeconds] = raw }).Object,
            Mock.Of<ICertificateDataReader>());
        Assert.Equal(expected, plugin.DcvPollTimeoutSeconds);
    }

    [Fact]
    public void Initialize_EnabledKeyPresentButNullValue_DefaultsToTrue()
    {
        var plugin = new CSCGlobalCAPlugin();
        plugin.Initialize(ConfigProviderMock(new Dictionary<string, object> { [Constants.Enabled] = null! }).Object,
            Mock.Of<ICertificateDataReader>());
        Assert.True(plugin.Enabled);
    }

    [Fact]
    public void Initialize_SyncFilterDaysKeyPresentButNullValue_DefaultsToZero()
    {
        var plugin = new CSCGlobalCAPlugin();
        plugin.Initialize(ConfigProviderMock(new Dictionary<string, object> { [Constants.SyncFilterDays] = null! }).Object,
            Mock.Of<ICertificateDataReader>());
        Assert.Equal(0, plugin.SyncFilterDays);
    }

    [Fact]
    public void Initialize_RenewalWindowDaysKeyPresentButNullValue_DefaultsTo30()
    {
        var plugin = new CSCGlobalCAPlugin();
        plugin.Initialize(ConfigProviderMock(new Dictionary<string, object> { [Constants.RenewalWindowDays] = null! }).Object,
            Mock.Of<ICertificateDataReader>());
        Assert.Equal(30, plugin.RenewalWindowDays);
    }

    [Fact]
    public void Initialize_DcvPollTimeoutSecondsKeyPresentButNullValue_DefaultsToZero()
    {
        var plugin = new CSCGlobalCAPlugin();
        plugin.Initialize(ConfigProviderMock(new Dictionary<string, object> { [Constants.DcvPollTimeoutSeconds] = null! }).Object,
            Mock.Of<ICertificateDataReader>());
        Assert.Equal(0, plugin.DcvPollTimeoutSeconds);
    }

    [Fact]
    public void Initialize_WithValidatorFactory_DoesNotThrow()
    {
        var plugin = new CSCGlobalCAPlugin(Mock.Of<IDomainValidatorFactory>());
        plugin.Initialize(ConfigProviderMock().Object, Mock.Of<ICertificateDataReader>());
        Assert.True(plugin.Enabled);
    }

    // ---------------------------------------------------------------------
    // GetSingleRecord
    // ---------------------------------------------------------------------

    [Fact]
    public async Task GetSingleRecord_NullId_Throws()
    {
        var plugin = MakePlugin();
        await Assert.ThrowsAsync<ArgumentNullException>(() => plugin.GetSingleRecord(null!));
    }

    [Fact]
    public async Task GetSingleRecord_TooShortId_Throws()
    {
        var plugin = MakePlugin();
        await Assert.ThrowsAsync<ArgumentException>(() => plugin.GetSingleRecord("short-id"));
    }

    [Fact]
    public async Task GetSingleRecord_NullClientResponse_ReturnsFailedMappedStatus()
    {
        var uuid = Guid.NewGuid().ToString();
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitGetCertificateAsync(uuid)).ReturnsAsync((CertificateResponse)null!);

        var plugin = MakePlugin(mockClient);
        var result = await plugin.GetSingleRecord(uuid);

        Assert.Equal(uuid, result.CARequestID);
        Assert.Equal((int)EndEntityStatus.FAILED, result.Status);
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
    public async Task GetSingleRecord_InvalidBase64Certificate_ReturnsEmptyCertificate()
    {
        var uuid = Guid.NewGuid().ToString();
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitGetCertificateAsync(uuid)).ReturnsAsync(new CertificateResponse
        {
            Certificate = Convert.ToBase64String(Encoding.ASCII.GetBytes("not valid pem at all")),
            Status = "ACTIVE"
        });

        var plugin = MakePlugin(mockClient);
        var result = await plugin.GetSingleRecord(uuid);

        Assert.Equal(string.Empty, result.Certificate);
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
    // Synchronize / SyncCertificates
    // ---------------------------------------------------------------------

    [Fact]
    public async Task Synchronize_NullBuffer_Throws()
    {
        var plugin = MakePlugin();
        await Assert.ThrowsAsync<ArgumentNullException>(() => plugin.Synchronize(null!, null, true, CancellationToken.None));
    }

    [Fact]
    public async Task Synchronize_Disabled_CompletesImmediatelyWithoutCallingClient()
    {
        var mockClient = new Mock<ICscGlobalClient>();
        var plugin = MakePlugin(mockClient, configOverrides: new Dictionary<string, object> { [Constants.Enabled] = "false" });
        var buffer = new System.Collections.Concurrent.BlockingCollection<AnyCAPluginCertificate>();

        await plugin.Synchronize(buffer, null, true, CancellationToken.None);

        Assert.True(buffer.IsAddingCompleted);
        mockClient.Verify(c => c.SubmitCertificateListRequestAsync(It.IsAny<string>()), Times.Never);
    }

    [Fact]
    public async Task Synchronize_FullSync_QueuesGeneratedAndRevokedOnly()
    {
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitCertificateListRequestAsync(null)).ReturnsAsync(new CertificateListResponse
        {
            Results = new List<CertificateResponse>
            {
                new CertificateResponse { Uuid = "u1", Status = "ACTIVE", Certificate = null, CertificateType = "4" },
                new CertificateResponse { Uuid = "u2", Status = "Pending", Certificate = null, CertificateType = "4" },
                null!
            }
        });

        var plugin = MakePlugin(mockClient);
        var buffer = new System.Collections.Concurrent.BlockingCollection<AnyCAPluginCertificate>();

        await plugin.Synchronize(buffer, null, true, CancellationToken.None);

        Assert.True(buffer.IsAddingCompleted);
        // Neither item has actual certificate bytes, so both get skipped after status-eligibility
        // check; this exercises the eligible-but-empty-content and null-item paths.
        Assert.Empty(buffer);
    }

    [Fact]
    public async Task Synchronize_IncrementalSync_UsesFilterDate()
    {
        var mockClient = new Mock<ICscGlobalClient>();
        string? capturedFilter = "not-called";
        mockClient.Setup(c => c.SubmitCertificateListRequestAsync(It.IsAny<string>()))
            .Callback<string>(f => capturedFilter = f)
            .ReturnsAsync(new CertificateListResponse { Results = new List<CertificateResponse>() });

        var plugin = MakePlugin(mockClient, configOverrides: new Dictionary<string, object> { [Constants.SyncFilterDays] = "10" });
        var buffer = new System.Collections.Concurrent.BlockingCollection<AnyCAPluginCertificate>();

        await plugin.Synchronize(buffer, null, false, CancellationToken.None);

        Assert.NotNull(capturedFilter);
        Assert.NotEqual("not-called", capturedFilter);
    }

    [Fact]
    public async Task Synchronize_IncrementalSync_SyncFilterDaysNotConfigured_DefaultsToFiveDays()
    {
        var mockClient = new Mock<ICscGlobalClient>();
        string? capturedFilter = "not-called";
        mockClient.Setup(c => c.SubmitCertificateListRequestAsync(It.IsAny<string>()))
            .Callback<string>(f => capturedFilter = f)
            .ReturnsAsync(new CertificateListResponse { Results = new List<CertificateResponse>() });

        var plugin = MakePlugin(mockClient);
        var buffer = new System.Collections.Concurrent.BlockingCollection<AnyCAPluginCertificate>();

        await plugin.Synchronize(buffer, null, false, CancellationToken.None);

        var expected = DateTime.Today.Subtract(TimeSpan.FromDays(5)).ToString("yyyy/MM/dd");
        Assert.Equal(expected, capturedFilter);
    }

    [Fact]
    public async Task Synchronize_NullResultsFromClient_CompletesWithoutError()
    {
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitCertificateListRequestAsync(It.IsAny<string>()))
            .ReturnsAsync((CertificateListResponse)null!);

        var plugin = MakePlugin(mockClient);
        var buffer = new System.Collections.Concurrent.BlockingCollection<AnyCAPluginCertificate>();

        await plugin.Synchronize(buffer, null, true, CancellationToken.None);

        Assert.True(buffer.IsAddingCompleted);
    }

    [Fact]
    public async Task Synchronize_NullResultsCollection_CompletesWithoutError()
    {
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitCertificateListRequestAsync(It.IsAny<string>()))
            .ReturnsAsync(new CertificateListResponse { Results = null });

        var plugin = MakePlugin(mockClient);
        var buffer = new System.Collections.Concurrent.BlockingCollection<AnyCAPluginCertificate>();

        await plugin.Synchronize(buffer, null, true, CancellationToken.None);

        Assert.True(buffer.IsAddingCompleted);
    }

    [Fact]
    public async Task Synchronize_ValidCertificateContent_AddsToBufferWithMappedProductId()
    {
        var (_, pem) = MakeSelfSignedCert();
        var apiBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(pem));

        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitCertificateListRequestAsync(It.IsAny<string>())).ReturnsAsync(new CertificateListResponse
        {
            Results = new List<CertificateResponse>
            {
                new CertificateResponse { Uuid = "u1", Status = "ACTIVE", Certificate = apiBase64, CertificateType = "CSC TrustedSecure DV" }
            }
        });

        var plugin = MakePlugin(mockClient);
        var buffer = new System.Collections.Concurrent.BlockingCollection<AnyCAPluginCertificate>();

        await plugin.Synchronize(buffer, null, true, CancellationToken.None);

        var items = buffer.ToArray();
        Assert.Single(items);
        Assert.Equal("u1", items[0].CARequestID);
        // CSC's list/sync API returns the certificate's current product name directly, so the
        // synced ProductID must match it verbatim (and therefore match the canonical Certificate
        // Profile name configured in Command) rather than going through a name-remapping table.
        Assert.Equal("CSC TrustedSecure DV", items[0].ProductID);
    }

    [Fact]
    public async Task Synchronize_MalformedBase64Certificate_SkipsItem()
    {
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitCertificateListRequestAsync(It.IsAny<string>())).ReturnsAsync(new CertificateListResponse
        {
            Results = new List<CertificateResponse>
            {
                new CertificateResponse { Uuid = "u1", Status = "ACTIVE", Certificate = "not valid base64 at all!!", CertificateType = "4" }
            }
        });

        var plugin = MakePlugin(mockClient);
        var buffer = new System.Collections.Concurrent.BlockingCollection<AnyCAPluginCertificate>();

        await plugin.Synchronize(buffer, null, true, CancellationToken.None);

        Assert.Empty(buffer);
    }

    [Fact]
    public async Task Synchronize_ValidBase64ButNoPemCertificates_SkipsItem()
    {
        var apiBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes("this is not a PEM certificate"));
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitCertificateListRequestAsync(It.IsAny<string>())).ReturnsAsync(new CertificateListResponse
        {
            Results = new List<CertificateResponse>
            {
                new CertificateResponse { Uuid = "u1", Status = "ACTIVE", Certificate = apiBase64, CertificateType = "4" }
            }
        });

        var plugin = MakePlugin(mockClient);
        var buffer = new System.Collections.Concurrent.BlockingCollection<AnyCAPluginCertificate>();

        await plugin.Synchronize(buffer, null, true, CancellationToken.None);

        Assert.Empty(buffer);
    }

    [Fact]
    public async Task Synchronize_RevokedStatus_AlsoQualifiesForSync()
    {
        var (_, pem) = MakeSelfSignedCert();
        var apiBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(pem));
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitCertificateListRequestAsync(It.IsAny<string>())).ReturnsAsync(new CertificateListResponse
        {
            Results = new List<CertificateResponse>
            {
                new CertificateResponse { Uuid = "u1", Status = "REVOKED", Certificate = apiBase64, CertificateType = "4" }
            }
        });

        var plugin = MakePlugin(mockClient);
        var buffer = new System.Collections.Concurrent.BlockingCollection<AnyCAPluginCertificate>();

        await plugin.Synchronize(buffer, null, true, CancellationToken.None);

        Assert.Single(buffer);
    }

    [Fact]
    public async Task Synchronize_ClientThrows_PropagatesAndCompletesBuffer()
    {
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitCertificateListRequestAsync(It.IsAny<string>())).ThrowsAsync(new InvalidOperationException("boom"));

        var plugin = MakePlugin(mockClient);
        var buffer = new System.Collections.Concurrent.BlockingCollection<AnyCAPluginCertificate>();

        await Assert.ThrowsAsync<InvalidOperationException>(() => plugin.Synchronize(buffer, null, true, CancellationToken.None));
        Assert.True(buffer.IsAddingCompleted);
    }

    [Fact]
    public async Task Synchronize_Cancelled_ThrowsOperationCanceledAndCompletesBuffer()
    {
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitCertificateListRequestAsync(It.IsAny<string>())).ReturnsAsync(new CertificateListResponse
        {
            Results = new List<CertificateResponse> { new CertificateResponse { Uuid = "u1", Status = "ACTIVE" } }
        });

        var plugin = MakePlugin(mockClient);
        var buffer = new System.Collections.Concurrent.BlockingCollection<AnyCAPluginCertificate>();
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAsync<OperationCanceledException>(() => plugin.Synchronize(buffer, null, true, cts.Token));
        Assert.True(buffer.IsAddingCompleted);
    }

    // ---------------------------------------------------------------------
    // Revoke
    // ---------------------------------------------------------------------

    [Fact]
    public async Task Revoke_Disabled_Throws()
    {
        var plugin = MakePlugin(configOverrides: new Dictionary<string, object> { [Constants.Enabled] = "false" });
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            plugin.Revoke(new string('a', 36), "serial", 0));
    }

    [Fact]
    public async Task Revoke_TooShortId_Throws()
    {
        var plugin = MakePlugin();
        await Assert.ThrowsAsync<ArgumentException>(() => plugin.Revoke("short", "serial", 0));
    }

    [Fact]
    public async Task Revoke_NullId_Throws()
    {
        var plugin = MakePlugin();
        await Assert.ThrowsAsync<ArgumentNullException>(() => plugin.Revoke(null!, "serial", 0));
    }

    [Fact]
    public async Task Revoke_NullResponse_Throws()
    {
        var uuid = Guid.NewGuid().ToString();
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitRevokeCertificateAsync(uuid)).ReturnsAsync((RevokeResponse)null!);

        var plugin = MakePlugin(mockClient);
        // Wrapped by the generic catch (Exception e) at the bottom of Revoke, since
        // InvalidOperationException isn't AggregateException or HttpRequestException.
        var ex = await Assert.ThrowsAsync<Exception>(() => plugin.Revoke(uuid, "serial", 0));
        Assert.IsType<InvalidOperationException>(ex.InnerException);
    }

    [Fact]
    public async Task Revoke_Success_ReturnsRevoked()
    {
        var uuid = Guid.NewGuid().ToString();
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitRevokeCertificateAsync(uuid)).ReturnsAsync(new RevokeResponse
        {
            RevokeSuccess = new RevokeSuccessResponse { Status = "REVOKED" }
        });

        var plugin = MakePlugin(mockClient);
        var result = await plugin.Revoke(uuid, "serial", 0);

        Assert.Equal((int)EndEntityStatus.REVOKED, result);
    }

    [Fact]
    public async Task Revoke_ErrorWithDescription_ThrowsHttpRequestException()
    {
        var uuid = Guid.NewGuid().ToString();
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitRevokeCertificateAsync(uuid)).ReturnsAsync(new RevokeResponse
        {
            RegistrationError = new RegistrationError { Description = "already revoked" }
        });

        var plugin = MakePlugin(mockClient);
        await Assert.ThrowsAsync<HttpRequestException>(() => plugin.Revoke(uuid, "serial", 0));
    }

    [Fact]
    public async Task Revoke_ClientThrows_WrapsException()
    {
        var uuid = Guid.NewGuid().ToString();
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitRevokeCertificateAsync(uuid)).ThrowsAsync(new InvalidOperationException("boom"));

        var plugin = MakePlugin(mockClient);
        await Assert.ThrowsAsync<Exception>(() => plugin.Revoke(uuid, "serial", 0));
    }

    // ---------------------------------------------------------------------
    // Ping / ValidateCAConnectionInfo
    // ---------------------------------------------------------------------

    [Fact]
    public async Task Ping_Enabled_DoesNotThrow()
    {
        var plugin = MakePlugin();
        await plugin.Ping();
    }

    [Fact]
    public async Task Ping_Disabled_DoesNotThrow()
    {
        var plugin = MakePlugin(configOverrides: new Dictionary<string, object> { [Constants.Enabled] = "false" });
        await plugin.Ping();
    }

    [Fact]
    public async Task ValidateCAConnectionInfo_NullConnectionInfo_Throws()
    {
        var plugin = MakePlugin();
        await Assert.ThrowsAsync<ArgumentNullException>(() => plugin.ValidateCAConnectionInfo(null!));
    }

    [Fact]
    public async Task ValidateCAConnectionInfo_Enabled_DoesNotThrow()
    {
        var plugin = MakePlugin();
        await plugin.ValidateCAConnectionInfo(new Dictionary<string, object>());
    }

    [Fact]
    public async Task ValidateCAConnectionInfo_ExplicitlyDisabled_DoesNotThrow()
    {
        var plugin = MakePlugin();
        await plugin.ValidateCAConnectionInfo(new Dictionary<string, object> { [Constants.Enabled] = "false" });
    }

    [Fact]
    public async Task ValidateCAConnectionInfo_UnparsableEnabledValue_TreatsAsEnabled()
    {
        var plugin = MakePlugin();
        await plugin.ValidateCAConnectionInfo(new Dictionary<string, object> { [Constants.Enabled] = "not-a-bool" });
    }

    // ---------------------------------------------------------------------
    // ValidateProductInfo
    // ---------------------------------------------------------------------

    [Theory]
    [InlineData("CSC TrustedSecure DV")]
    [InlineData("CSC TrustedSecure DV Wildcard, Multiple Names")]
    public async Task ValidateProductInfo_CanonicalProductName_DoesNotThrow(string productId)
    {
        var plugin = MakePlugin();
        await plugin.ValidateProductInfo(ProductInfo(productId), new Dictionary<string, object>());
    }

    [Theory]
    [InlineData("CSC TrustedSecure UC Certificate")]
    [InlineData("CSC TrustedSecure Domain Validated SSL")]
    [InlineData("CSC Trusted Secure Domain Validated Wildcard SSL")]
    public async Task ValidateProductInfo_LegacyProductName_DoesNotThrow(string legacyProductId)
    {
        var plugin = MakePlugin();
        await plugin.ValidateProductInfo(ProductInfo(legacyProductId), new Dictionary<string, object>());
    }

    [Fact]
    public async Task ValidateProductInfo_NullProductInfo_Throws()
    {
        var plugin = MakePlugin();
        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            plugin.ValidateProductInfo(null!, new Dictionary<string, object>()));
    }

    [Fact]
    public async Task ValidateProductInfo_EmptyProductId_Throws()
    {
        var plugin = MakePlugin();
        await Assert.ThrowsAsync<ArgumentException>(() =>
            plugin.ValidateProductInfo(ProductInfo(""), new Dictionary<string, object>()));
    }

    [Fact]
    public async Task ValidateProductInfo_UnknownProduct_Throws()
    {
        var plugin = MakePlugin();
        await Assert.ThrowsAsync<ArgumentException>(() =>
            plugin.ValidateProductInfo(ProductInfo("Not A Real Product"), new Dictionary<string, object>()));
    }

    [Fact]
    public async Task ValidateProductInfo_NullConnectionInfo_TreatsAsEnabled()
    {
        var plugin = MakePlugin();
        await Assert.ThrowsAsync<ArgumentException>(() =>
            plugin.ValidateProductInfo(ProductInfo("Not A Real Product"), null!));
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
    public async Task ValidateProductInfo_UnparsableEnabledValue_TreatsAsEnabled()
    {
        var plugin = MakePlugin();
        var connectionInfo = new Dictionary<string, object> { [Constants.Enabled] = "not-a-bool" };
        await Assert.ThrowsAsync<ArgumentException>(() =>
            plugin.ValidateProductInfo(ProductInfo("Not A Real Product"), connectionInfo));
    }

    // ---------------------------------------------------------------------
    // Annotations / product IDs
    // ---------------------------------------------------------------------

    [Fact]
    public void GetCAConnectorAnnotations_ReturnsExpectedKeys()
    {
        var plugin = MakePlugin();
        var annotations = plugin.GetCAConnectorAnnotations();
        Assert.Contains(Constants.Enabled, annotations.Keys);
        Assert.Contains(Constants.CscGlobalUrl, annotations.Keys);
        Assert.Contains(Constants.DcvPollTimeoutSeconds, annotations.Keys);
    }

    [Fact]
    public void GetTemplateParameterAnnotations_ReturnsExpectedKeys()
    {
        var plugin = MakePlugin();
        var annotations = plugin.GetTemplateParameterAnnotations();
        Assert.Contains(EnrollmentConfigConstants.CnDcvEmail, annotations.Keys);
        Assert.Contains(EnrollmentConfigConstants.AdditionalSansCommaSeparatedDcvEmails, annotations.Keys);
    }

    [Fact]
    public void GetProductIds_ReturnsCanonicalTenProducts()
    {
        var plugin = MakePlugin();
        Assert.Equal(10, plugin.GetProductIds().Count);
    }

    // ---------------------------------------------------------------------
    // Enroll - validation and New enrollment
    // ---------------------------------------------------------------------

    [Fact]
    public async Task Enroll_Disabled_ReturnsFailedWithoutCallingClient()
    {
        var mockClient = new Mock<ICscGlobalClient>();
        var plugin = MakePlugin(mockClient, configOverrides: new Dictionary<string, object> { [Constants.Enabled] = "false" });

        var result = await plugin.Enroll("csr", "CN=test", new Dictionary<string, string[]>(), ProductInfo(),
            RequestFormat.PKCS10, EnrollmentType.New);

        Assert.Equal((int)EndEntityStatus.FAILED, result.Status);
        mockClient.Verify(c => c.SubmitGetCustomFields(), Times.Never);
    }

    [Fact]
    public async Task Enroll_NullProductInfo_Throws()
    {
        var plugin = MakePlugin();
        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            plugin.Enroll("csr", "CN=test", new Dictionary<string, string[]>(), null!, RequestFormat.PKCS10, EnrollmentType.New));
    }

    [Fact]
    public async Task Enroll_NullProductParameters_Throws()
    {
        var plugin = MakePlugin();
        var productInfo = new EnrollmentProductInfo { ProductID = "CSC TrustedSecure DV", ProductParameters = null! };
        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            plugin.Enroll("csr", "CN=test", new Dictionary<string, string[]>(), productInfo, RequestFormat.PKCS10, EnrollmentType.New));
    }

    [Fact]
    public async Task Enroll_EmptyCsr_Throws()
    {
        var plugin = MakePlugin();
        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            plugin.Enroll("", "CN=test", new Dictionary<string, string[]>(), ProductInfo(), RequestFormat.PKCS10, EnrollmentType.New));
    }

    [Fact]
    public async Task Enroll_New_PriorCertSnPresent_ReturnsFailure()
    {
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitGetCustomFields()).ReturnsAsync(new List<GetCustomField>());
        var plugin = MakePlugin(mockClient);
        var productInfo = ProductInfo(parameters: new Dictionary<string, string> { ["PriorCertSN"] = "ABC123" });

        var result = await plugin.Enroll("csr", "CN=test", new Dictionary<string, string[]>(), productInfo,
            RequestFormat.PKCS10, EnrollmentType.New);

        Assert.NotEqual((int)EndEntityStatus.EXTERNALVALIDATION, result.Status);
        mockClient.Verify(c => c.SubmitRegistrationAsync(It.IsAny<RegistrationRequest>()), Times.Never);
    }

    [Fact]
    public async Task Enroll_New_Success_ReturnsExternalValidation()
    {
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitGetCustomFields()).ReturnsAsync(new List<GetCustomField>());
        mockClient.Setup(c => c.SubmitRegistrationAsync(It.IsAny<RegistrationRequest>())).ReturnsAsync(new RegistrationResponse
        {
            Result = new Result { CommonName = "new.example.com", Status = new Status { Uuid = "uuid-new" } }
        });

        var plugin = MakePlugin(mockClient);
        var result = await plugin.Enroll("csr", "CN=test", new Dictionary<string, string[]>(), ProductInfo(),
            RequestFormat.PKCS10, EnrollmentType.New);

        Assert.Equal((int)EndEntityStatus.EXTERNALVALIDATION, result.Status);
        Assert.Equal("uuid-new", result.CARequestID);
        // Command's enrollment UI doesn't surface StatusMessage on a successful/pending result -
        // only EnrollmentContext is - so the flow summary must be attached there instead, one
        // bullet per step so it renders readably rather than as a single run-on blob.
        Assert.NotNull(result.EnrollmentContext);
        Assert.True(result.EnrollmentContext.ContainsKey("Flow: Enroll-New"));
        Assert.True(result.EnrollmentContext.Keys.Count(k => k.StartsWith("Flow Step ")) > 1);
    }

    [Fact]
    public async Task Enroll_New_SuccessWithDcvDetails_KeepsDcvEntriesAlongsideFlowSummary()
    {
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitGetCustomFields()).ReturnsAsync(new List<GetCustomField>());
        mockClient.Setup(c => c.SubmitRegistrationAsync(It.IsAny<RegistrationRequest>())).ReturnsAsync(new RegistrationResponse
        {
            Result = new Result
            {
                CommonName = "dcv.example.com",
                Status = new Status { Uuid = "uuid-dcv" },
                DcvDetails = new List<DcvDetail>
                {
                    new DcvDetail { CName = new CName { Name = "_dnsauth.example.com", Value = "token" } }
                }
            }
        });

        var plugin = MakePlugin(mockClient);
        var result = await plugin.Enroll("csr", "CN=test", new Dictionary<string, string[]>(), ProductInfo(),
            RequestFormat.PKCS10, EnrollmentType.New);

        Assert.Equal("token", result.EnrollmentContext["_dnsauth.example.com"]);
        Assert.True(result.EnrollmentContext.ContainsKey("Flow: Enroll-New"));
        Assert.True(result.EnrollmentContext.Keys.Count(k => k.StartsWith("Flow Step ")) > 1);
    }

    [Fact]
    public async Task Enroll_New_RegistrationErrorFromCsc_PrependsFlowSummaryToStatusMessage()
    {
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitGetCustomFields()).ReturnsAsync(new List<GetCustomField>());
        mockClient.Setup(c => c.SubmitRegistrationAsync(It.IsAny<RegistrationRequest>())).ReturnsAsync(new RegistrationResponse
        {
            RegistrationError = new RegistrationError { Description = "Open order in progress" }
        });

        var plugin = MakePlugin(mockClient);
        var result = await plugin.Enroll("csr", "CN=test", new Dictionary<string, string[]>(), ProductInfo(),
            RequestFormat.PKCS10, EnrollmentType.New);

        Assert.Equal((int)EndEntityStatus.FAILED, result.Status);
        Assert.Contains("Enroll-New", result.StatusMessage);
        Assert.Contains("Open order in progress", result.StatusMessage);
    }

    [Fact]
    public async Task Enroll_New_NullClientResponse_ReturnsFailure()
    {
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitGetCustomFields()).ReturnsAsync(new List<GetCustomField>());
        mockClient.Setup(c => c.SubmitRegistrationAsync(It.IsAny<RegistrationRequest>())).ReturnsAsync((RegistrationResponse)null!);

        var plugin = MakePlugin(mockClient);
        var result = await plugin.Enroll("csr", "CN=test", new Dictionary<string, string[]>(), ProductInfo(),
            RequestFormat.PKCS10, EnrollmentType.New);

        Assert.NotEqual((int)EndEntityStatus.EXTERNALVALIDATION, result.Status);
    }

    [Fact]
    public async Task Enroll_New_ClientThrows_ReturnsFailureInsteadOfThrowing()
    {
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitGetCustomFields()).ReturnsAsync(new List<GetCustomField>());
        mockClient.Setup(c => c.SubmitRegistrationAsync(It.IsAny<RegistrationRequest>())).ThrowsAsync(new InvalidOperationException("boom"));

        var plugin = MakePlugin(mockClient);
        var result = await plugin.Enroll("csr", "CN=test", new Dictionary<string, string[]>(), ProductInfo(),
            RequestFormat.PKCS10, EnrollmentType.New);

        Assert.NotEqual((int)EndEntityStatus.EXTERNALVALIDATION, result.Status);
        Assert.Contains("boom", result.StatusMessage);
    }

    [Fact]
    public async Task Enroll_UnhandledEnrollmentType_ReturnsFailure()
    {
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitGetCustomFields()).ReturnsAsync(new List<GetCustomField>());
        var plugin = MakePlugin(mockClient);

        var result = await plugin.Enroll("csr", "CN=test", new Dictionary<string, string[]>(), ProductInfo(),
            RequestFormat.PKCS10, EnrollmentType.Renew);

        Assert.NotEqual((int)EndEntityStatus.EXTERNALVALIDATION, result.Status);
    }

    [Fact]
    public async Task Enroll_New_WithPollingEnabledAndFastIssuance_ReturnsGeneratedCertDirectly()
    {
        var (_, pem) = MakeSelfSignedCert();
        var apiBase64 = Convert.ToBase64String(Encoding.ASCII.GetBytes(pem));
        var uuid = Guid.NewGuid().ToString(); // must be >= 36 chars - GetSingleRecord validates length

        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitGetCustomFields()).ReturnsAsync(new List<GetCustomField>());
        mockClient.Setup(c => c.SubmitRegistrationAsync(It.IsAny<RegistrationRequest>())).ReturnsAsync(new RegistrationResponse
        {
            Result = new Result { CommonName = "fast.example.com", Status = new Status { Uuid = uuid } }
        });
        mockClient.Setup(c => c.SubmitGetCertificateAsync(uuid)).ReturnsAsync(new CertificateResponse
        {
            Status = "ACTIVE",
            Certificate = apiBase64
        });

        // DcvPollTimeoutSeconds < the 10s poll interval means exactly one poll attempt happens
        // and the loop then breaks without ever calling Task.Delay - fast and deterministic.
        var plugin = MakePlugin(mockClient, configOverrides: new Dictionary<string, object> { [Constants.DcvPollTimeoutSeconds] = "1" });

        var result = await plugin.Enroll("csr", "CN=test", new Dictionary<string, string[]>(), ProductInfo(),
            RequestFormat.PKCS10, EnrollmentType.New);

        Assert.Equal((int)EndEntityStatus.GENERATED, result.Status);
        Assert.Equal(uuid, result.CARequestID);
        Assert.NotNull(result.Certificate);
    }

    [Fact]
    public async Task Enroll_New_PollingEnabledButNotIssued_FallsBackToPendingResult()
    {
        var uuid = Guid.NewGuid().ToString();
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitGetCustomFields()).ReturnsAsync(new List<GetCustomField>());
        mockClient.Setup(c => c.SubmitRegistrationAsync(It.IsAny<RegistrationRequest>())).ReturnsAsync(new RegistrationResponse
        {
            Result = new Result { CommonName = "pending.example.com", Status = new Status { Uuid = uuid } }
        });
        mockClient.Setup(c => c.SubmitGetCertificateAsync(uuid)).ReturnsAsync(new CertificateResponse { Status = "Pending" });

        var plugin = MakePlugin(mockClient, configOverrides: new Dictionary<string, object> { [Constants.DcvPollTimeoutSeconds] = "1" });

        var result = await plugin.Enroll("csr", "CN=test", new Dictionary<string, string[]>(), ProductInfo(),
            RequestFormat.PKCS10, EnrollmentType.New);

        Assert.Equal((int)EndEntityStatus.EXTERNALVALIDATION, result.Status);
        Assert.Equal(uuid, result.CARequestID);
    }

    [Fact]
    public async Task Enroll_New_WithDnsValidatorFactory_PublishesCnameRecord()
    {
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitGetCustomFields()).ReturnsAsync(new List<GetCustomField>());
        mockClient.Setup(c => c.SubmitRegistrationAsync(It.IsAny<RegistrationRequest>())).ReturnsAsync(new RegistrationResponse
        {
            Result = new Result
            {
                CommonName = "cname.example.com",
                Status = new Status { Uuid = "uuid-cname" },
                DcvDetails = new List<DcvDetail>
                {
                    new DcvDetail { CName = new CName { Name = "_dnsauth.example.com.", Value = "target.sectigo.com." } }
                }
            }
        });

        var mockValidator = new Mock<IDomainValidator>();
        mockValidator.Setup(v => v.GetValidationType()).Returns("cname");
        mockValidator.Setup(v => v.StageValidation(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DomainValidationResult { Success = true, Status = "staged" });

        var mockFactory = new Mock<IDomainValidatorFactory>();
        mockFactory.Setup(f => f.ResolveDomainValidator(It.IsAny<string>(), "cname")).Returns(mockValidator.Object);

        var plugin = MakePlugin(mockClient, validatorFactory: mockFactory.Object);
        var productInfo = ProductInfo(parameters: new Dictionary<string, string>
        {
            [EnrollmentConfigConstants.DomainControlValidationMethod] = "CNAME"
        });

        var result = await plugin.Enroll("csr", "CN=test", new Dictionary<string, string[]>(), productInfo,
            RequestFormat.PKCS10, EnrollmentType.New);

        Assert.Equal((int)EndEntityStatus.EXTERNALVALIDATION, result.Status);
        // Trailing dots must be stripped before resolution or no provider would match.
        mockFactory.Verify(f => f.ResolveDomainValidator("_dnsauth.example.com", "cname"), Times.Once);
        mockValidator.Verify(v => v.StageValidation("_dnsauth.example.com", "target.sectigo.com", It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task Enroll_New_WithDnsValidatorFactoryButEmailMethod_DoesNotAttemptPublish()
    {
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitGetCustomFields()).ReturnsAsync(new List<GetCustomField>());
        mockClient.Setup(c => c.SubmitRegistrationAsync(It.IsAny<RegistrationRequest>())).ReturnsAsync(new RegistrationResponse
        {
            Result = new Result
            {
                CommonName = "email.example.com",
                Status = new Status { Uuid = "uuid-email" },
                DcvDetails = new List<DcvDetail> { new DcvDetail { Email = "admin@example.com" } }
            }
        });

        var mockFactory = new Mock<IDomainValidatorFactory>();
        var plugin = MakePlugin(mockClient, validatorFactory: mockFactory.Object);
        var productInfo = ProductInfo(parameters: new Dictionary<string, string>
        {
            [EnrollmentConfigConstants.DomainControlValidationMethod] = "EMAIL"
        });

        await plugin.Enroll("csr", "CN=test", new Dictionary<string, string[]>(), productInfo,
            RequestFormat.PKCS10, EnrollmentType.New);

        mockFactory.Verify(f => f.ResolveDomainValidator(It.IsAny<string>(), It.IsAny<string>()), Times.Never);
    }

    [Fact]
    public async Task Enroll_New_DnsValidatorUnresolved_DoesNotThrow()
    {
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitGetCustomFields()).ReturnsAsync(new List<GetCustomField>());
        mockClient.Setup(c => c.SubmitRegistrationAsync(It.IsAny<RegistrationRequest>())).ReturnsAsync(new RegistrationResponse
        {
            Result = new Result
            {
                CommonName = "unresolved.example.com",
                Status = new Status { Uuid = "uuid-unresolved" },
                DcvDetails = new List<DcvDetail>
                {
                    new DcvDetail { CName = new CName { Name = "_dnsauth.example.com", Value = "target.sectigo.com" } }
                }
            }
        });

        var mockFactory = new Mock<IDomainValidatorFactory>();
        mockFactory.Setup(f => f.ResolveDomainValidator(It.IsAny<string>(), "cname")).Returns((IDomainValidator)null!);

        var plugin = MakePlugin(mockClient, validatorFactory: mockFactory.Object);
        var productInfo = ProductInfo(parameters: new Dictionary<string, string>
        {
            [EnrollmentConfigConstants.DomainControlValidationMethod] = "CNAME"
        });

        var result = await plugin.Enroll("csr", "CN=test", new Dictionary<string, string[]>(), productInfo,
            RequestFormat.PKCS10, EnrollmentType.New);

        Assert.Equal((int)EndEntityStatus.EXTERNALVALIDATION, result.Status);
    }

    [Fact]
    public async Task Enroll_New_DnsValidatorStageValidationThrows_DoesNotThrow()
    {
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitGetCustomFields()).ReturnsAsync(new List<GetCustomField>());
        mockClient.Setup(c => c.SubmitRegistrationAsync(It.IsAny<RegistrationRequest>())).ReturnsAsync(new RegistrationResponse
        {
            Result = new Result
            {
                CommonName = "err.example.com",
                Status = new Status { Uuid = "uuid-err" },
                DcvDetails = new List<DcvDetail>
                {
                    new DcvDetail { CName = new CName { Name = "_dnsauth.example.com", Value = "target.sectigo.com" } }
                }
            }
        });

        var mockValidator = new Mock<IDomainValidator>();
        mockValidator.Setup(v => v.GetValidationType()).Returns("cname");
        mockValidator.Setup(v => v.StageValidation(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("dns failure"));

        var mockFactory = new Mock<IDomainValidatorFactory>();
        mockFactory.Setup(f => f.ResolveDomainValidator(It.IsAny<string>(), "cname")).Returns(mockValidator.Object);

        var plugin = MakePlugin(mockClient, validatorFactory: mockFactory.Object);
        var productInfo = ProductInfo(parameters: new Dictionary<string, string>
        {
            [EnrollmentConfigConstants.DomainControlValidationMethod] = "CNAME"
        });

        var result = await plugin.Enroll("csr", "CN=test", new Dictionary<string, string[]>(), productInfo,
            RequestFormat.PKCS10, EnrollmentType.New);

        Assert.Equal((int)EndEntityStatus.EXTERNALVALIDATION, result.Status);
    }

    [Fact]
    public async Task Enroll_New_DnsValidatorReturnsFailure_DoesNotThrow()
    {
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitGetCustomFields()).ReturnsAsync(new List<GetCustomField>());
        mockClient.Setup(c => c.SubmitRegistrationAsync(It.IsAny<RegistrationRequest>())).ReturnsAsync(new RegistrationResponse
        {
            Result = new Result
            {
                CommonName = "fail.example.com",
                Status = new Status { Uuid = "uuid-fail" },
                DcvDetails = new List<DcvDetail>
                {
                    new DcvDetail { CName = new CName { Name = "_dnsauth.example.com", Value = "target.sectigo.com" } }
                }
            }
        });

        var mockValidator = new Mock<IDomainValidator>();
        mockValidator.Setup(v => v.GetValidationType()).Returns("cname");
        mockValidator.Setup(v => v.StageValidation(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DomainValidationResult { Success = false, Status = "error", ErrorMessage = "nope" });

        var mockFactory = new Mock<IDomainValidatorFactory>();
        mockFactory.Setup(f => f.ResolveDomainValidator(It.IsAny<string>(), "cname")).Returns(mockValidator.Object);

        var plugin = MakePlugin(mockClient, validatorFactory: mockFactory.Object);
        var productInfo = ProductInfo(parameters: new Dictionary<string, string>
        {
            [EnrollmentConfigConstants.DomainControlValidationMethod] = "CNAME"
        });

        var result = await plugin.Enroll("csr", "CN=test", new Dictionary<string, string[]>(), productInfo,
            RequestFormat.PKCS10, EnrollmentType.New);

        Assert.Equal((int)EndEntityStatus.EXTERNALVALIDATION, result.Status);
    }

    [Fact]
    public async Task Enroll_New_DnsValidatorReturnsNullResult_DoesNotThrow()
    {
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitGetCustomFields()).ReturnsAsync(new List<GetCustomField>());
        mockClient.Setup(c => c.SubmitRegistrationAsync(It.IsAny<RegistrationRequest>())).ReturnsAsync(new RegistrationResponse
        {
            Result = new Result
            {
                CommonName = "fail-null.example.com",
                Status = new Status { Uuid = "uuid-fail-null" },
                DcvDetails = new List<DcvDetail>
                {
                    new DcvDetail { CName = new CName { Name = "_dnsauth.example.com", Value = "target.sectigo.com" } }
                }
            }
        });

        var mockValidator = new Mock<IDomainValidator>();
        mockValidator.Setup(v => v.GetValidationType()).Returns("cname");
        mockValidator.Setup(v => v.StageValidation(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((DomainValidationResult)null!);

        var mockFactory = new Mock<IDomainValidatorFactory>();
        mockFactory.Setup(f => f.ResolveDomainValidator(It.IsAny<string>(), "cname")).Returns(mockValidator.Object);

        var plugin = MakePlugin(mockClient, validatorFactory: mockFactory.Object);
        var productInfo = ProductInfo(parameters: new Dictionary<string, string>
        {
            [EnrollmentConfigConstants.DomainControlValidationMethod] = "CNAME"
        });

        var result = await plugin.Enroll("csr", "CN=test", new Dictionary<string, string[]>(), productInfo,
            RequestFormat.PKCS10, EnrollmentType.New);

        Assert.Equal((int)EndEntityStatus.EXTERNALVALIDATION, result.Status);
    }

    [Fact]
    public async Task Enroll_New_DnsFactoryButNoEnrollmentContext_SkipsPublish()
    {
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitGetCustomFields()).ReturnsAsync(new List<GetCustomField>());
        mockClient.Setup(c => c.SubmitRegistrationAsync(It.IsAny<RegistrationRequest>())).ReturnsAsync(new RegistrationResponse
        {
            Result = new Result { CommonName = "none.example.com", Status = new Status { Uuid = "uuid-none" } }
        });

        var mockFactory = new Mock<IDomainValidatorFactory>();
        var plugin = MakePlugin(mockClient, validatorFactory: mockFactory.Object);

        await plugin.Enroll("csr", "CN=test", new Dictionary<string, string[]>(), ProductInfo(),
            RequestFormat.PKCS10, EnrollmentType.New);

        mockFactory.Verify(f => f.ResolveDomainValidator(It.IsAny<string>(), It.IsAny<string>()), Times.Never);
    }

    [Fact]
    public async Task Enroll_New_PollingEnabledButNoCARequestId_SkipsPollingWithoutError()
    {
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitGetCustomFields()).ReturnsAsync(new List<GetCustomField>());
        mockClient.Setup(c => c.SubmitRegistrationAsync(It.IsAny<RegistrationRequest>())).ReturnsAsync(new RegistrationResponse
        {
            // No Status/Uuid at all -> enrollResult.CARequestID is null -> TryPollForIssuedCertAsync
            // must skip cleanly rather than throw.
            Result = new Result { CommonName = "no-uuid.example.com" }
        });

        var plugin = MakePlugin(mockClient, configOverrides: new Dictionary<string, object> { [Constants.DcvPollTimeoutSeconds] = "1" });

        var result = await plugin.Enroll("csr", "CN=test", new Dictionary<string, string[]>(), ProductInfo(),
            RequestFormat.PKCS10, EnrollmentType.New);

        Assert.Equal((int)EndEntityStatus.EXTERNALVALIDATION, result.Status);
        mockClient.Verify(c => c.SubmitGetCertificateAsync(It.IsAny<string>()), Times.Never);
    }

    [Fact]
    public async Task Enroll_New_PollingThrowsOnFirstAttempt_FallsBackToPendingResult()
    {
        var uuid = Guid.NewGuid().ToString();
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitGetCustomFields()).ReturnsAsync(new List<GetCustomField>());
        mockClient.Setup(c => c.SubmitRegistrationAsync(It.IsAny<RegistrationRequest>())).ReturnsAsync(new RegistrationResponse
        {
            Result = new Result { CommonName = "poll-error.example.com", Status = new Status { Uuid = uuid } }
        });
        // GetSingleRecord (called internally by the poll loop) throws - must be caught and retried,
        // not propagated, and the loop still falls back to the pending result once time is up.
        mockClient.Setup(c => c.SubmitGetCertificateAsync(uuid)).ThrowsAsync(new InvalidOperationException("network blip"));

        var plugin = MakePlugin(mockClient, configOverrides: new Dictionary<string, object> { [Constants.DcvPollTimeoutSeconds] = "1" });

        var result = await plugin.Enroll("csr", "CN=test", new Dictionary<string, string[]>(), ProductInfo(),
            RequestFormat.PKCS10, EnrollmentType.New);

        Assert.Equal((int)EndEntityStatus.EXTERNALVALIDATION, result.Status);
    }

    [Fact]
    public async Task Enroll_New_CnameMethodWithMixedEmailEntry_SkipsEmailPassthroughEntry()
    {
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitGetCustomFields()).ReturnsAsync(new List<GetCustomField>());
        mockClient.Setup(c => c.SubmitRegistrationAsync(It.IsAny<RegistrationRequest>())).ReturnsAsync(new RegistrationResponse
        {
            Result = new Result
            {
                CommonName = "mixed.example.com",
                Status = new Status { Uuid = "uuid-mixed" },
                DcvDetails = new List<DcvDetail>
                {
                    new DcvDetail { CName = new CName { Name = "_dnsauth.example.com", Value = "target.sectigo.com" } },
                    // Key == value: GetEnrollmentResult's email passthrough shape, mixed into the
                    // same EnrollmentContext even though the product's DCV method is CNAME.
                    new DcvDetail { Email = "admin@example.com" }
                }
            }
        });

        var mockValidator = new Mock<IDomainValidator>();
        mockValidator.Setup(v => v.GetValidationType()).Returns("cname");
        mockValidator.Setup(v => v.StageValidation(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DomainValidationResult { Success = true });

        var mockFactory = new Mock<IDomainValidatorFactory>();
        mockFactory.Setup(f => f.ResolveDomainValidator(It.IsAny<string>(), "cname")).Returns(mockValidator.Object);

        var plugin = MakePlugin(mockClient, validatorFactory: mockFactory.Object);
        var productInfo = ProductInfo(parameters: new Dictionary<string, string>
        {
            [EnrollmentConfigConstants.DomainControlValidationMethod] = "CNAME"
        });

        await plugin.Enroll("csr", "CN=test", new Dictionary<string, string[]>(), productInfo,
            RequestFormat.PKCS10, EnrollmentType.New);

        // Only the CNAME entry should have been resolved/staged; the email passthrough is skipped.
        mockFactory.Verify(f => f.ResolveDomainValidator(It.IsAny<string>(), "cname"), Times.Once);
    }

    // ---------------------------------------------------------------------
    // Enroll - RenewOrReissue
    // ---------------------------------------------------------------------

    [Fact]
    public async Task Enroll_RenewOrReissue_MissingPriorCertSn_ReturnsFailure()
    {
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitGetCustomFields()).ReturnsAsync(new List<GetCustomField>());
        var plugin = MakePlugin(mockClient);

        var result = await plugin.Enroll("csr", "CN=test", new Dictionary<string, string[]>(), ProductInfo(),
            RequestFormat.PKCS10, EnrollmentType.RenewOrReissue);

        Assert.NotEqual((int)EndEntityStatus.EXTERNALVALIDATION, result.Status);
        Assert.Contains("PriorCertSN", result.StatusMessage);
    }

    [Fact]
    public async Task Enroll_RenewOrReissue_NoOrderIdFoundForSerial_ReturnsFailure()
    {
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitGetCustomFields()).ReturnsAsync(new List<GetCustomField>());
        var certDataReader = new Mock<ICertificateDataReader>();
        certDataReader.Setup(r => r.GetRequestIDBySerialNumber("ABC123")).ReturnsAsync(string.Empty);

        var plugin = MakePlugin(mockClient, certDataReader);
        var productInfo = ProductInfo(parameters: new Dictionary<string, string> { ["PriorCertSN"] = "ABC123" });

        var result = await plugin.Enroll("csr", "CN=test", new Dictionary<string, string[]>(), productInfo,
            RequestFormat.PKCS10, EnrollmentType.RenewOrReissue);

        Assert.NotEqual((int)EndEntityStatus.EXTERNALVALIDATION, result.Status);
    }

    [Fact]
    public async Task Enroll_RenewOrReissue_OrderIdTooShort_ReturnsFailure()
    {
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitGetCustomFields()).ReturnsAsync(new List<GetCustomField>());
        var certDataReader = new Mock<ICertificateDataReader>();
        certDataReader.Setup(r => r.GetRequestIDBySerialNumber("ABC123")).ReturnsAsync("short");

        var plugin = MakePlugin(mockClient, certDataReader);
        var productInfo = ProductInfo(parameters: new Dictionary<string, string> { ["PriorCertSN"] = "ABC123" });

        var result = await plugin.Enroll("csr", "CN=test", new Dictionary<string, string[]>(), productInfo,
            RequestFormat.PKCS10, EnrollmentType.RenewOrReissue);

        Assert.NotEqual((int)EndEntityStatus.EXTERNALVALIDATION, result.Status);
    }

    [Fact]
    public async Task Enroll_RenewOrReissue_RenewalWithApplicantLastName_Succeeds()
    {
        var orderUuid = Guid.NewGuid().ToString();
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitGetCustomFields()).ReturnsAsync(new List<GetCustomField>());
        // OrderDate 2 years ago -> well past the 1-year+RenewalWindowDays expiry -> renewal path.
        mockClient.Setup(c => c.SubmitGetCertificateAsync(orderUuid)).ReturnsAsync(new CertificateResponse
        {
            OrderDate = DateTime.UtcNow.AddYears(-2).ToString("o")
        });
        mockClient.Setup(c => c.SubmitRenewalAsync(It.IsAny<RenewalRequest>())).ReturnsAsync(new RenewalResponse
        {
            Result = new Result { CommonName = "renewed.example.com", Status = new Status { Uuid = orderUuid } }
        });

        var certDataReader = new Mock<ICertificateDataReader>();
        certDataReader.Setup(r => r.GetRequestIDBySerialNumber("ABC123")).ReturnsAsync(orderUuid);

        var plugin = MakePlugin(mockClient, certDataReader);
        var productInfo = ProductInfo(parameters: new Dictionary<string, string>
        {
            ["PriorCertSN"] = "ABC123",
            ["Applicant Last Name"] = "Doe"
        });

        var result = await plugin.Enroll("csr", "CN=test", new Dictionary<string, string[]>(), productInfo,
            RequestFormat.PKCS10, EnrollmentType.RenewOrReissue);

        Assert.Equal((int)EndEntityStatus.EXTERNALVALIDATION, result.Status);
        mockClient.Verify(c => c.SubmitRenewalAsync(It.IsAny<RenewalRequest>()), Times.Once);
    }

    [Fact]
    public async Task Enroll_RenewOrReissue_RenewalMissingApplicantLastName_ReturnsFailure()
    {
        var orderUuid = Guid.NewGuid().ToString();
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitGetCustomFields()).ReturnsAsync(new List<GetCustomField>());
        mockClient.Setup(c => c.SubmitGetCertificateAsync(orderUuid)).ReturnsAsync(new CertificateResponse
        {
            OrderDate = DateTime.UtcNow.AddYears(-2).ToString("o")
        });

        var certDataReader = new Mock<ICertificateDataReader>();
        certDataReader.Setup(r => r.GetRequestIDBySerialNumber("ABC123")).ReturnsAsync(orderUuid);

        var plugin = MakePlugin(mockClient, certDataReader);
        var productInfo = ProductInfo(parameters: new Dictionary<string, string> { ["PriorCertSN"] = "ABC123" });

        var result = await plugin.Enroll("csr", "CN=test", new Dictionary<string, string[]>(), productInfo,
            RequestFormat.PKCS10, EnrollmentType.RenewOrReissue);

        Assert.NotEqual((int)EndEntityStatus.EXTERNALVALIDATION, result.Status);
        mockClient.Verify(c => c.SubmitRenewalAsync(It.IsAny<RenewalRequest>()), Times.Never);
    }

    [Fact]
    public async Task Enroll_RenewOrReissue_ReissueWithApplicantLastName_Succeeds()
    {
        var orderUuid = Guid.NewGuid().ToString();
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitGetCustomFields()).ReturnsAsync(new List<GetCustomField>());
        // OrderDate today -> well within the renewal window -> reissue (free) path.
        mockClient.Setup(c => c.SubmitGetCertificateAsync(orderUuid)).ReturnsAsync(new CertificateResponse
        {
            OrderDate = DateTime.UtcNow.ToString("o")
        });
        mockClient.Setup(c => c.SubmitReissueAsync(It.IsAny<ReissueRequest>())).ReturnsAsync(new ReissueResponse
        {
            Result = new Result { CommonName = "reissued.example.com", Status = new Status { Uuid = orderUuid } }
        });

        var certDataReader = new Mock<ICertificateDataReader>();
        certDataReader.Setup(r => r.GetRequestIDBySerialNumber("ABC123")).ReturnsAsync(orderUuid);

        var plugin = MakePlugin(mockClient, certDataReader);
        var productInfo = ProductInfo(parameters: new Dictionary<string, string>
        {
            ["PriorCertSN"] = "ABC123",
            ["Applicant Last Name"] = "Doe"
        });

        var result = await plugin.Enroll("csr", "CN=test", new Dictionary<string, string[]>(), productInfo,
            RequestFormat.PKCS10, EnrollmentType.RenewOrReissue);

        Assert.Equal((int)EndEntityStatus.EXTERNALVALIDATION, result.Status);
        mockClient.Verify(c => c.SubmitReissueAsync(It.IsAny<ReissueRequest>()), Times.Once);
    }

    [Fact]
    public async Task Enroll_RenewOrReissue_ReissueMissingApplicantLastName_ReturnsFailure()
    {
        var orderUuid = Guid.NewGuid().ToString();
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitGetCustomFields()).ReturnsAsync(new List<GetCustomField>());
        mockClient.Setup(c => c.SubmitGetCertificateAsync(orderUuid)).ReturnsAsync(new CertificateResponse
        {
            OrderDate = DateTime.UtcNow.ToString("o")
        });

        var certDataReader = new Mock<ICertificateDataReader>();
        certDataReader.Setup(r => r.GetRequestIDBySerialNumber("ABC123")).ReturnsAsync(orderUuid);

        var plugin = MakePlugin(mockClient, certDataReader);
        var productInfo = ProductInfo(parameters: new Dictionary<string, string> { ["PriorCertSN"] = "ABC123" });

        var result = await plugin.Enroll("csr", "CN=test", new Dictionary<string, string[]>(), productInfo,
            RequestFormat.PKCS10, EnrollmentType.RenewOrReissue);

        Assert.NotEqual((int)EndEntityStatus.EXTERNALVALIDATION, result.Status);
        mockClient.Verify(c => c.SubmitReissueAsync(It.IsAny<ReissueRequest>()), Times.Never);
    }

    [Fact]
    public async Task Enroll_RenewOrReissue_NoOrderDate_FallsBackToCertificateDataReaderExpiry()
    {
        var orderUuid = Guid.NewGuid().ToString();
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitGetCustomFields()).ReturnsAsync(new List<GetCustomField>());
        // No OrderDate at all -> falls back to expiry-based decision.
        mockClient.Setup(c => c.SubmitGetCertificateAsync(orderUuid)).ReturnsAsync(new CertificateResponse { OrderDate = null });
        mockClient.Setup(c => c.SubmitRenewalAsync(It.IsAny<RenewalRequest>())).ReturnsAsync(new RenewalResponse
        {
            Result = new Result { CommonName = "expired.example.com", Status = new Status { Uuid = orderUuid } }
        });

        var certDataReader = new Mock<ICertificateDataReader>();
        certDataReader.Setup(r => r.GetRequestIDBySerialNumber("ABC123")).ReturnsAsync(orderUuid);
        certDataReader.Setup(r => r.GetExpirationDateByRequestId(orderUuid)).Returns(DateTime.Now.AddDays(-1));

        var plugin = MakePlugin(mockClient, certDataReader);
        var productInfo = ProductInfo(parameters: new Dictionary<string, string>
        {
            ["PriorCertSN"] = "ABC123",
            ["Applicant Last Name"] = "Doe"
        });

        var result = await plugin.Enroll("csr", "CN=test", new Dictionary<string, string[]>(), productInfo,
            RequestFormat.PKCS10, EnrollmentType.RenewOrReissue);

        Assert.Equal((int)EndEntityStatus.EXTERNALVALIDATION, result.Status);
        mockClient.Verify(c => c.SubmitRenewalAsync(It.IsAny<RenewalRequest>()), Times.Once);
    }

    // ---------------------------------------------------------------------
    // GetEndEntityCertificate / ExtractCertificates / FindLeaf
    // ---------------------------------------------------------------------

    [Fact]
    public void GetEndEntityCertificate_EmptyInput_ReturnsEmpty()
    {
        var plugin = MakePlugin();
        Assert.Equal(string.Empty, plugin.GetEndEntityCertificate(""));
        Assert.Equal(string.Empty, plugin.GetEndEntityCertificate("   "));
        Assert.Equal(string.Empty, plugin.GetEndEntityCertificate(null!));
    }

    [Fact]
    public void GetEndEntityCertificate_NoPemBlocks_ReturnsEmpty()
    {
        var plugin = MakePlugin();
        Assert.Equal(string.Empty, plugin.GetEndEntityCertificate("just some plain text, no PEM fences"));
    }

    [Fact]
    public void GetEndEntityCertificate_EmptyPemBlockContent_SkipsBlock()
    {
        var (cert, pem) = MakeSelfSignedCert();
        var emptyBlock = "-----BEGIN CERTIFICATE-----\n \n-----END CERTIFICATE-----\n";
        var plugin = MakePlugin();

        var result = plugin.GetEndEntityCertificate(emptyBlock + pem);

        Assert.Equal(Convert.ToBase64String(cert.RawData), result);
    }

    [Fact]
    public void GetEndEntityCertificate_CertWithoutBasicConstraints_TreatedAsNonCa()
    {
        // A cert with no Basic Constraints extension at all exercises FindLeaf's IsCa "unknown ->
        // treat as non-CA" fallback, distinct from an explicit CertificateAuthority=false.
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=no-constraints.example.com", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(365));
        var pem = "-----BEGIN CERTIFICATE-----\n" +
                  Convert.ToBase64String(cert.RawData, Base64FormattingOptions.InsertLineBreaks) +
                  "\n-----END CERTIFICATE-----\n";

        var plugin = MakePlugin();
        var result = plugin.GetEndEntityCertificate(pem);

        Assert.Equal(Convert.ToBase64String(cert.RawData), result);
    }

    [Fact]
    public void GetEndEntityCertificate_MalformedBase64InBlock_SkipsAndReturnsEmpty()
    {
        var pem = "-----BEGIN CERTIFICATE-----\nNOT!!VALID==BASE64%%CHARS\n-----END CERTIFICATE-----\n";
        var plugin = MakePlugin();
        Assert.Equal(string.Empty, plugin.GetEndEntityCertificate(pem));
    }

    [Fact]
    public void GetEndEntityCertificate_ValidBase64ButNotACertificate_SkipsAndReturnsEmpty()
    {
        var notACert = Convert.ToBase64String(Encoding.UTF8.GetBytes("this decodes fine but is not DER-encoded"));
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

    [Fact]
    public void GetEndEntityCertificate_NoDeterminableLeaf_ReturnsEmpty()
    {
        // Two distinct CA certs that (deliberately) share the exact same Subject/Issuer DN
        // string: FindLeaf's Issuer/Subject string-matching heuristic treats each as "issuing"
        // the other, so neither ends up in nonIssuers nor anyNonCa (both are CA=true) - the
        // "give up" path.
        string ToPemBlock(X509Certificate2 c) => "-----BEGIN CERTIFICATE-----\n" +
            Convert.ToBase64String(c.RawData, Base64FormattingOptions.InsertLineBreaks) +
            "\n-----END CERTIFICATE-----\n";

        X509Certificate2 MakeCaCert()
        {
            using var rsa = RSA.Create(2048);
            var req = new CertificateRequest("CN=duplicate.example.com", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            return req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(365));
        }

        var pem = ToPemBlock(MakeCaCert()) + ToPemBlock(MakeCaCert());
        var plugin = MakePlugin();

        Assert.Equal(string.Empty, plugin.GetEndEntityCertificate(pem));
    }

    [Fact]
    public async Task Enroll_New_CustomFieldsNull_UsesEmptyListInstead()
    {
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitGetCustomFields()).ReturnsAsync((List<GetCustomField>)null!);
        mockClient.Setup(c => c.SubmitRegistrationAsync(It.IsAny<RegistrationRequest>())).ReturnsAsync(new RegistrationResponse
        {
            Result = new Result { CommonName = "nullfields.example.com", Status = new Status { Uuid = "uuid-nf" } }
        });

        var plugin = MakePlugin(mockClient);
        var result = await plugin.Enroll("csr", "CN=test", new Dictionary<string, string[]>(), ProductInfo(),
            RequestFormat.PKCS10, EnrollmentType.New);

        Assert.Equal((int)EndEntityStatus.EXTERNALVALIDATION, result.Status);
    }

    [Fact]
    public async Task Enroll_RenewOrReissue_FetchLiveCertThrowsAndFallbackAlsoFails_ReturnsFailure()
    {
        var orderUuid = Guid.NewGuid().ToString();
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitGetCustomFields()).ReturnsAsync(new List<GetCustomField>());
        // Both the primary live-cert fetch AND the fallback's GetSingleRecord call use the same
        // client method, and both fail - forcing the innermost catch(fallbackEx) path.
        mockClient.Setup(c => c.SubmitGetCertificateAsync(orderUuid)).ThrowsAsync(new InvalidOperationException("network error"));

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

        Assert.NotEqual((int)EndEntityStatus.EXTERNALVALIDATION, result.Status);
        Assert.Contains("unable to determine renewal status", result.StatusMessage);
    }

    [Fact]
    public async Task Enroll_RenewOrReissue_RenewalUuidLookupFails_ReturnsFailure()
    {
        var orderUuid = Guid.NewGuid().ToString();
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitGetCustomFields()).ReturnsAsync(new List<GetCustomField>());
        mockClient.Setup(c => c.SubmitGetCertificateAsync(orderUuid)).ReturnsAsync(new CertificateResponse
        {
            OrderDate = DateTime.UtcNow.AddYears(-2).ToString("o") // renewal path
        });

        var certDataReader = new Mock<ICertificateDataReader>();
        // First call resolves the top-level order_id; second (inside the renewal branch, for the
        // same PriorCertSN) fails to resolve - exercises ValidateRenewalUUID's failure branch.
        certDataReader.SetupSequence(r => r.GetRequestIDBySerialNumber("ABC123"))
            .ReturnsAsync(orderUuid)
            .ReturnsAsync(string.Empty);

        var plugin = MakePlugin(mockClient, certDataReader);
        var productInfo = ProductInfo(parameters: new Dictionary<string, string>
        {
            ["PriorCertSN"] = "ABC123",
            ["Applicant Last Name"] = "Doe"
        });

        var result = await plugin.Enroll("csr", "CN=test", new Dictionary<string, string[]>(), productInfo,
            RequestFormat.PKCS10, EnrollmentType.RenewOrReissue);

        Assert.NotEqual((int)EndEntityStatus.EXTERNALVALIDATION, result.Status);
        Assert.Contains("could not resolve prior certificate serial number", result.StatusMessage);
    }

    [Fact]
    public async Task Enroll_RenewOrReissue_RenewalNullResponse_ReturnsFailure()
    {
        var orderUuid = Guid.NewGuid().ToString();
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitGetCustomFields()).ReturnsAsync(new List<GetCustomField>());
        mockClient.Setup(c => c.SubmitGetCertificateAsync(orderUuid)).ReturnsAsync(new CertificateResponse
        {
            OrderDate = DateTime.UtcNow.AddYears(-2).ToString("o")
        });
        mockClient.Setup(c => c.SubmitRenewalAsync(It.IsAny<RenewalRequest>())).ReturnsAsync((RenewalResponse)null!);

        var certDataReader = new Mock<ICertificateDataReader>();
        certDataReader.Setup(r => r.GetRequestIDBySerialNumber("ABC123")).ReturnsAsync(orderUuid);

        var plugin = MakePlugin(mockClient, certDataReader);
        var productInfo = ProductInfo(parameters: new Dictionary<string, string>
        {
            ["PriorCertSN"] = "ABC123",
            ["Applicant Last Name"] = "Doe"
        });

        var result = await plugin.Enroll("csr", "CN=test", new Dictionary<string, string[]>(), productInfo,
            RequestFormat.PKCS10, EnrollmentType.RenewOrReissue);

        Assert.NotEqual((int)EndEntityStatus.EXTERNALVALIDATION, result.Status);
        Assert.Contains("CSC API returned a null response", result.StatusMessage);
    }

    [Fact]
    public async Task Enroll_RenewOrReissue_ReissueRequestIdLookupEmpty_ReturnsFailure()
    {
        var orderUuid = Guid.NewGuid().ToString();
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitGetCustomFields()).ReturnsAsync(new List<GetCustomField>());
        mockClient.Setup(c => c.SubmitGetCertificateAsync(orderUuid)).ReturnsAsync(new CertificateResponse
        {
            OrderDate = DateTime.UtcNow.ToString("o") // reissue path
        });

        var certDataReader = new Mock<ICertificateDataReader>();
        certDataReader.SetupSequence(r => r.GetRequestIDBySerialNumber("ABC123"))
            .ReturnsAsync(orderUuid)
            .ReturnsAsync(string.Empty);

        var plugin = MakePlugin(mockClient, certDataReader);
        var productInfo = ProductInfo(parameters: new Dictionary<string, string>
        {
            ["PriorCertSN"] = "ABC123",
            ["Applicant Last Name"] = "Doe"
        });

        var result = await plugin.Enroll("csr", "CN=test", new Dictionary<string, string[]>(), productInfo,
            RequestFormat.PKCS10, EnrollmentType.RenewOrReissue);

        Assert.NotEqual((int)EndEntityStatus.EXTERNALVALIDATION, result.Status);
        Assert.Contains("could not resolve prior certificate serial number", result.StatusMessage);
    }

    [Fact]
    public async Task Enroll_RenewOrReissue_ReissueRequestIdTooShort_ReturnsFailure()
    {
        var orderUuid = Guid.NewGuid().ToString();
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitGetCustomFields()).ReturnsAsync(new List<GetCustomField>());
        mockClient.Setup(c => c.SubmitGetCertificateAsync(orderUuid)).ReturnsAsync(new CertificateResponse
        {
            OrderDate = DateTime.UtcNow.ToString("o")
        });

        var certDataReader = new Mock<ICertificateDataReader>();
        certDataReader.SetupSequence(r => r.GetRequestIDBySerialNumber("ABC123"))
            .ReturnsAsync(orderUuid)
            .ReturnsAsync("too-short");

        var plugin = MakePlugin(mockClient, certDataReader);
        var productInfo = ProductInfo(parameters: new Dictionary<string, string>
        {
            ["PriorCertSN"] = "ABC123",
            ["Applicant Last Name"] = "Doe"
        });

        var result = await plugin.Enroll("csr", "CN=test", new Dictionary<string, string[]>(), productInfo,
            RequestFormat.PKCS10, EnrollmentType.RenewOrReissue);

        Assert.NotEqual((int)EndEntityStatus.EXTERNALVALIDATION, result.Status);
        Assert.Contains("too short to extract a UUID", result.StatusMessage);
    }

    [Fact]
    public async Task Enroll_RenewOrReissue_ReissueNullResponse_ReturnsFailure()
    {
        var orderUuid = Guid.NewGuid().ToString();
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitGetCustomFields()).ReturnsAsync(new List<GetCustomField>());
        mockClient.Setup(c => c.SubmitGetCertificateAsync(orderUuid)).ReturnsAsync(new CertificateResponse
        {
            OrderDate = DateTime.UtcNow.ToString("o")
        });
        mockClient.Setup(c => c.SubmitReissueAsync(It.IsAny<ReissueRequest>())).ReturnsAsync((ReissueResponse)null!);

        var certDataReader = new Mock<ICertificateDataReader>();
        certDataReader.Setup(r => r.GetRequestIDBySerialNumber("ABC123")).ReturnsAsync(orderUuid);

        var plugin = MakePlugin(mockClient, certDataReader);
        var productInfo = ProductInfo(parameters: new Dictionary<string, string>
        {
            ["PriorCertSN"] = "ABC123",
            ["Applicant Last Name"] = "Doe"
        });

        var result = await plugin.Enroll("csr", "CN=test", new Dictionary<string, string[]>(), productInfo,
            RequestFormat.PKCS10, EnrollmentType.RenewOrReissue);

        Assert.NotEqual((int)EndEntityStatus.EXTERNALVALIDATION, result.Status);
        Assert.Contains("CSC API returned a null response", result.StatusMessage);
    }

    [Fact]
    public async Task Enroll_RenewOrReissue_FetchLiveCertThrows_FallsBackToExpiryCheck()
    {
        var orderUuid = Guid.NewGuid().ToString();
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitGetCustomFields()).ReturnsAsync(new List<GetCustomField>());
        mockClient.SetupSequence(c => c.SubmitGetCertificateAsync(orderUuid))
            .ThrowsAsync(new InvalidOperationException("network error"));
        mockClient.Setup(c => c.SubmitReissueAsync(It.IsAny<ReissueRequest>())).ReturnsAsync(new ReissueResponse
        {
            Result = new Result { CommonName = "fallback.example.com", Status = new Status { Uuid = orderUuid } }
        });

        var certDataReader = new Mock<ICertificateDataReader>();
        certDataReader.Setup(r => r.GetRequestIDBySerialNumber("ABC123")).ReturnsAsync(orderUuid);
        certDataReader.Setup(r => r.GetExpirationDateByRequestId(orderUuid)).Returns(DateTime.Now.AddDays(30));

        var plugin = MakePlugin(mockClient, certDataReader);
        var productInfo = ProductInfo(parameters: new Dictionary<string, string>
        {
            ["PriorCertSN"] = "ABC123",
            ["Applicant Last Name"] = "Doe"
        });

        var result = await plugin.Enroll("csr", "CN=test", new Dictionary<string, string[]>(), productInfo,
            RequestFormat.PKCS10, EnrollmentType.RenewOrReissue);

        Assert.Equal((int)EndEntityStatus.EXTERNALVALIDATION, result.Status);
    }

    [Fact]
    public async Task Enroll_RenewOrReissue_NoOrderDateAndNoExpirationDateOnReader_FallsThroughToSingleRecordLookup()
    {
        var orderUuid = Guid.NewGuid().ToString();
        var mockClient = new Mock<ICscGlobalClient>();
        mockClient.Setup(c => c.SubmitGetCustomFields()).ReturnsAsync(new List<GetCustomField>());
        // No OrderDate -> falls back to expiry check. GetExpirationDateByRequestId (below) returns
        // null, so the fallback's "??" actually has to call GetSingleRecord for a second time to
        // get a RevocationDate - which is never set by GetSingleRecord, so it stays null and the
        // nullable "<" comparison evaluates to false (not a renewal).
        mockClient.Setup(c => c.SubmitGetCertificateAsync(orderUuid)).ReturnsAsync(new CertificateResponse
        {
            OrderDate = null,
            Status = "ACTIVE"
        });
        mockClient.Setup(c => c.SubmitReissueAsync(It.IsAny<ReissueRequest>())).ReturnsAsync(new ReissueResponse
        {
            Result = new Result { CommonName = "reissue.example.com", Status = new Status { Uuid = orderUuid } }
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

        Assert.Equal((int)EndEntityStatus.EXTERNALVALIDATION, result.Status);
        mockClient.Verify(c => c.SubmitReissueAsync(It.IsAny<ReissueRequest>()), Times.Once);
    }
}
