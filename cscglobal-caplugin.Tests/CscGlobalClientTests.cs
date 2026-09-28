// Copyright 2021 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.

using System.Net;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.CSCGlobal;
using Keyfactor.Extensions.CAPlugin.CSCGlobal.Client;
using Keyfactor.Extensions.CAPlugin.CSCGlobal.Client.Models;
using Moq;
using Xunit;

namespace CscGlobalCAPluginTests;

public class CscGlobalClientTests
{
    private sealed class FakeHttpMessageHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _responder;
        public HttpRequestMessage? LastRequest { get; private set; }

        public FakeHttpMessageHandler(Func<HttpRequestMessage, HttpResponseMessage> responder) => _responder = responder;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            LastRequest = request;
            return Task.FromResult(_responder(request));
        }
    }

    private static HttpResponseMessage JsonResponse(HttpStatusCode code, string json) =>
        new HttpResponseMessage(code) { Content = new StringContent(json) };

    private static Mock<IAnyCAPluginConfigProvider> ValidConfig()
    {
        var mock = new Mock<IAnyCAPluginConfigProvider>();
        mock.Setup(c => c.CAConnectionData).Returns(new Dictionary<string, object>
        {
            [Constants.CscGlobalApiKey] = "api-key",
            [Constants.CscGlobalUrl] = "https://example.invalid/",
            [Constants.BearerToken] = "bearer-token"
        });
        return mock;
    }

    private static CscGlobalClient MakeClient(Func<HttpRequestMessage, HttpResponseMessage> responder, out FakeHttpMessageHandler handler)
    {
        handler = new FakeHttpMessageHandler(responder);
        return new CscGlobalClient(ValidConfig().Object, handler);
    }

    // ---------------------------------------------------------------------
    // Constructor validation
    // ---------------------------------------------------------------------

    [Fact]
    public void Constructor_NullConfig_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => new CscGlobalClient(null!));
    }

    [Fact]
    public void Constructor_NullCAConnectionData_Throws()
    {
        var mock = new Mock<IAnyCAPluginConfigProvider>();
        mock.Setup(c => c.CAConnectionData).Returns((Dictionary<string, object>)null!);
        Assert.Throws<InvalidOperationException>(() => new CscGlobalClient(mock.Object));
    }

    [Fact]
    public void Constructor_MissingApiKey_Throws()
    {
        var mock = new Mock<IAnyCAPluginConfigProvider>();
        mock.Setup(c => c.CAConnectionData).Returns(new Dictionary<string, object>());
        Assert.Throws<InvalidOperationException>(() => new CscGlobalClient(mock.Object));
    }

    [Fact]
    public void Constructor_MissingUrl_Throws()
    {
        var mock = new Mock<IAnyCAPluginConfigProvider>();
        mock.Setup(c => c.CAConnectionData).Returns(new Dictionary<string, object>
        {
            [Constants.CscGlobalApiKey] = "api-key"
        });
        Assert.Throws<InvalidOperationException>(() => new CscGlobalClient(mock.Object));
    }

    [Fact]
    public void Constructor_EmptyApiKeyValue_Throws()
    {
        var mock = new Mock<IAnyCAPluginConfigProvider>();
        mock.Setup(c => c.CAConnectionData).Returns(new Dictionary<string, object>
        {
            [Constants.CscGlobalApiKey] = "",
            [Constants.CscGlobalUrl] = "https://example.invalid/"
        });
        Assert.Throws<InvalidOperationException>(() => new CscGlobalClient(mock.Object));
    }

    [Fact]
    public void Constructor_NullApiKeyValue_Throws()
    {
        // Key present but value is a null object (distinct from a missing key or an empty string -
        // exercises the `?.ToString()` null-conditional rather than the ContainsKey check).
        var mock = new Mock<IAnyCAPluginConfigProvider>();
        mock.Setup(c => c.CAConnectionData).Returns(new Dictionary<string, object>
        {
            [Constants.CscGlobalApiKey] = null!,
            [Constants.CscGlobalUrl] = "https://example.invalid/"
        });
        Assert.Throws<InvalidOperationException>(() => new CscGlobalClient(mock.Object));
    }

    [Fact]
    public void Constructor_NullUrlValue_Throws()
    {
        // Url key present but value is a null object (distinct from a missing key).
        var mock = new Mock<IAnyCAPluginConfigProvider>();
        mock.Setup(c => c.CAConnectionData).Returns(new Dictionary<string, object>
        {
            [Constants.CscGlobalApiKey] = "api-key",
            [Constants.CscGlobalUrl] = null!
        });
        Assert.Throws<InvalidOperationException>(() => new CscGlobalClient(mock.Object));
    }

    [Fact]
    public void Constructor_EmptyBearerTokenValue_Throws()
    {
        var mock = new Mock<IAnyCAPluginConfigProvider>();
        mock.Setup(c => c.CAConnectionData).Returns(new Dictionary<string, object>
        {
            [Constants.CscGlobalApiKey] = "api-key",
            [Constants.CscGlobalUrl] = "https://example.invalid/",
            [Constants.BearerToken] = ""
        });
        Assert.Throws<InvalidOperationException>(() => new CscGlobalClient(mock.Object));
    }

    [Fact]
    public void Constructor_NullBearerTokenValue_Throws()
    {
        // BearerToken key present but value is a null object (distinct from a missing key or an
        // empty string - exercises the `?.ToString()` null-conditional rather than ContainsKey).
        var mock = new Mock<IAnyCAPluginConfigProvider>();
        mock.Setup(c => c.CAConnectionData).Returns(new Dictionary<string, object>
        {
            [Constants.CscGlobalApiKey] = "api-key",
            [Constants.CscGlobalUrl] = "https://example.invalid/",
            [Constants.BearerToken] = null!
        });
        Assert.Throws<InvalidOperationException>(() => new CscGlobalClient(mock.Object));
    }

    [Fact]
    public void Constructor_MissingBearerToken_Throws()
    {
        var mock = new Mock<IAnyCAPluginConfigProvider>();
        mock.Setup(c => c.CAConnectionData).Returns(new Dictionary<string, object>
        {
            [Constants.CscGlobalApiKey] = "api-key",
            [Constants.CscGlobalUrl] = "https://example.invalid/"
        });
        Assert.Throws<InvalidOperationException>(() => new CscGlobalClient(mock.Object));
    }

    [Fact]
    public void Constructor_ValidConfig_DoesNotThrow()
    {
        var client = new CscGlobalClient(ValidConfig().Object, new FakeHttpMessageHandler(_ => JsonResponse(HttpStatusCode.OK, "{}")));
        Assert.NotNull(client);
    }

    // ---------------------------------------------------------------------
    // SubmitRegistrationAsync
    // ---------------------------------------------------------------------

    [Fact]
    public async Task SubmitRegistrationAsync_Success_ReturnsParsedResponse()
    {
        var client = MakeClient(_ => JsonResponse(HttpStatusCode.OK,
            "{\"result\":{\"commonName\":\"order-1\",\"price\":{\"currency\":\"USD\",\"total\":99.5}}}"), out var handler);

        var response = await client.SubmitRegistrationAsync(new RegistrationRequest());

        Assert.Equal("order-1", response.Result.CommonName);
        Assert.Contains("/dbs/api/v2/tls/registration", handler.LastRequest!.RequestUri!.ToString());
    }

    [Fact]
    public async Task SubmitRegistrationAsync_NullRequest_Throws()
    {
        var client = MakeClient(_ => JsonResponse(HttpStatusCode.OK, "{}"), out _);
        await Assert.ThrowsAsync<ArgumentNullException>(() => client.SubmitRegistrationAsync(null!));
    }

    [Fact]
    public async Task SubmitRegistrationAsync_BadRequest_ReturnsRegistrationError()
    {
        var client = MakeClient(_ => JsonResponse(HttpStatusCode.BadRequest, "{\"description\":\"denied\"}"), out _);
        var response = await client.SubmitRegistrationAsync(new RegistrationRequest());
        Assert.Equal("denied", response.RegistrationError.Description);
        Assert.Null(response.Result);
    }

    [Fact]
    public async Task SubmitRegistrationAsync_OtherError_Throws()
    {
        var client = MakeClient(_ => JsonResponse(HttpStatusCode.InternalServerError, "boom"), out _);
        await Assert.ThrowsAsync<HttpRequestException>(() => client.SubmitRegistrationAsync(new RegistrationRequest()));
    }

    // ---------------------------------------------------------------------
    // SubmitRenewalAsync
    // ---------------------------------------------------------------------

    [Fact]
    public async Task SubmitRenewalAsync_Success_ReturnsParsedResponse()
    {
        var client = MakeClient(_ => JsonResponse(HttpStatusCode.OK, "{\"result\":{\"commonName\":\"renewed-1\"}}"), out var handler);
        var response = await client.SubmitRenewalAsync(new RenewalRequest());
        Assert.Equal("renewed-1", response.Result.CommonName);
        Assert.Contains("/dbs/api/v2/tls/renewal", handler.LastRequest!.RequestUri!.ToString());
    }

    [Fact]
    public async Task SubmitRenewalAsync_NullRequest_Throws()
    {
        var client = MakeClient(_ => JsonResponse(HttpStatusCode.OK, "{}"), out _);
        await Assert.ThrowsAsync<ArgumentNullException>(() => client.SubmitRenewalAsync(null!));
    }

    [Fact]
    public async Task SubmitRenewalAsync_BadRequest_ReturnsRegistrationError()
    {
        var client = MakeClient(_ => JsonResponse(HttpStatusCode.BadRequest, "{\"description\":\"denied\"}"), out _);
        var response = await client.SubmitRenewalAsync(new RenewalRequest());
        Assert.Equal("denied", response.RegistrationError.Description);
    }

    [Fact]
    public async Task SubmitRenewalAsync_OtherError_Throws()
    {
        var client = MakeClient(_ => JsonResponse(HttpStatusCode.InternalServerError, "boom"), out _);
        await Assert.ThrowsAsync<HttpRequestException>(() => client.SubmitRenewalAsync(new RenewalRequest()));
    }

    // ---------------------------------------------------------------------
    // SubmitReissueAsync
    // ---------------------------------------------------------------------

    [Fact]
    public async Task SubmitReissueAsync_Success_ReturnsParsedResponse()
    {
        var client = MakeClient(_ => JsonResponse(HttpStatusCode.OK, "{\"result\":{\"commonName\":\"reissue-1\"}}"), out var handler);
        var response = await client.SubmitReissueAsync(new ReissueRequest());
        Assert.Equal("reissue-1", response.Result.CommonName);
        Assert.Contains("/dbs/api/v2/tls/reissue", handler.LastRequest!.RequestUri!.ToString());
    }

    [Fact]
    public async Task SubmitReissueAsync_NullPriceTotal_DoesNotThrow()
    {
        // Real CSC Global response observed in production: "price.total" comes back null for a
        // reissue where the certificate is not in a reissuable status.
        var client = MakeClient(_ => JsonResponse(HttpStatusCode.OK,
            "{\"result\":{\"commonName\":\"reissue-2\",\"price\":{\"currency\":\"USD\",\"total\":null}}}"), out _);

        var response = await client.SubmitReissueAsync(new ReissueRequest());

        Assert.Equal("reissue-2", response.Result.CommonName);
        Assert.Null(response.Result.Price.Total);
    }

    [Fact]
    public async Task SubmitReissueAsync_BadRequest_ReturnsRegistrationError()
    {
        var client = MakeClient(_ => JsonResponse(HttpStatusCode.BadRequest, "{\"description\":\"denied\"}"), out _);
        var response = await client.SubmitReissueAsync(new ReissueRequest());
        Assert.Equal("denied", response.RegistrationError.Description);
    }

    [Fact]
    public async Task SubmitReissueAsync_OtherError_Throws()
    {
        var client = MakeClient(_ => JsonResponse(HttpStatusCode.InternalServerError, "boom"), out _);
        await Assert.ThrowsAsync<HttpRequestException>(() => client.SubmitReissueAsync(new ReissueRequest()));
    }

    // ---------------------------------------------------------------------
    // SubmitGetCertificateAsync
    // ---------------------------------------------------------------------

    [Fact]
    public async Task SubmitGetCertificateAsync_Success_ReturnsParsedResponse()
    {
        var client = MakeClient(_ => JsonResponse(HttpStatusCode.OK, "{\"status\":\"ACTIVE\",\"certificate\":\"abc\"}"), out var handler);
        var response = await client.SubmitGetCertificateAsync("uuid-1");
        Assert.Equal("ACTIVE", response.Status);
        Assert.Contains("/dbs/api/v2/tls/certificate/uuid-1", handler.LastRequest!.RequestUri!.ToString());
    }

    [Fact]
    public async Task SubmitGetCertificateAsync_NullId_Throws()
    {
        var client = MakeClient(_ => JsonResponse(HttpStatusCode.OK, "{}"), out _);
        await Assert.ThrowsAsync<ArgumentNullException>(() => client.SubmitGetCertificateAsync(null!));
    }

    [Fact]
    public async Task SubmitGetCertificateAsync_ErrorStatus_Throws()
    {
        var client = MakeClient(_ => JsonResponse(HttpStatusCode.NotFound, "not found"), out _);
        await Assert.ThrowsAsync<HttpRequestException>(() => client.SubmitGetCertificateAsync("uuid-1"));
    }

    // ---------------------------------------------------------------------
    // SubmitGetCustomFields
    // ---------------------------------------------------------------------

    [Fact]
    public async Task SubmitGetCustomFields_Success_ReturnsList()
    {
        var client = MakeClient(_ => JsonResponse(HttpStatusCode.OK,
            "{\"customFields\":[{\"label\":\"Field1\",\"mandatory\":true}]}"), out var handler);

        var fields = await client.SubmitGetCustomFields();

        Assert.Single(fields);
        Assert.Equal("Field1", fields[0].Label);
        Assert.Contains("/dbs/api/v2/admin/customfields", handler.LastRequest!.RequestUri!.ToString());
    }

    [Fact]
    public async Task SubmitGetCustomFields_NullCustomFieldsProperty_ReturnsEmptyList()
    {
        var client = MakeClient(_ => JsonResponse(HttpStatusCode.OK, "{}"), out _);
        var fields = await client.SubmitGetCustomFields();
        Assert.Empty(fields);
    }

    [Fact]
    public async Task SubmitGetCustomFields_NullResponseBody_ReturnsEmptyList()
    {
        var client = MakeClient(_ => JsonResponse(HttpStatusCode.OK, "null"), out _);
        var fields = await client.SubmitGetCustomFields();
        Assert.Empty(fields);
    }

    [Fact]
    public async Task SubmitGetCustomFields_ErrorStatus_Throws()
    {
        var client = MakeClient(_ => JsonResponse(HttpStatusCode.InternalServerError, "boom"), out _);
        await Assert.ThrowsAsync<HttpRequestException>(() => client.SubmitGetCustomFields());
    }

    // ---------------------------------------------------------------------
    // SubmitRevokeCertificateAsync
    // ---------------------------------------------------------------------

    [Fact]
    public async Task SubmitRevokeCertificateAsync_Success_ReturnsParsedResponse()
    {
        var client = MakeClient(_ => JsonResponse(HttpStatusCode.OK,
            "{\"revokeSuccess\":{\"status\":\"REVOKED\"}}"), out var handler);

        var response = await client.SubmitRevokeCertificateAsync("uuid-1");

        Assert.Equal("REVOKED", response.RevokeSuccess.Status);
        Assert.Contains("/dbs/api/v2/tls/revoke/uuid-1", handler.LastRequest!.RequestUri!.ToString());
    }

    [Fact]
    public async Task SubmitRevokeCertificateAsync_NullUuid_Throws()
    {
        var client = MakeClient(_ => JsonResponse(HttpStatusCode.OK, "{}"), out _);
        await Assert.ThrowsAsync<ArgumentNullException>(() => client.SubmitRevokeCertificateAsync(null!));
    }

    [Fact]
    public async Task SubmitRevokeCertificateAsync_BadRequest_ReturnsRegistrationError()
    {
        var client = MakeClient(_ => JsonResponse(HttpStatusCode.BadRequest, "{\"description\":\"already revoked\"}"), out _);
        var response = await client.SubmitRevokeCertificateAsync("uuid-1");
        Assert.Equal("already revoked", response.RegistrationError.Description);
    }

    [Fact]
    public async Task SubmitRevokeCertificateAsync_OtherError_Throws()
    {
        var client = MakeClient(_ => JsonResponse(HttpStatusCode.InternalServerError, "boom"), out _);
        await Assert.ThrowsAsync<HttpRequestException>(() => client.SubmitRevokeCertificateAsync("uuid-1"));
    }

    // ---------------------------------------------------------------------
    // SubmitCertificateListRequestAsync
    // ---------------------------------------------------------------------

    [Fact]
    public async Task SubmitCertificateListRequestAsync_NoDateFilter_ReturnsResults()
    {
        var client = MakeClient(_ => JsonResponse(HttpStatusCode.OK,
            "{\"meta\":{\"numResults\":1},\"results\":[{\"uuid\":\"u1\"}]}"), out var handler);

        var response = await client.SubmitCertificateListRequestAsync();

        Assert.Single(response.Results);
        Assert.DoesNotContain("effectiveDate", handler.LastRequest!.RequestUri!.ToString());
    }

    [Fact]
    public async Task SubmitCertificateListRequestAsync_WithDateFilter_AppendsFilterToQuery()
    {
        var client = MakeClient(_ => JsonResponse(HttpStatusCode.OK, "{\"results\":[]}"), out var handler);

        await client.SubmitCertificateListRequestAsync("2026/01/01");

        Assert.Contains("effectiveDate=ge=2026/01/01", handler.LastRequest!.RequestUri!.ToString());
    }

    [Fact]
    public async Task SubmitCertificateListRequestAsync_NullBody_ReturnsEmptyResponse()
    {
        var client = MakeClient(_ => new HttpResponseMessage(HttpStatusCode.OK), out _);
        var response = await client.SubmitCertificateListRequestAsync();
        Assert.NotNull(response);
    }

    [Fact]
    public async Task SubmitCertificateListRequestAsync_ErrorStatus_DoesNotThrow_ReturnsParsedBody()
    {
        // Unlike the other Submit* methods, this one only logs on non-success and still parses
        // whatever body came back rather than throwing.
        var client = MakeClient(_ => JsonResponse(HttpStatusCode.InternalServerError, "{\"results\":[]}"), out _);
        var response = await client.SubmitCertificateListRequestAsync();
        Assert.NotNull(response.Results);
        Assert.Empty(response.Results);
    }
}
