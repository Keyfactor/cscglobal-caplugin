// Copyright 2021 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.

using System.Net;
using System.Net.Http;
using System.Text;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.CSCGlobal;
using Keyfactor.Extensions.CAPlugin.CSCGlobal.Client;
using Keyfactor.Extensions.CAPlugin.CSCGlobal.Client.Models;
using Xunit;

namespace CscGlobalCAPluginTests;

public class CscGlobalClientTests
{
    private sealed class FakeConfigProvider : IAnyCAPluginConfigProvider
    {
        public Dictionary<string, object> CAConnectionData { get; set; } = new();
    }

    private sealed class FakeHttpMessageHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _responder;

        public FakeHttpMessageHandler(Func<HttpRequestMessage, HttpResponseMessage> responder)
        {
            _responder = responder;
        }

        public HttpRequestMessage? LastRequest { get; private set; }
        public string? LastRequestBody { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            LastRequest = request;
            LastRequestBody = request.Content?.ReadAsStringAsync(cancellationToken).GetAwaiter().GetResult();
            return Task.FromResult(_responder(request));
        }
    }

    private static HttpResponseMessage JsonResponse(HttpStatusCode status, string json) =>
        new HttpResponseMessage(status) { Content = new StringContent(json, Encoding.UTF8, "application/json") };

    private static IAnyCAPluginConfigProvider ValidConfig() => new FakeConfigProvider
    {
        CAConnectionData = new Dictionary<string, object>
        {
            [Constants.CscGlobalUrl] = "https://api.csc.test",
            [Constants.CscGlobalApiKey] = "test-api-key",
            [Constants.BearerToken] = "test-bearer-token"
        }
    };

    private static CscGlobalClient MakeClient(Func<HttpRequestMessage, HttpResponseMessage> responder,
        out FakeHttpMessageHandler handler, IAnyCAPluginConfigProvider? config = null)
    {
        handler = new FakeHttpMessageHandler(responder);
        return new CscGlobalClient(config ?? ValidConfig(), handler);
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
    public async Task Constructor_NullConnectionData_DoesNotThrowButClientIsInert()
    {
        var config = new FakeConfigProvider { CAConnectionData = null! };
        var client = new CscGlobalClient(config);

        await Assert.ThrowsAsync<NullReferenceException>(() => client.SubmitGetCustomFields());
    }

    [Fact]
    public async Task Constructor_MissingApiKeyEntry_DoesNotThrowButClientIsInert()
    {
        var config = new FakeConfigProvider { CAConnectionData = new Dictionary<string, object>() };
        var client = new CscGlobalClient(config);

        await Assert.ThrowsAsync<NullReferenceException>(() => client.SubmitGetCustomFields());
    }

    // ---------------------------------------------------------------------
    // SubmitRegistrationAsync
    // ---------------------------------------------------------------------

    [Fact]
    public async Task SubmitRegistrationAsync_Success_ReturnsParsedResponse()
    {
        var client = MakeClient(_ => JsonResponse(HttpStatusCode.OK,
            "{\"result\":{\"commonName\":\"order-1\",\"price\":{\"currency\":\"USD\",\"total\":99.5}," +
            "\"dcvDetails\":[{\"domainName\":\"example.com\",\"actionNeeded\":\"N\"}]}}"), out var handler);

        var response = await client.SubmitRegistrationAsync(new RegistrationRequest());

        Assert.NotNull(response.Result);
        Assert.Equal("order-1", response.Result.CommonName);
        Assert.Equal("USD", response.Result.Price.Currency);
        Assert.Equal(99.5m, response.Result.Price.Total);
        Assert.Equal("example.com", response.Result.DcvDetails[0].DomainName);
        Assert.Equal("N", response.Result.DcvDetails[0].ActionNeeded);
        Assert.Contains("/dbs/api/v2/tls/registration", handler.LastRequest!.RequestUri!.ToString());
    }

    [Fact]
    public async Task SubmitRegistrationAsync_BadRequest_ReturnsRegistrationError()
    {
        var client = MakeClient(_ => JsonResponse(HttpStatusCode.BadRequest,
            "{\"description\":\"invalid csr\"}"), out _);

        var response = await client.SubmitRegistrationAsync(new RegistrationRequest());

        Assert.NotNull(response.RegistrationError);
        Assert.Equal("invalid csr", response.RegistrationError.Description);
        Assert.Null(response.Result);
    }

    [Fact]
    public async Task SubmitRegistrationAsync_OtherError_Throws()
    {
        var client = MakeClient(_ => JsonResponse(HttpStatusCode.InternalServerError, "boom"), out _);

        await Assert.ThrowsAsync<HttpRequestException>(() => client.SubmitRegistrationAsync(new RegistrationRequest()));
    }

    [Fact]
    public async Task SubmitRegistrationAsync_UnparsableSuccessBody_Throws()
    {
        var client = MakeClient(_ => JsonResponse(HttpStatusCode.OK, "null"), out _);

        await Assert.ThrowsAsync<InvalidOperationException>(() => client.SubmitRegistrationAsync(new RegistrationRequest()));
    }

    // ---------------------------------------------------------------------
    // SubmitRenewalAsync
    // ---------------------------------------------------------------------

    [Fact]
    public async Task SubmitRenewalAsync_Success_ReturnsParsedResponse()
    {
        var client = MakeClient(_ => JsonResponse(HttpStatusCode.OK,
            "{\"result\":{\"commonName\":\"renew-1\"}}"), out var handler);

        var response = await client.SubmitRenewalAsync(new RenewalRequest());

        Assert.Equal("renew-1", response.Result.CommonName);
        Assert.Contains("/dbs/api/v2/tls/renewal", handler.LastRequest!.RequestUri!.ToString());
    }

    [Fact]
    public async Task SubmitRenewalAsync_BadRequest_ReturnsRegistrationError()
    {
        var client = MakeClient(_ => JsonResponse(HttpStatusCode.BadRequest, "{\"description\":\"nope\"}"), out _);

        var response = await client.SubmitRenewalAsync(new RenewalRequest());

        Assert.Equal("nope", response.RegistrationError.Description);
    }

    [Fact]
    public async Task SubmitRenewalAsync_OtherError_Throws()
    {
        var client = MakeClient(_ => JsonResponse(HttpStatusCode.InternalServerError, "boom"), out _);

        await Assert.ThrowsAsync<HttpRequestException>(() => client.SubmitRenewalAsync(new RenewalRequest()));
    }

    [Fact]
    public async Task SubmitRenewalAsync_UnparsableSuccessBody_Throws()
    {
        var client = MakeClient(_ => JsonResponse(HttpStatusCode.OK, "null"), out _);

        await Assert.ThrowsAsync<InvalidOperationException>(() => client.SubmitRenewalAsync(new RenewalRequest()));
    }

    // ---------------------------------------------------------------------
    // SubmitReissueAsync
    // ---------------------------------------------------------------------

    [Fact]
    public async Task SubmitReissueAsync_Success_ReturnsParsedResponse()
    {
        var client = MakeClient(_ => JsonResponse(HttpStatusCode.OK,
            "{\"result\":{\"commonName\":\"reissue-1\"}}"), out var handler);

        var response = await client.SubmitReissueAsync(new ReissueRequest());

        Assert.Equal("reissue-1", response.Result.CommonName);
        Assert.Contains("/dbs/api/v2/tls/reissue", handler.LastRequest!.RequestUri!.ToString());
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

    [Fact]
    public async Task SubmitReissueAsync_UnparsableSuccessBody_Throws()
    {
        var client = MakeClient(_ => JsonResponse(HttpStatusCode.OK, "null"), out _);

        await Assert.ThrowsAsync<InvalidOperationException>(() => client.SubmitReissueAsync(new ReissueRequest()));
    }

    // ---------------------------------------------------------------------
    // SubmitGetCertificateAsync
    // ---------------------------------------------------------------------

    [Fact]
    public async Task SubmitGetCertificateAsync_Success_ReturnsParsedResponse()
    {
        var client = MakeClient(_ => JsonResponse(HttpStatusCode.OK, "{\"certificate\":\"abc123\"}"), out var handler);

        var response = await client.SubmitGetCertificateAsync("cert-uuid");

        Assert.Equal("abc123", response.Certificate);
        Assert.Contains("/dbs/api/v2/tls/certificate/cert-uuid", handler.LastRequest!.RequestUri!.ToString());
    }

    [Fact]
    public async Task SubmitGetCertificateAsync_Failure_Throws()
    {
        var client = MakeClient(_ => JsonResponse(HttpStatusCode.NotFound, "not found"), out _);

        await Assert.ThrowsAsync<HttpRequestException>(() => client.SubmitGetCertificateAsync("missing-uuid"));
    }

    [Fact]
    public async Task SubmitGetCertificateAsync_UnparsableSuccessBody_Throws()
    {
        var client = MakeClient(_ => JsonResponse(HttpStatusCode.OK, "null"), out _);

        await Assert.ThrowsAsync<InvalidOperationException>(() => client.SubmitGetCertificateAsync("cert-uuid"));
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
    public async Task SubmitGetCustomFields_NullCustomFieldsArray_ReturnsEmptyList()
    {
        var client = MakeClient(_ => JsonResponse(HttpStatusCode.OK, "{}"), out _);

        var fields = await client.SubmitGetCustomFields();

        Assert.Empty(fields);
    }

    [Fact]
    public async Task SubmitGetCustomFields_Failure_Throws()
    {
        var client = MakeClient(_ => JsonResponse(HttpStatusCode.InternalServerError, "boom"), out _);

        await Assert.ThrowsAsync<HttpRequestException>(() => client.SubmitGetCustomFields());
    }

    [Fact]
    public async Task SubmitGetCustomFields_UnparsableBody_Throws()
    {
        var client = MakeClient(_ => JsonResponse(HttpStatusCode.OK, "null"), out _);

        await Assert.ThrowsAsync<InvalidOperationException>(() => client.SubmitGetCustomFields());
    }

    // ---------------------------------------------------------------------
    // SubmitRevokeCertificateAsync
    // ---------------------------------------------------------------------

    [Fact]
    public async Task SubmitRevokeCertificateAsync_Success_ReturnsParsedResponse()
    {
        var client = MakeClient(_ => JsonResponse(HttpStatusCode.OK,
            "{\"revokeSuccess\":{\"commonName\":\"revoked.example.com\",\"certificateType\":\"4\",\"status\":\"REVOKED\"}}"), out var handler);

        var response = await client.SubmitRevokeCertificateAsync("revoke-uuid");

        Assert.Equal("revoked.example.com", response.RevokeSuccess.CommonName);
        Assert.Equal("4", response.RevokeSuccess.CertificateType);
        Assert.Equal("REVOKED", response.RevokeSuccess.Status);
        Assert.Contains("/dbs/api/v2/tls/revoke/revoke-uuid", handler.LastRequest!.RequestUri!.ToString());
    }

    [Fact]
    public async Task SubmitRevokeCertificateAsync_BadRequest_ReturnsRegistrationError()
    {
        var client = MakeClient(_ => JsonResponse(HttpStatusCode.BadRequest, "{\"description\":\"already revoked\"}"), out _);

        var response = await client.SubmitRevokeCertificateAsync("revoke-uuid");

        Assert.Equal("already revoked", response.RegistrationError.Description);
    }

    [Fact]
    public async Task SubmitRevokeCertificateAsync_OtherError_Throws()
    {
        var client = MakeClient(_ => JsonResponse(HttpStatusCode.InternalServerError, "boom"), out _);

        await Assert.ThrowsAsync<HttpRequestException>(() => client.SubmitRevokeCertificateAsync("revoke-uuid"));
    }

    [Fact]
    public async Task SubmitRevokeCertificateAsync_UnparsableSuccessBody_Throws()
    {
        var client = MakeClient(_ => JsonResponse(HttpStatusCode.OK, "null"), out _);

        await Assert.ThrowsAsync<InvalidOperationException>(() => client.SubmitRevokeCertificateAsync("revoke-uuid"));
    }

    // ---------------------------------------------------------------------
    // SubmitCertificateListRequestAsync
    // ---------------------------------------------------------------------

    [Fact]
    public async Task SubmitCertificateListRequestAsync_NoDateFilter_Success()
    {
        var client = MakeClient(_ => JsonResponse(HttpStatusCode.OK,
            "{\"meta\":{\"numResults\":1},\"results\":[{\"uuid\":\"cert-1\"}]}"), out var handler);

        var response = await client.SubmitCertificateListRequestAsync();

        Assert.Single(response.Results);
        Assert.Equal(1, response.Meta.NumResults);
        Assert.DoesNotContain("effectiveDate", handler.LastRequest!.RequestUri!.ToString());
    }

    [Fact]
    public async Task SubmitCertificateListRequestAsync_WithDateFilter_IncludesFilterInQuery()
    {
        var client = MakeClient(_ => JsonResponse(HttpStatusCode.OK, "{\"results\":[]}"), out var handler);

        await client.SubmitCertificateListRequestAsync("2026/01/01");

        Assert.Contains("effectiveDate=ge=2026/01/01", handler.LastRequest!.RequestUri!.ToString());
    }

    [Fact]
    public async Task SubmitCertificateListRequestAsync_Failure_Throws()
    {
        var client = MakeClient(_ => JsonResponse(HttpStatusCode.InternalServerError, "boom"), out _);

        await Assert.ThrowsAsync<HttpRequestException>(() => client.SubmitCertificateListRequestAsync());
    }

    [Fact]
    public async Task SubmitCertificateListRequestAsync_UnparsableBody_Throws()
    {
        var client = MakeClient(_ => JsonResponse(HttpStatusCode.OK, "null"), out _);

        await Assert.ThrowsAsync<InvalidOperationException>(() => client.SubmitCertificateListRequestAsync());
    }
}
