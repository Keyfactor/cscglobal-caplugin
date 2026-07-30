// Copyright 2021 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System.Net;
using System.Net.Http.Headers;
using System.Text;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.CSCGlobal.Client.Models;
using Keyfactor.Extensions.CAPlugin.CSCGlobal.Interfaces;
using Keyfactor.Logging;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;

namespace Keyfactor.Extensions.CAPlugin.CSCGlobal.Client;

public sealed class CscGlobalClient : ICscGlobalClient
{
    private readonly ILogger Logger;

    public CscGlobalClient(IAnyCAPluginConfigProvider config)
    {
        Logger = LogHandler.GetClassLogger<CscGlobalClient>();

        if (config == null)
            throw new ArgumentNullException(nameof(config), "config cannot be null in CscGlobalClient constructor.");

        if (config.CAConnectionData == null)
            throw new InvalidOperationException("CAConnectionData is null on config provider.");

        Logger.LogTrace("CscGlobalClient: CAConnectionData keys=[{Keys}]", string.Join(", ", config.CAConnectionData.Keys));

        if (config.CAConnectionData.ContainsKey(Constants.CscGlobalApiKey))
        {
            var rawUrl = config.CAConnectionData.ContainsKey(Constants.CscGlobalUrl)
                ? config.CAConnectionData[Constants.CscGlobalUrl]?.ToString()
                : null;
            if (string.IsNullOrEmpty(rawUrl))
            {
                Logger.LogError("CscGlobalClient: CscGlobalUrl is missing or empty in CAConnectionData.");
                throw new InvalidOperationException("CscGlobalUrl is required but was not configured.");
            }

            Logger.LogTrace("CscGlobalClient: BaseUrl='{BaseUrl}'", rawUrl);
            BaseUrl = new Uri(rawUrl);

            ApiKey = config.CAConnectionData[Constants.CscGlobalApiKey]?.ToString();
            if (string.IsNullOrEmpty(ApiKey))
            {
                Logger.LogError("CscGlobalClient: ApiKey is empty or null.");
                throw new InvalidOperationException("ApiKey is required but was not configured.");
            }
            Logger.LogTrace("CscGlobalClient: ApiKey is present (length={Length}).", ApiKey.Length);

            if (!config.CAConnectionData.ContainsKey(Constants.BearerToken))
            {
                Logger.LogError("CscGlobalClient: BearerToken key not found in CAConnectionData.");
                throw new InvalidOperationException("BearerToken is required but was not configured.");
            }
            Authorization = config.CAConnectionData[Constants.BearerToken]?.ToString();
            if (string.IsNullOrEmpty(Authorization))
            {
                Logger.LogError("CscGlobalClient: BearerToken is empty or null.");
                throw new InvalidOperationException("BearerToken is required but was empty.");
            }
            Logger.LogTrace("CscGlobalClient: BearerToken is present (length={Length}).", Authorization.Length);

            RestClient = ConfigureRestClient();
            Logger.LogTrace("CscGlobalClient: RestClient configured successfully.");
        }
        else
        {
            Logger.LogError("CscGlobalClient: ApiKey key '{Key}' not found in CAConnectionData. Client will not be functional.", Constants.CscGlobalApiKey);
            throw new InvalidOperationException($"Required key '{Constants.CscGlobalApiKey}' not found in CAConnectionData.");
        }
    }

    private Uri BaseUrl { get; }
    private HttpClient RestClient { get; }
    private string ApiKey { get; }
    private string Authorization { get; }

    public async Task<RegistrationResponse> SubmitRegistrationAsync(
        RegistrationRequest registerRequest)
    {
        Logger.LogTrace("SubmitRegistrationAsync: sending registration request...");
        if (registerRequest == null)
            throw new ArgumentNullException(nameof(registerRequest));

        var requestJson = JsonConvert.SerializeObject(registerRequest);
        Logger.LogTrace("SubmitRegistrationAsync: request JSON: {Json}", requestJson);

        using (var resp = await RestClient.PostAsync("/dbs/api/v2/tls/registration", new StringContent(
                   requestJson, Encoding.ASCII, "application/json")))
        {
            var rawBody = await resp.Content.ReadAsStringAsync();
            Logger.LogTrace("SubmitRegistrationAsync: HTTP {StatusCode}, body length={Length}", (int)resp.StatusCode, rawBody?.Length ?? 0);
            Logger.LogTrace("SubmitRegistrationAsync: response body: {Body}", rawBody ?? "(null)");

            var settings = new JsonSerializerSettings { NullValueHandling = NullValueHandling.Ignore };
            if (resp.StatusCode == HttpStatusCode.BadRequest)
            {
                Logger.LogWarning("SubmitRegistrationAsync: received 400 BadRequest.");
                var errorResponse = JsonConvert.DeserializeObject<RegistrationError>(rawBody ?? "{}", settings);
                Logger.LogTrace("SubmitRegistrationAsync: error description='{Desc}'", errorResponse?.Description ?? "(null)");
                var response = new RegistrationResponse();
                response.RegistrationError = errorResponse;
                response.Result = null;
                return response;
            }

            if (!resp.IsSuccessStatusCode)
            {
                Logger.LogError("SubmitRegistrationAsync: unexpected HTTP {StatusCode}: {Body}", (int)resp.StatusCode, rawBody);
                throw new HttpRequestException($"SubmitRegistrationAsync failed with HTTP {(int)resp.StatusCode}: {rawBody}");
            }

            var registrationResponse = JsonConvert.DeserializeObject<RegistrationResponse>(rawBody ?? "{}", settings);
            Logger.LogTrace("SubmitRegistrationAsync: deserialized response. Result is {Null}, RegistrationError is {Null2}",
                registrationResponse?.Result == null ? "null" : "present",
                registrationResponse?.RegistrationError == null ? "null" : "present");
            return registrationResponse;
        }
    }

    public async Task<RenewalResponse> SubmitRenewalAsync(
        RenewalRequest renewalRequest)
    {
        Logger.LogTrace("SubmitRenewalAsync: sending renewal request...");
        if (renewalRequest == null)
            throw new ArgumentNullException(nameof(renewalRequest));

        var requestJson = JsonConvert.SerializeObject(renewalRequest);
        Logger.LogTrace("SubmitRenewalAsync: request JSON: {Json}", requestJson);

        using (var resp = await RestClient.PostAsync("/dbs/api/v2/tls/renewal", new StringContent(
                   requestJson, Encoding.ASCII, "application/json")))
        {
            var rawBody = await resp.Content.ReadAsStringAsync();
            Logger.LogTrace("SubmitRenewalAsync: HTTP {StatusCode}, body length={Length}", (int)resp.StatusCode, rawBody?.Length ?? 0);
            Logger.LogTrace("SubmitRenewalAsync: response body: {Body}", rawBody ?? "(null)");

            var settings = new JsonSerializerSettings { NullValueHandling = NullValueHandling.Ignore };
            if (resp.StatusCode == HttpStatusCode.BadRequest)
            {
                Logger.LogWarning("SubmitRenewalAsync: received 400 BadRequest.");
                var errorResponse = JsonConvert.DeserializeObject<RegistrationError>(rawBody ?? "{}", settings);
                Logger.LogTrace("SubmitRenewalAsync: error description='{Desc}'", errorResponse?.Description ?? "(null)");
                var response = new RenewalResponse();
                response.RegistrationError = errorResponse;
                response.Result = null;
                return response;
            }

            if (!resp.IsSuccessStatusCode)
            {
                Logger.LogError("SubmitRenewalAsync: unexpected HTTP {StatusCode}: {Body}", (int)resp.StatusCode, rawBody);
                throw new HttpRequestException($"SubmitRenewalAsync failed with HTTP {(int)resp.StatusCode}: {rawBody}");
            }

            var renewalResponse = JsonConvert.DeserializeObject<RenewalResponse>(rawBody ?? "{}");
            Logger.LogTrace("SubmitRenewalAsync: deserialized response. Result is {Null}, RegistrationError is {Null2}",
                renewalResponse?.Result == null ? "null" : "present",
                renewalResponse?.RegistrationError == null ? "null" : "present");
            return renewalResponse;
        }
    }

    public async Task<ReissueResponse> SubmitReissueAsync(
        ReissueRequest reissueRequest)
    {
        Logger.LogTrace("SubmitReissueAsync: sending reissue request...");
        if (reissueRequest == null)
            throw new ArgumentNullException(nameof(reissueRequest));

        var requestJson = JsonConvert.SerializeObject(reissueRequest);
        Logger.LogTrace("SubmitReissueAsync: request JSON: {Json}", requestJson);

        using (var resp = await RestClient.PostAsync("/dbs/api/v2/tls/reissue", new StringContent(
                   requestJson, Encoding.ASCII, "application/json")))
        {
            var rawBody = await resp.Content.ReadAsStringAsync();
            Logger.LogTrace("SubmitReissueAsync: HTTP {StatusCode}, body length={Length}", (int)resp.StatusCode, rawBody?.Length ?? 0);
            Logger.LogTrace("SubmitReissueAsync: response body: {Body}", rawBody ?? "(null)");

            var settings = new JsonSerializerSettings { NullValueHandling = NullValueHandling.Ignore };
            if (resp.StatusCode == HttpStatusCode.BadRequest)
            {
                Logger.LogWarning("SubmitReissueAsync: received 400 BadRequest.");
                var errorResponse = JsonConvert.DeserializeObject<RegistrationError>(rawBody ?? "{}", settings);
                Logger.LogTrace("SubmitReissueAsync: error description='{Desc}'", errorResponse?.Description ?? "(null)");
                var response = new ReissueResponse();
                response.RegistrationError = errorResponse;
                response.Result = null;
                return response;
            }

            if (!resp.IsSuccessStatusCode)
            {
                Logger.LogError("SubmitReissueAsync: unexpected HTTP {StatusCode}: {Body}", (int)resp.StatusCode, rawBody);
                throw new HttpRequestException($"SubmitReissueAsync failed with HTTP {(int)resp.StatusCode}: {rawBody}");
            }

            var reissueResponse = JsonConvert.DeserializeObject<ReissueResponse>(rawBody ?? "{}");
            Logger.LogTrace("SubmitReissueAsync: deserialized response. Result is {Null}, RegistrationError is {Null2}",
                reissueResponse?.Result == null ? "null" : "present",
                reissueResponse?.RegistrationError == null ? "null" : "present");
            return reissueResponse;
        }
    }

    public async Task<CertificateResponse> SubmitGetCertificateAsync(string certificateId)
    {
        Logger.LogTrace("SubmitGetCertificateAsync: fetching certificate for id='{CertificateId}'", certificateId ?? "(null)");

        if (string.IsNullOrEmpty(certificateId))
            throw new ArgumentNullException(nameof(certificateId), "certificateId cannot be null or empty.");

        using (var resp = await RestClient.GetAsync($"/dbs/api/v2/tls/certificate/{certificateId}"))
        {
            var rawBody = await resp.Content.ReadAsStringAsync();
            Logger.LogTrace("SubmitGetCertificateAsync: HTTP {StatusCode}, body length={Length}", (int)resp.StatusCode, rawBody?.Length ?? 0);

            if (!resp.IsSuccessStatusCode)
            {
                Logger.LogError("SubmitGetCertificateAsync: HTTP {StatusCode} for certificateId='{CertificateId}': {Body}",
                    (int)resp.StatusCode, certificateId, rawBody);
                resp.EnsureSuccessStatusCode(); // will throw
            }

            Logger.LogTrace("SubmitGetCertificateAsync: response body: {Body}", rawBody ?? "(null)");
            var getCertificateResponse = JsonConvert.DeserializeObject<CertificateResponse>(rawBody ?? "{}");
            Logger.LogTrace("SubmitGetCertificateAsync: deserialized. Status='{Status}', OrderDate='{OrderDate}', Certificate is {Null}",
                getCertificateResponse?.Status ?? "(null)",
                getCertificateResponse?.OrderDate ?? "(null)",
                string.IsNullOrEmpty(getCertificateResponse?.Certificate) ? "empty/null" : "present");
            return getCertificateResponse;
        }
    }

    public async Task<List<GetCustomField>> SubmitGetCustomFields()
    {
        Logger.LogTrace("SubmitGetCustomFields: fetching custom fields...");

        using (var resp = await RestClient.GetAsync("/dbs/api/v2/admin/customfields"))
        {
            var rawBody = await resp.Content.ReadAsStringAsync();
            Logger.LogTrace("SubmitGetCustomFields: HTTP {StatusCode}, body length={Length}", (int)resp.StatusCode, rawBody?.Length ?? 0);

            if (!resp.IsSuccessStatusCode)
            {
                Logger.LogError("SubmitGetCustomFields: HTTP {StatusCode}: {Body}", (int)resp.StatusCode, rawBody);
                resp.EnsureSuccessStatusCode(); // will throw
            }

            Logger.LogTrace("SubmitGetCustomFields: response body: {Body}", rawBody ?? "(null)");
            var getCustomFieldsResponse = JsonConvert.DeserializeObject<GetCustomFields>(rawBody ?? "{}");

            if (getCustomFieldsResponse == null)
            {
                Logger.LogWarning("SubmitGetCustomFields: deserialized response is null, returning empty list.");
                return new List<GetCustomField>();
            }

            if (getCustomFieldsResponse.CustomFields == null)
            {
                Logger.LogWarning("SubmitGetCustomFields: CustomFields property is null, returning empty list.");
                return new List<GetCustomField>();
            }

            Logger.LogTrace("SubmitGetCustomFields: received {Count} custom fields.", getCustomFieldsResponse.CustomFields.Count);
            return getCustomFieldsResponse.CustomFields;
        }
    }

    public async Task<RevokeResponse> SubmitRevokeCertificateAsync(string uuId)
    {
        Logger.LogTrace("SubmitRevokeCertificateAsync: revoking certificate UUID='{Uuid}'", uuId ?? "(null)");

        if (string.IsNullOrEmpty(uuId))
            throw new ArgumentNullException(nameof(uuId), "uuId cannot be null or empty.");

        using (var resp = await RestClient.PutAsync($"/dbs/api/v2/tls/revoke/{uuId}", new StringContent("")))
        {
            var rawBody = await resp.Content.ReadAsStringAsync();
            Logger.LogTrace("SubmitRevokeCertificateAsync: HTTP {StatusCode}, body length={Length}", (int)resp.StatusCode, rawBody?.Length ?? 0);
            Logger.LogTrace("SubmitRevokeCertificateAsync: response body: {Body}", rawBody ?? "(null)");

            var settings = new JsonSerializerSettings { NullValueHandling = NullValueHandling.Ignore };
            if (resp.StatusCode == HttpStatusCode.BadRequest)
            {
                Logger.LogWarning("SubmitRevokeCertificateAsync: received 400 BadRequest for UUID='{Uuid}'.", uuId);
                var errorResponse = JsonConvert.DeserializeObject<RegistrationError>(rawBody ?? "{}", settings);
                Logger.LogTrace("SubmitRevokeCertificateAsync: error description='{Desc}'", errorResponse?.Description ?? "(null)");
                var response = new RevokeResponse();
                response.RegistrationError = errorResponse;
                response.RevokeSuccess = null;
                return response;
            }

            if (!resp.IsSuccessStatusCode)
            {
                Logger.LogError("SubmitRevokeCertificateAsync: unexpected HTTP {StatusCode} for UUID='{Uuid}': {Body}", (int)resp.StatusCode, uuId, rawBody);
                throw new HttpRequestException($"SubmitRevokeCertificateAsync failed with HTTP {(int)resp.StatusCode}: {rawBody}");
            }

            var getRevokeResponse = JsonConvert.DeserializeObject<RevokeResponse>(rawBody ?? "{}");
            Logger.LogTrace("SubmitRevokeCertificateAsync: deserialized. RevokeSuccess is {Null}, RegistrationError is {Null2}",
                getRevokeResponse?.RevokeSuccess == null ? "null" : "present",
                getRevokeResponse?.RegistrationError == null ? "null" : "present");
            return getRevokeResponse;
        }
    }

    public async Task<CertificateListResponse> SubmitCertificateListRequestAsync(string? dateFilter = null)
    {
        Logger.MethodEntry(LogLevel.Debug);
        Logger.LogTrace("SubmitCertificateListRequestAsync: dateFilter='{DateFilter}'", dateFilter ?? "(null)");

        var filterQuery = "filter=status=in=(ACTIVE,REVOKED)";
        if (!string.IsNullOrEmpty(dateFilter))
        {
            filterQuery += $";effectiveDate=ge={dateFilter}";
        }
        Logger.LogTrace("SubmitCertificateListRequestAsync: filter query: {FilterQuery}", filterQuery);

        var resp = RestClient.GetAsync($"/dbs/api/v2/tls/certificate?{filterQuery}").Result;
        var rawBody = await resp.Content.ReadAsStringAsync();
        Logger.LogTrace("SubmitCertificateListRequestAsync: HTTP {StatusCode}, body length={Length}", (int)resp.StatusCode, rawBody?.Length ?? 0);

        if (!resp.IsSuccessStatusCode)
        {
            Logger.LogError(
                "SubmitCertificateListRequestAsync: failed request. StatusCode={StatusCode}, Body={Body}",
                (int)resp.StatusCode, rawBody);
        }

        var certificateListResponse = JsonConvert.DeserializeObject<CertificateListResponse>(rawBody ?? "{}");

        if (certificateListResponse == null)
        {
            Logger.LogWarning("SubmitCertificateListRequestAsync: deserialized response is null.");
            return new CertificateListResponse();
        }

        Logger.LogTrace("SubmitCertificateListRequestAsync: Results count={Count}",
            certificateListResponse.Results?.Count ?? 0);
        Logger.MethodExit(LogLevel.Debug);
        return certificateListResponse;
    }

    private HttpClient ConfigureRestClient()
    {
        var clientHandler = new HttpClientHandler();
        var returnClient = new HttpClient(clientHandler, true)
        {
            BaseAddress = BaseUrl
        };
        returnClient.DefaultRequestHeaders.Accept.Add(
            new MediaTypeWithQualityHeaderValue("application/json")
        );
        returnClient.DefaultRequestHeaders.Add("Authorization", "Bearer " + Authorization);
        returnClient.DefaultRequestHeaders.Add("apikey", ApiKey);
        return returnClient;
    }
}