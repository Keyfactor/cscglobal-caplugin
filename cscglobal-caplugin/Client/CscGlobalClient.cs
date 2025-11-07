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
        Logger = LogHandler.GetClassLogger<CSCGlobalCAPlugin>();
        if (config.CAConnectionData.ContainsKey(Constants.CscGlobalApiKey))
        {
            BaseUrl = new Uri(config.CAConnectionData[Constants.CscGlobalUrl].ToString());
            ApiKey = config.CAConnectionData[Constants.CscGlobalApiKey].ToString();
            Authorization = config.CAConnectionData[Constants.BearerToken].ToString();
            RestClient = ConfigureRestClient();
        }
    }

    private Uri BaseUrl { get; }
    private HttpClient RestClient { get; }
    private string ApiKey { get; }
    private string Authorization { get; }

    public async Task<RegistrationResponse> SubmitRegistrationAsync(
        RegistrationRequest registerRequest)
    {
        using (var resp = await RestClient.PostAsync("/dbs/api/v2/tls/registration", new StringContent(
                   JsonConvert.SerializeObject(registerRequest), Encoding.ASCII, "application/json")))
        {
            Logger.LogTrace(JsonConvert.SerializeObject(registerRequest));
            var settings = new JsonSerializerSettings { NullValueHandling = NullValueHandling.Ignore };
            if (resp.StatusCode == HttpStatusCode.BadRequest) //Csc Sends Errors back in 400 Json Response
            {
                var errorResponse =
                    JsonConvert.DeserializeObject<RegistrationError>(await resp.Content.ReadAsStringAsync(),
                        settings);
                var response = new RegistrationResponse();
                response.RegistrationError = errorResponse;
                response.Result = null;
                return response;
            }

            var registrationResponse =
                JsonConvert.DeserializeObject<RegistrationResponse>(await resp.Content.ReadAsStringAsync(),
                    settings);
            return registrationResponse;
        }
    }

    public async Task<RenewalResponse> SubmitRenewalAsync(
        RenewalRequest renewalRequest)
    {
        using (var resp = await RestClient.PostAsync("/dbs/api/v2/tls/renewal", new StringContent(
                   JsonConvert.SerializeObject(renewalRequest), Encoding.ASCII, "application/json")))
        {
            Logger.LogTrace(JsonConvert.SerializeObject(renewalRequest));

            var settings = new JsonSerializerSettings { NullValueHandling = NullValueHandling.Ignore };
            if (resp.StatusCode == HttpStatusCode.BadRequest) //Csc Sends Errors back in 400 Json Response
            {
                var rawErrorResponse = await resp.Content.ReadAsStringAsync();
                Logger.LogTrace("Logging Error Response Raw");
                Logger.LogTrace(rawErrorResponse);
                var errorResponse =
                    JsonConvert.DeserializeObject<RegistrationError>(rawErrorResponse,
                        settings);
                var response = new RenewalResponse();
                response.RegistrationError = errorResponse;
                response.Result = null;
                return response;
            }

            var rawRenewResponse = await resp.Content.ReadAsStringAsync();
            Logger.LogTrace("Logging Success Response Raw");
            Logger.LogTrace(rawRenewResponse);
            var renewalResponse =
                JsonConvert.DeserializeObject<RenewalResponse>(rawRenewResponse);
            return renewalResponse;
        }
    }

    public async Task<ReissueResponse> SubmitReissueAsync(
        ReissueRequest reissueRequest)
    {
        using (var resp = await RestClient.PostAsync("/dbs/api/v2/tls/reissue", new StringContent(
                   JsonConvert.SerializeObject(reissueRequest), Encoding.ASCII, "application/json")))
        {
            Logger.LogTrace(JsonConvert.SerializeObject(reissueRequest));

            var settings = new JsonSerializerSettings { NullValueHandling = NullValueHandling.Ignore };
            if (resp.StatusCode == HttpStatusCode.BadRequest) //Csc Sends Errors back in 400 Json Response
            {
                var errorResponse =
                    JsonConvert.DeserializeObject<RegistrationError>(await resp.Content.ReadAsStringAsync(),
                        settings);
                var response = new ReissueResponse();
                response.RegistrationError = errorResponse;
                response.Result = null;
                return response;
            }

            var reissueResponse =
                JsonConvert.DeserializeObject<ReissueResponse>(await resp.Content.ReadAsStringAsync());
            return reissueResponse;
        }
    }

    public async Task<CertificateResponse> SubmitGetCertificateAsync(string certificateId)
    {
        using (var resp = await RestClient.GetAsync($"/dbs/api/v2/tls/certificate/{certificateId}"))
        {
            resp.EnsureSuccessStatusCode();
            var getCertificateResponse =
                JsonConvert.DeserializeObject<CertificateResponse>(await resp.Content.ReadAsStringAsync());
            return getCertificateResponse;
        }
    }

    public async Task<List<GetCustomField>> SubmitGetCustomFields()
    {
        using (var resp = await RestClient.GetAsync("/dbs/api/v2/admin/customfields"))
        {
            resp.EnsureSuccessStatusCode();
            var getCustomFieldsResponse =
                JsonConvert.DeserializeObject<GetCustomFields>(await resp.Content.ReadAsStringAsync());
            return getCustomFieldsResponse.CustomFields;
        }
    }

    public async Task<RevokeResponse> SubmitRevokeCertificateAsync(string uuId)
    {
        using (var resp = await RestClient.PutAsync($"/dbs/api/v2/tls/revoke/{uuId}", new StringContent("")))
        {
            var settings = new JsonSerializerSettings { NullValueHandling = NullValueHandling.Ignore };
            if (resp.StatusCode == HttpStatusCode.BadRequest) //Csc Sends Errors back in 400 Json Response
            {
                var errorResponse =
                    JsonConvert.DeserializeObject<RegistrationError>(await resp.Content.ReadAsStringAsync(),
                        settings);
                var response = new RevokeResponse();
                response.RegistrationError = errorResponse;
                response.RevokeSuccess = null;
                return response;
            }

            var getRevokeResponse =
                JsonConvert.DeserializeObject<RevokeResponse>(await resp.Content.ReadAsStringAsync());
            return getRevokeResponse;
        }
    }

    public async Task<CertificateListResponse> SubmitCertificateListRequestAsync()
    {
        Logger.MethodEntry(LogLevel.Debug);
        var resp = RestClient.GetAsync("/dbs/api/v2/tls/certificate?filter=status=in=(ACTIVE,REVOKED)").Result;

        if (!resp.IsSuccessStatusCode)
        {
            var responseMessage = resp.Content.ReadAsStringAsync().Result;
            Logger.LogError(
                $"Failed Request to Keyfactor. Retrying request. Status Code {resp.StatusCode} | Message: {responseMessage}");
        }

        var certificateListResponse =
            JsonConvert.DeserializeObject<CertificateListResponse>(await resp.Content.ReadAsStringAsync());
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