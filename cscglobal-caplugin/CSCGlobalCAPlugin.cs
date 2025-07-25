// Copyright 2021 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.CSCGlobal.Client;
using Keyfactor.Extensions.CAPlugin.CSCGlobal.Client.Models;
using Keyfactor.Extensions.CAPlugin.CSCGlobal.Interfaces;
using Keyfactor.Logging;
using Keyfactor.PKI.Enums.EJBCA;
using Keyfactor.PKI.X509;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Org.BouncyCastle.Pqc.Crypto.Lms;

namespace Keyfactor.Extensions.CAPlugin.CSCGlobal;

public class CSCGlobalCAPlugin : IAnyCAPlugin
{
    private readonly RequestManager _requestManager;
    private readonly ILogger Logger;
    private ICertificateDataReader _certificateDataReader;

    public CSCGlobalCAPlugin()
    {
        Logger = LogHandler.GetClassLogger<CSCGlobalCAPlugin>();
        _requestManager = new RequestManager();
    }

    private ICscGlobalClient CscGlobalClient { get; set; }

    public bool EnableTemplateSync { get; set; }

    //done
    public void Initialize(IAnyCAPluginConfigProvider configProvider, ICertificateDataReader certificateDataReader)
    {
        Logger.MethodEntry(LogLevel.Debug);
        _certificateDataReader = certificateDataReader;
        CscGlobalClient = new CscGlobalClient(configProvider);
        var templateSync = configProvider.CAConnectionData["TemplateSync"].ToString();
        if (templateSync.ToUpper() == "ON") EnableTemplateSync = true;
        Logger.MethodExit(LogLevel.Debug);
    }

    //done
    public async Task<AnyCAPluginCertificate> GetSingleRecord(string caRequestID)
    {
        try
        {
            Logger.MethodEntry(LogLevel.Debug);
            var keyfactorCaId = caRequestID?.Substring(0, 36); //todo fix to use pipe delimiter
            Logger.LogTrace($"Keyfactor Ca Id: {keyfactorCaId}");
            var certificateResponse =
                Task.Run(async () => await CscGlobalClient.SubmitGetCertificateAsync(keyfactorCaId))
                    .Result;
            
            Logger.LogTrace($"Single Cert JSON: {JsonConvert.SerializeObject(certificateResponse)}");

            var fileContent =
                Encoding.ASCII.GetString(
                    Convert.FromBase64String(certificateResponse?.Certificate ?? string.Empty));

            Logger.LogTrace($"File Content {fileContent}");
            var certData = fileContent?.Replace("\r\n", string.Empty);
            var certString = string.Empty;
            if (!string.IsNullOrEmpty(certData))
                certString = GetEndEntityCertificate(certData);
            Logger.LogTrace($"Cert String Content {certString}");

            Logger.MethodExit(LogLevel.Debug);

            return new AnyCAPluginCertificate
            {
                CARequestID = keyfactorCaId,
                Certificate = certString,
                Status = _requestManager.MapReturnStatus(certificateResponse?.Status)
            };
        }
        catch (Exception e)
        {
            throw new Exception($"Error Occurred getting single cert {e.Message}");
        }
    }

    //done
    public async Task Synchronize(BlockingCollection<AnyCAPluginCertificate> blockingBuffer, DateTime? lastSync,
        bool fullSync, CancellationToken cancelToken)
    {
        Logger.LogTrace($"Full Sync? {fullSync.ToString()}");
        Logger.MethodEntry();
        try
        {
            if (fullSync)
            {
                var certs = await CscGlobalClient.SubmitCertificateListRequestAsync();

                foreach (var currentResponseItem in certs.Results)
                {
                    cancelToken.ThrowIfCancellationRequested();
                    Logger.LogTrace($"Took Certificate ID {currentResponseItem?.Uuid} from Queue");
                    var certStatus = _requestManager.MapReturnStatus(currentResponseItem?.Status);

                    //Keyfactor sync only seems to work when there is a valid cert and I can only get Active valid certs from Csc Global
                    if (certStatus == Convert.ToInt32(EndEntityStatus.GENERATED) ||
                        certStatus == Convert.ToInt32(EndEntityStatus.REVOKED))
                    {
                        //One click renewal/reissue won't work for this implementation so there is an option to disable it by not syncing back template
                        var productId = "CscGlobal";
                        if (EnableTemplateSync) productId = currentResponseItem?.CertificateType;

                        var fileContent =
                            Encoding.ASCII.GetString(
                                Convert.FromBase64String(currentResponseItem?.Certificate ?? string.Empty));

                        if (fileContent.Length > 0)
                        {
                            Logger.LogTrace($"File Content {fileContent}");
                            var certData = fileContent.Replace("\r\n", string.Empty);
                            var certString = GetEndEntityCertificate(certData);
                            var currentCert = new X509Certificate2(Encoding.ASCII.GetBytes(certString));
                            if (certString.Length > 0)
                                blockingBuffer.Add(new AnyCAPluginCertificate
                                {
                                    CARequestID = $"{currentResponseItem?.Uuid}",
                                    Certificate = certString,
                                    //SubmissionDate = currentResponseItem?.OrderDate == null
                                    //? Convert.ToDateTime(currentCert.NotBefore)
                                    //: Convert.ToDateTime(currentResponseItem.OrderDate),
                                    Status = certStatus,
                                    ProductID = productId
                                }, cancelToken);
                        }
                    }
                }

                blockingBuffer.CompleteAdding();
            }
        }
        catch (Exception e)
        {
            Logger.LogError($"Csc Global Synchronize Task failed! {LogHandler.FlattenException(e)}");
            Logger.MethodExit();
            blockingBuffer.CompleteAdding();
            throw;
        }

        Logger.MethodExit(LogLevel.Debug);
    }

    //done
    public async Task<int> Revoke(string caRequestID, string hexSerialNumber, uint revocationReason)
    {
        try
        {
            Logger.LogTrace("Staring Revoke Method");
            var revokeResponse =
                    Task.Run(async () =>
                        await CscGlobalClient.SubmitRevokeCertificateAsync(caRequestID.Substring(0, 36))).Result
                ; //todo fix to use pipe delimiter

            Logger.LogTrace($"Revoke Response JSON: {JsonConvert.SerializeObject(revokeResponse)}");
            Logger.MethodExit(LogLevel.Debug);

            var revokeResult = _requestManager.GetRevokeResult(revokeResponse);

            if (revokeResult == (int)EndEntityStatus.FAILED)
                if (!string.IsNullOrEmpty(revokeResponse?.RegistrationError?.Description))
                    throw new HttpRequestException($"Revoke Failed with message {revokeResponse?.RegistrationError?.Description}");

            return revokeResult;
        }
        catch (Exception e)
        {
            throw new Exception($"Revoke Failed with message {e?.Message}");
        }
    }

    //do
    public async Task<EnrollmentResult> Enroll(string csr, string subject, Dictionary<string, string[]> san,
        EnrollmentProductInfo productInfo, RequestFormat requestFormat, EnrollmentType enrollmentType)
    {
        Logger.MethodEntry(LogLevel.Debug);

        RegistrationRequest enrollmentRequest;
        var priorSn = "";
        ReissueRequest reissueRequest;
        RenewalRequest renewRequest;
        if (productInfo.ProductParameters.ContainsKey("priorcertsn"))
        {
            priorSn = productInfo.ProductParameters["PriorCertSN"];
            Logger.LogDebug($"Prior cert sn: {priorSn}");
        }

        string uUId;
		var customFields = await CscGlobalClient.SubmitGetCustomFields();

		switch (enrollmentType)
        {
            case EnrollmentType.New:
                Logger.LogTrace("Entering New Enrollment");
                //If they renewed an expired cert it gets here and this will not be supported
                IRegistrationResponse enrollmentResponse;
                if (!productInfo.ProductParameters.ContainsKey("PriorCertSN"))
                {
                    enrollmentRequest = _requestManager.GetRegistrationRequest(productInfo, csr, san, customFields);
                    Logger.LogTrace($"Enrollment Request JSON: {JsonConvert.SerializeObject(enrollmentRequest)}");
                    enrollmentResponse =
                        Task.Run(async () => await CscGlobalClient.SubmitRegistrationAsync(enrollmentRequest))
                            .Result;
                    Logger.LogTrace($"Enrollment Response JSON: {JsonConvert.SerializeObject(enrollmentResponse)}");
                }
                else
                {
                    return new EnrollmentResult
                    {
                        Status = 30, //failure
                        StatusMessage = "You cannot renew and expired cert please perform an new enrollment."
                    };
                }

                Logger.MethodExit(LogLevel.Debug);
                return _requestManager.GetEnrollmentResult(enrollmentResponse);
            case EnrollmentType.RenewOrReissue:
                Logger.LogTrace("Entering Renew Enrollment");
                //Logic to determine renew vs reissue
                var renewal = false;
                var order_id = await _certificateDataReader.GetRequestIDBySerialNumber(priorSn);
                var expirationDate = _certificateDataReader.GetExpirationDateByRequestId(order_id);
                if (expirationDate == null)
                {
                    var localcert = await GetSingleRecord(order_id);
                    expirationDate = localcert.RevocationDate;
                }

                if (expirationDate < DateTime.Now) renewal = true;
                if (renewal)
                {
                    //One click won't work for this implementation b/c we are missing enrollment params
                    if (productInfo.ProductParameters.ContainsKey("Applicant Last Name"))
                    {
                        //priorCert = _certificateDataReader.get(
                        //DataConversion.HexToBytes(productInfo.ProductParameters["PriorCertSN"]));
                        //uUId = priorCert.CARequestID.Substring(0, 36); //uUId is a GUID
                        uUId = await _certificateDataReader.GetRequestIDBySerialNumber(
                            productInfo.ProductParameters["PriorCertSN"]);
                        Logger.LogTrace($"Renew uUId: {uUId}");
                        renewRequest = _requestManager.GetRenewalRequest(productInfo, uUId, csr, san, customFields);
                        Logger.LogTrace($"Renewal Request JSON: {JsonConvert.SerializeObject(renewRequest)}");
                        var renewResponse = Task.Run(async () => await CscGlobalClient.SubmitRenewalAsync(renewRequest))
                            .Result;
                        Logger.LogTrace($"Renewal Response JSON: {JsonConvert.SerializeObject(renewResponse)}");
                        Logger.MethodExit(LogLevel.Debug);
                        return _requestManager.GetRenewResponse(renewResponse);
                    }

                    return new EnrollmentResult
                    {
                        Status = 30, //failure
                        StatusMessage =
                            "One click Renew Is Not Available for this Certificate Type.  Use the configure button instead."
                    };
                }

                Logger.LogTrace("Entering Reissue Enrollment");
                //One click won't work for this implementation b/c we are missing enrollment params
                if (productInfo.ProductParameters.ContainsKey("Applicant Last Name"))
                {
                    var requestid = await _certificateDataReader.GetRequestIDBySerialNumber(
                        productInfo.ProductParameters["PriorCertSN"]);
                    uUId = requestid.Substring(0, 36); //uUId is a GUID
                    Logger.LogTrace($"Reissue uUId: {uUId}");
                    reissueRequest = _requestManager.GetReissueRequest(productInfo, uUId, csr, san, customFields);
                    Logger.LogTrace($"Reissue JSON: {JsonConvert.SerializeObject(reissueRequest)}");
                    var reissueResponse = Task.Run(async () => await CscGlobalClient.SubmitReissueAsync(reissueRequest))
                        .Result;
                    Logger.LogTrace($"Reissue Response JSON: {JsonConvert.SerializeObject(reissueResponse)}");
                    Logger.MethodExit(LogLevel.Debug);
                    return _requestManager.GetReIssueResult(reissueResponse);
                }

                return new EnrollmentResult
                {
                    Status = 30, //failure
                    StatusMessage =
                        "One click Renew Is Not Available for this Certificate Type.  Use the configure button instead."
                };
        }

        Logger.MethodExit(LogLevel.Debug);
        return null;
    }

    //done
    public async Task Ping()
    {
        Logger.MethodEntry();
        try
        {
            Logger.LogInformation("Ping request received");
        }
        catch (Exception e)
        {
            Logger.LogError($"There was an error contacting CSCGlobal: {e.Message}.");
            throw new Exception($"Error attempting to ping CSCGlobal: {e.Message}.", e);
        }

        Logger.MethodExit();
    }

    //do
    public async Task ValidateCAConnectionInfo(Dictionary<string, object> connectionInfo)
    {
    }

    //do
    public async Task ValidateProductInfo(EnrollmentProductInfo productInfo,
        Dictionary<string, object> connectionInfo)
    {
    }

    //done
    public Dictionary<string, PropertyConfigInfo> GetCAConnectorAnnotations()
    {
        return new Dictionary<string, PropertyConfigInfo>
        {
            [Constants.CscGlobalUrl] = new()
            {
                Comments = "CSCGlobal API URL",
                Hidden = false,
                DefaultValue = "",
                Type = "String"
            },
            [Constants.CscGlobalApiKey] = new()
            {
                Comments = "CSCGlobal API Key",
                Hidden = true,
                DefaultValue = "",
                Type = "String"
            },
            [Constants.BearerToken] = new()
            {
                Comments = "CSCGlobal Bearer Token",
                Hidden = true,
                DefaultValue = "",
                Type = "String"
            },
            [Constants.DefaultPageSize] = new()
            {
                Comments = "Default page size for use with the API. Default is 100",
                Hidden = false,
                DefaultValue = "100",
                Type = "String"
            },
            [Constants.TemplateSync] = new()
            {
                Comments = "Enable template sync.",
                Hidden = false,
                DefaultValue = "false",
                Type = "Bool"
            }
        };
    }

    //done
    public Dictionary<string, PropertyConfigInfo> GetTemplateParameterAnnotations()
    {
        return new Dictionary<string, PropertyConfigInfo>();
    }

    //done
    public List<string> GetProductIds()
    {
        var ProductIDs = new List<string>
        {
            "CSC TrustedSecure Premium Certificate",
            "CSC TrustedSecure EV Certificate",
            "CSC TrustedSecure UC Certificate",
            "CSC TrustedSecure Premium Wildcard Certificate",
            "CSC TrustedSecure Domain Validated SSL",
            "CSC TrustedSecure Domain Validated Wildcard SSL",
            "CSC TrustedSecure Domain Validated UC Certificate"
        };
        return ProductIDs;
    }

    #region PRIVATE

    //potential issues
    private string GetEndEntityCertificate(string certData)
    {
        var splitCerts =
            certData.Split(new[] { "-----END CERTIFICATE-----", "-----BEGIN CERTIFICATE-----" },
                StringSplitOptions.RemoveEmptyEntries);

        X509Certificate2Collection col = new X509Certificate2Collection();
        foreach (var cert in splitCerts)
        {
            Logger.LogTrace($"Split Cert Value: {cert}");
            //skip these headers that came with the split function
            if (!cert.Contains(".crt"))
            {
                col.Import(Encoding.UTF8.GetBytes(cert));
            }
        }
        Logger.LogTrace("Getting End Entity Certificate");
        var currentCert = X509Utilities.ExtractEndEntityCertificateContents(ExportCollectionToPem(col), "");
        Logger.LogTrace("Converting to Byte Array");
        var byteArray = currentCert?.Export(X509ContentType.Cert);
        Logger.LogTrace("Initializing empty string");
        var certString = string.Empty;
        if (byteArray != null)
        {
            certString = Convert.ToBase64String(byteArray);
        }
        Logger.LogTrace($"Got certificate {certString}");

        return certString;
    }
    private string ExportCollectionToPem(X509Certificate2Collection collection)
    {
        var pemBuilder = new StringBuilder();

        foreach (var cert in collection)
        {
            pemBuilder.AppendLine("-----BEGIN CERTIFICATE-----");
            pemBuilder.AppendLine(Convert.ToBase64String(cert.RawData, Base64FormattingOptions.InsertLineBreaks));
            pemBuilder.AppendLine("-----END CERTIFICATE-----");
        }

        return pemBuilder.ToString();
    }

    #endregion

    #region PUBLIC

    #endregion
}