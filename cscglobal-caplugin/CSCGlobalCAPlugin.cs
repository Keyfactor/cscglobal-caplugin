// Copyright 2021 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.CSCGlobal.Client;
using Keyfactor.Extensions.CAPlugin.CSCGlobal.Client.Models;
using Keyfactor.Extensions.CAPlugin.CSCGlobal.Interfaces;
using Keyfactor.Logging;
using Keyfactor.PKI.Enums.EJBCA;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;

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

    public int SyncFilterDays { get; set; }

    //done
    public void Initialize(IAnyCAPluginConfigProvider configProvider, ICertificateDataReader certificateDataReader)
    {
        Logger.MethodEntry(LogLevel.Debug);
        if (configProvider == null) throw new ArgumentNullException(nameof(configProvider));
        _certificateDataReader = certificateDataReader ?? throw new ArgumentNullException(nameof(certificateDataReader));
        CscGlobalClient = new CscGlobalClient(configProvider);

        if (configProvider.CAConnectionData.TryGetValue("TemplateSync", out var templateSyncValue) &&
            templateSyncValue != null &&
            string.Equals(templateSyncValue.ToString(), "ON", StringComparison.OrdinalIgnoreCase))
            EnableTemplateSync = true;
        Logger.LogInformation($"Template sync is {(EnableTemplateSync ? "enabled" : "disabled")}");

        if (configProvider.CAConnectionData.ContainsKey(Constants.SyncFilterDays))
        {
            var syncFilterDaysStr = configProvider.CAConnectionData[Constants.SyncFilterDays]?.ToString();
            if (int.TryParse(syncFilterDaysStr, out var syncFilterDays))
            {
                SyncFilterDays = syncFilterDays;
                Logger.LogDebug($"SyncFilterDays configured to {SyncFilterDays} days");
            }
            else
            {
                Logger.LogWarning($"Could not parse {Constants.SyncFilterDays} value '{syncFilterDaysStr}' as an integer; using default");
            }
        }

        Logger.LogInformation("CSCGlobalCAPlugin initialized successfully");
        Logger.MethodExit(LogLevel.Debug);
    }

    //done
    public async Task<AnyCAPluginCertificate> GetSingleRecord(string caRequestID)
    {
        try
        {
            Logger.MethodEntry(LogLevel.Debug);
            if (string.IsNullOrEmpty(caRequestID) || caRequestID.Length < 36)
                throw new ArgumentException($"CA request ID '{caRequestID}' is missing or too short to contain a valid UUID", nameof(caRequestID));

            var keyfactorCaId = caRequestID.Substring(0, 36); //todo fix to use pipe delimiter
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
            Logger.LogError(e, "Error occurred getting single cert for CA request ID {CaRequestID}: {Message}", caRequestID, e.Message);
            throw new Exception($"Error Occurred getting single cert {e.Message}");
        }
    }

    //done
    public async Task Synchronize(BlockingCollection<AnyCAPluginCertificate> blockingBuffer, DateTime? lastSync,
        bool fullSync, CancellationToken cancelToken)
    {
        Logger.LogTrace($"Full Sync? {fullSync.ToString()}");
        Logger.MethodEntry();
        using var flow = new FlowLogger(Logger, "Synchronize");
        try
        {
            if (fullSync)
            {
                Logger.LogInformation("Performing full sync - no date filter applied");
                flow.Step("DetermineSyncMode", "Full sync - no date filter applied");
                await SyncCertificates(blockingBuffer, cancelToken, null, flow);
            }
            else
            {
                var filterDays = SyncFilterDays > 0 ? SyncFilterDays : 5;
                var filterDate = DateTime.Today.Subtract(TimeSpan.FromDays(filterDays));
                var dateFilter = filterDate.ToString("yyyy/MM/dd");
                Logger.LogInformation($"Performing incremental sync with expiration date filter: {dateFilter}");
                flow.Step("DetermineSyncMode", $"Incremental sync with expiration date filter: {dateFilter}");
                await SyncCertificates(blockingBuffer, cancelToken, dateFilter, flow);
            }

            blockingBuffer.CompleteAdding();
            Logger.LogInformation("Csc Global Synchronize Task completed successfully");
        }
        catch (OperationCanceledException)
        {
            Logger.LogWarning("Csc Global Synchronize Task was cancelled");
            flow.Fail("Synchronize", "Task was cancelled");
            blockingBuffer.CompleteAdding();
            throw;
        }
        catch (Exception e)
        {
            Logger.LogError(e, $"Csc Global Synchronize Task failed! {LogHandler.FlattenException(e)}");
            flow.Fail("Synchronize", e.Message);
            Logger.MethodExit();
            blockingBuffer.CompleteAdding();
            throw;
        }

        Logger.MethodExit(LogLevel.Debug);
    }

    private async Task SyncCertificates(BlockingCollection<AnyCAPluginCertificate> blockingBuffer,
        CancellationToken cancelToken, string? dateFilter, FlowLogger flow)
    {
        var certs = await flow.StepAsync("SubmitCertificateListRequest",
            () => CscGlobalClient.SubmitCertificateListRequestAsync(dateFilter));

        Logger.LogInformation($"Retrieved {certs?.Results?.Count ?? 0} certificate(s) from CSC Global for sync");

        if (certs?.Results == null)
        {
            Logger.LogWarning("Certificate list request returned no results collection; nothing to sync");
            flow.Step("QueueCertificates", "No results collection returned; nothing to sync");
            return;
        }

        var queuedCount = 0;
        var queuedWithoutCertCount = 0;
        foreach (var currentResponseItem in certs.Results)
        {
            cancelToken.ThrowIfCancellationRequested();
            Logger.LogTrace($"Took Certificate ID {currentResponseItem?.Uuid} from Queue");
            var certStatus = _requestManager.MapReturnStatus(currentResponseItem?.Status);

            //Every known request is always reported back to Command, even without a certificate,
            //so Command never considers a still-pending or failed request "outdated" and tries to
            //prune it (which can hit an internal Command bug for requests with no staged private key).
            var productId = "CscGlobal";
            if (EnableTemplateSync) productId = currentResponseItem?.CertificateType;

            var certString = string.Empty;
            var hasIssuedOrRevokedCert = certStatus == Convert.ToInt32(EndEntityStatus.GENERATED) ||
                                         certStatus == Convert.ToInt32(EndEntityStatus.REVOKED);

            if (hasIssuedOrRevokedCert)
            {
                var fileContent =
                    PreparePemTextFromApi(
                        currentResponseItem?.Certificate ?? string.Empty);

                if (fileContent.Length > 0)
                {
                    Logger.LogTrace($"File Content {fileContent}");
                    var certData = fileContent.Replace("\r\n", string.Empty);
                    certString = GetEndEntityCertificate(certData);
                }

                if (string.IsNullOrEmpty(certString))
                    Logger.LogWarning($"Could not extract end-entity certificate for {currentResponseItem?.Uuid} (status {currentResponseItem?.Status}); syncing status only");
            }
            else
            {
                Logger.LogTrace($"Certificate ID {currentResponseItem?.Uuid} - status {currentResponseItem?.Status} has no certificate content yet; syncing status only");
            }

            blockingBuffer.Add(new AnyCAPluginCertificate
            {
                CARequestID = $"{currentResponseItem?.Uuid}",
                Certificate = certString,
                Status = certStatus,
                ProductID = productId
            }, cancelToken);

            if (string.IsNullOrEmpty(certString))
                queuedWithoutCertCount++;
            else
                queuedCount++;
        }

        flow.Step("QueueCertificates", $"Queued {queuedCount} with certificates, {queuedWithoutCertCount} status-only");
        Logger.LogInformation($"Sync queued {queuedCount} certificate(s) with content, {queuedWithoutCertCount} status-only record(s)");
    }

    //done
    public async Task<int> Revoke(string caRequestID, string hexSerialNumber, uint revocationReason)
    {
        Logger.MethodEntry(LogLevel.Debug);
        using var flow = new FlowLogger(Logger, "Revoke");
        try
        {
            Logger.LogInformation($"Starting Revoke for CA request ID {caRequestID}, reason {revocationReason}");
            if (string.IsNullOrEmpty(caRequestID) || caRequestID.Length < 36)
                throw new ArgumentException($"CA request ID '{caRequestID}' is missing or too short to contain a valid UUID", nameof(caRequestID));

            var uuid = caRequestID.Substring(0, 36); //todo fix to use pipe delimiter

            var revokeResponse = await flow.StepAsync("SubmitRevokeCertificate",
                () => CscGlobalClient.SubmitRevokeCertificateAsync(uuid));

            Logger.LogTrace($"Revoke Response JSON: {JsonConvert.SerializeObject(revokeResponse)}");

            var revokeResult = _requestManager.GetRevokeResult(revokeResponse);

            if (revokeResult == (int)EndEntityStatus.FAILED)
            {
                if (!string.IsNullOrEmpty(revokeResponse?.RegistrationError?.Description))
                {
                    flow.Fail("SubmitRevokeCertificate", revokeResponse?.RegistrationError?.Description ?? "Unknown error");
                    throw new HttpRequestException(
                        $"Revoke Failed with message {revokeResponse?.RegistrationError?.Description}");
                }

                Logger.LogWarning($"Revoke returned a failed status for CA request ID {caRequestID} with no error description");
            }
            else
            {
                Logger.LogInformation($"Revoke succeeded for CA request ID {caRequestID}");
            }

            Logger.MethodExit(LogLevel.Debug);
            return revokeResult;
        }
        catch (Exception e)
        {
            Logger.LogError(e, $"Revoke Failed for CA request ID {caRequestID} with message {e?.Message}");
            throw new Exception($"Revoke Failed with message {e?.Message}");
        }
    }

    //do
    public async Task<EnrollmentResult> Enroll(string csr, string subject, Dictionary<string, string[]> san,
        EnrollmentProductInfo productInfo, RequestFormat requestFormat, EnrollmentType enrollmentType)
    {
        if (productInfo == null) throw new ArgumentNullException(nameof(productInfo));

        Logger.MethodEntry(LogLevel.Debug);
        Logger.LogInformation($"Starting Enroll for product {productInfo.ProductID}, enrollment type {enrollmentType}");
        using var flow = new FlowLogger(Logger, "Enroll");

        try
        {
            RegistrationRequest enrollmentRequest;
            var priorSn = "";
            ReissueRequest reissueRequest;
            RenewalRequest renewRequest;
            var productParameters = productInfo.ProductParameters ?? new Dictionary<string, string>();
            if (productParameters.ContainsKey("priorcertsn"))
            {
                productParameters.TryGetValue("PriorCertSN", out priorSn);
                priorSn ??= "";
                Logger.LogDebug($"Prior cert sn: {priorSn}");
            }

            string uUId;
            var customFields = await flow.StepAsync("SubmitGetCustomFields", () => CscGlobalClient.SubmitGetCustomFields());

            switch (enrollmentType)
            {
                case EnrollmentType.New:
                    flow.Branch("New Enrollment");
                    //If they renewed an expired cert it gets here and this will not be supported
                    IRegistrationResponse enrollmentResponse;
                    if (!productParameters.ContainsKey("PriorCertSN"))
                    {
                        enrollmentRequest = _requestManager.GetRegistrationRequest(productInfo, csr, san, customFields);
                        Logger.LogTrace($"Enrollment Request JSON: {JsonConvert.SerializeObject(enrollmentRequest)}");
                        enrollmentResponse = await flow.StepAsync("SubmitRegistration",
                            () => CscGlobalClient.SubmitRegistrationAsync(enrollmentRequest));
                        Logger.LogTrace($"Enrollment Response JSON: {JsonConvert.SerializeObject(enrollmentResponse)}");
                    }
                    else
                    {
                        Logger.LogWarning("Cannot renew an expired cert via new enrollment; a new enrollment must be performed instead");
                        flow.Fail("New Enrollment", "Attempted to renew an expired cert via new enrollment");
                        flow.EndBranch();
                        return new EnrollmentResult
                        {
                            Status = 30, //failure
                            StatusMessage = "You cannot renew an expired cert please perform an new enrollment."
                        };
                    }

                    flow.EndBranch();
                    var newResult = _requestManager.GetEnrollmentResult(enrollmentResponse);
                    LogEnrollmentOutcome(newResult, "New Enrollment");
                    Logger.MethodExit(LogLevel.Debug);
                    return newResult;
                case EnrollmentType.RenewOrReissue:
                    flow.Branch("Renew Or Reissue");
                    if (string.IsNullOrEmpty(priorSn))
                    {
                        Logger.LogWarning($"Renew/Reissue requested for product {productInfo.ProductID} but no prior certificate serial number was supplied");
                        flow.Fail("Renew Or Reissue", "Missing prior certificate serial number");
                        flow.EndBranch();
                        return new EnrollmentResult
                        {
                            Status = 30, //failure
                            StatusMessage = "Cannot renew or reissue: no prior certificate serial number was supplied."
                        };
                    }

                    //Logic to determine renew vs reissue
                    var renewal = false;
                    var order_id = await _certificateDataReader.GetRequestIDBySerialNumber(priorSn);
                    if (string.IsNullOrEmpty(order_id))
                    {
                        Logger.LogWarning($"Could not find a Keyfactor request ID for prior certificate serial number {priorSn}");
                        flow.Fail("Renew Or Reissue", $"No request ID found for prior certificate serial number {priorSn}");
                        flow.EndBranch();
                        return new EnrollmentResult
                        {
                            Status = 30, //failure
                            StatusMessage = $"Cannot renew or reissue: no prior request found for serial number {priorSn}."
                        };
                    }

                    var expirationDate = _certificateDataReader.GetExpirationDateByRequestId(order_id);
                    if (expirationDate == null)
                    {
                        var localcert = await GetSingleRecord(order_id);
                        expirationDate = localcert?.RevocationDate;
                    }

                    if (expirationDate < DateTime.Now) renewal = true;
                    if (renewal)
                    {
                        flow.Step("DetermineRenewOrReissue", "Renewal - cert is expired");
                        //One click won't work for this implementation b/c we are missing enrollment params
                        if (productParameters.ContainsKey("Applicant Last Name"))
                        {
                            //priorCert = _certificateDataReader.get(
                            //DataConversion.HexToBytes(productInfo.ProductParameters["PriorCertSN"]));
                            //uUId = priorCert.CARequestID.Substring(0, 36); //uUId is a GUID
                            uUId = await _certificateDataReader.GetRequestIDBySerialNumber(
                                productParameters.GetValueOrDefault("PriorCertSN", ""));
                            Logger.LogTrace($"Renew uUId: {uUId}");
                            renewRequest = _requestManager.GetRenewalRequest(productInfo, uUId, csr, san, customFields);
                            Logger.LogTrace($"Renewal Request JSON: {JsonConvert.SerializeObject(renewRequest)}");
                            var renewResponse = await flow.StepAsync("SubmitRenewal",
                                () => CscGlobalClient.SubmitRenewalAsync(renewRequest));
                            Logger.LogTrace($"Renewal Response JSON: {JsonConvert.SerializeObject(renewResponse)}");
                            flow.EndBranch();
                            var renewResult = _requestManager.GetRenewResponse(renewResponse);
                            LogEnrollmentOutcome(renewResult, "Renewal");
                            Logger.MethodExit(LogLevel.Debug);
                            return renewResult;
                        }

                        Logger.LogWarning($"One click renew is not available for product {productInfo.ProductID}; missing required enrollment parameters");
                        flow.Fail("Renewal", "One click renew is not available; missing Applicant Last Name");
                        flow.EndBranch();
                        return new EnrollmentResult
                        {
                            Status = 30, //failure
                            StatusMessage =
                                "One click Renew Is Not Available for this Certificate Type.  Use the configure button instead."
                        };
                    }

                    flow.Step("DetermineRenewOrReissue", "Reissue - cert is still valid");
                    //One click won't work for this implementation b/c we are missing enrollment params
                    if (productParameters.ContainsKey("Applicant Last Name"))
                    {
                        var requestid = await _certificateDataReader.GetRequestIDBySerialNumber(
                            productParameters.GetValueOrDefault("PriorCertSN", ""));
                        if (string.IsNullOrEmpty(requestid) || requestid.Length < 36)
                        {
                            Logger.LogWarning($"Could not find a valid Keyfactor request ID for prior certificate serial number for product {productInfo.ProductID}");
                            flow.Fail("Reissue", "No valid request ID found for prior certificate serial number");
                            flow.EndBranch();
                            return new EnrollmentResult
                            {
                                Status = 30, //failure
                                StatusMessage = "Cannot reissue: no prior request found for the supplied certificate serial number."
                            };
                        }

                        uUId = requestid.Substring(0, 36); //uUId is a GUID
                        Logger.LogTrace($"Reissue uUId: {uUId}");
                        reissueRequest = _requestManager.GetReissueRequest(productInfo, uUId, csr, san, customFields);
                        Logger.LogTrace($"Reissue JSON: {JsonConvert.SerializeObject(reissueRequest)}");
                        var reissueResponse = await flow.StepAsync("SubmitReissue",
                            () => CscGlobalClient.SubmitReissueAsync(reissueRequest));
                        Logger.LogTrace($"Reissue Response JSON: {JsonConvert.SerializeObject(reissueResponse)}");
                        flow.EndBranch();
                        var reissueResult = _requestManager.GetReIssueResult(reissueResponse);
                        LogEnrollmentOutcome(reissueResult, "Reissue");
                        Logger.MethodExit(LogLevel.Debug);
                        return reissueResult;
                    }

                    Logger.LogWarning($"One click reissue is not available for product {productInfo.ProductID}; missing required enrollment parameters");
                    flow.Fail("Reissue", "One click reissue is not available; missing Applicant Last Name");
                    flow.EndBranch();
                    return new EnrollmentResult
                    {
                        Status = 30, //failure
                        StatusMessage =
                            "One click Renew Is Not Available for this Certificate Type.  Use the configure button instead."
                    };
            }

            Logger.LogWarning($"Unhandled enrollment type {enrollmentType} for product {productInfo.ProductID}");
            Logger.MethodExit(LogLevel.Debug);
            return null;
        }
        catch (Exception e)
        {
            Logger.LogError(e, $"Enroll failed for product {productInfo.ProductID}: {e.Message}");
            flow.Fail("Enroll", e.Message);
            throw;
        }
    }

    private void LogEnrollmentOutcome(EnrollmentResult result, string operationName)
    {
        if (result == null) return;
        if (result.Status == (int)EndEntityStatus.FAILED)
            Logger.LogError($"{operationName} failed: {result.StatusMessage}");
        else
            Logger.LogInformation($"{operationName} succeeded: {result.StatusMessage}");
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
            Logger.LogError(e, $"There was an error contacting CSCGlobal: {e.Message}.");
            throw new Exception($"Error attempting to ping CSCGlobal: {e.Message}.", e);
        }

        Logger.MethodExit();
    }

    //do
    public async Task ValidateCAConnectionInfo(Dictionary<string, object> connectionInfo)
    {
        Logger.MethodEntry(LogLevel.Debug);
        Logger.LogDebug($"Validating CA connection info with {connectionInfo?.Count ?? 0} entries");
        Logger.MethodExit(LogLevel.Debug);
    }

    //do
    public async Task ValidateProductInfo(EnrollmentProductInfo productInfo,
        Dictionary<string, object> connectionInfo)
    {
        Logger.MethodEntry(LogLevel.Debug);
        var certType = ProductIDs.productIds.Find(x =>
            x.Equals(productInfo.ProductID, StringComparison.InvariantCultureIgnoreCase));

        if (certType == null)
        {
            Logger.LogError($"Cannot find product ID {productInfo.ProductID} in the list of supported CSC Global products");
            throw new ArgumentException($"Cannot find {productInfo.ProductID}", "ProductId");
        }

        Logger.LogInformation($"Validated {certType} ({certType})configured for AnyGateway");
        Logger.MethodExit(LogLevel.Debug);
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
            },
            [Constants.SyncFilterDays] = new()
            {
                Comments = "Number of days from today to filter certificates by expiration date during incremental sync.",
                Hidden = false,
                DefaultValue = "5",
                Type = "Number"
            }
        };
    }

    //done
    public Dictionary<string, PropertyConfigInfo> GetTemplateParameterAnnotations()
    {
        return new Dictionary<string, PropertyConfigInfo>
        {
            [EnrollmentConfigConstants.Term] = new()
            {
                Comments = "OPTIONAL: Certificate term (e.g. 12 or 24 months)",
                Hidden = false,
                DefaultValue = string.Empty,
                Type = "Number"
            },

            [EnrollmentConfigConstants.ApplicantFirstName] = new()
            {
                Comments = "OPTIONAL: Applicant First Name",
                Hidden = false,
                DefaultValue = string.Empty,
                Type = "String"
            },

            [EnrollmentConfigConstants.ApplicantLastName] = new()
            {
                Comments = "OPTIONAL: Applicant Last Name",
                Hidden = false,
                DefaultValue = string.Empty,
                Type = "String"
            },

            [EnrollmentConfigConstants.ApplicantEmailAddress] = new()
            {
                Comments = "OPTIONAL: Applicant Email Address",
                Hidden = false,
                DefaultValue = string.Empty,
                Type = "String"
            },

            [EnrollmentConfigConstants.ApplicantPhone] = new()
            {
                Comments = "OPTIONAL: Applicant Phone (+nn.nnnnnnnn)",
                Hidden = false,
                DefaultValue = string.Empty,
                Type = "String"
            },

            [EnrollmentConfigConstants.DomainControlValidationMethod] = new()
            {
                Comments = "OPTIONAL: Domain Control Validation Method (e.g. EMAIL)",
                Hidden = false,
                DefaultValue = string.Empty,
                Type = "String"
            },

            [EnrollmentConfigConstants.OrganizationContact] = new()
            {
                Comments = "OPTIONAL: Organization Contact (selected from CSC configuration)",
                Hidden = false,
                DefaultValue = string.Empty,
                Type = "String"
            },

            [EnrollmentConfigConstants.BusinessUnit] = new()
            {
                Comments = "OPTIONAL: Business Unit (selected from CSC configuration)",
                Hidden = false,
                DefaultValue = string.Empty,
                Type = "String"
            },

            [EnrollmentConfigConstants.NotificationEmailsCommaSeparated] = new()
            {
                Comments = "OPTIONAL: Notification Email(s), comma separated",
                Hidden = false,
                DefaultValue = string.Empty,
                Type = "String"
            },

            [EnrollmentConfigConstants.CnDcvEmail] = new()
            {
                Comments = "OPTIONAL: CN DCV Email (e.g. admin@yourdomain.com)",
                Hidden = false,
                DefaultValue = string.Empty,
                Type = "String"
            },

            [EnrollmentConfigConstants.OrganizationCountry] = new()
            {
                Comments = "OPTIONAL: Organization Country",
                Hidden = false,
                DefaultValue = string.Empty,
                Type = "String"
            },

            [EnrollmentConfigConstants.AdditionalSansCommaSeparatedDcvEmails] = new()
            {
                Comments = "OPTIONAL: Additional SANs DCV Emails, comma separated",
                Hidden = false,
                DefaultValue = string.Empty,
                Type = "String"
            }
        };
    }

    //done
    public List<string> GetProductIds()
    {

        return ProductIDs.productIds;
    }

    #region PRIVATE

    //Trying to fix leaf extraction
    private static readonly Regex PemBlock = new(
        "-----BEGIN CERTIFICATE-----\\s*(?<b64>[A-Za-z0-9+/=\\r\\n]+?)\\s*-----END CERTIFICATE-----",
        RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.Singleline);

    private static readonly Regex Ws = new("\\s+", RegexOptions.Compiled);

    /// <summary>
    ///     Returns the end-entity certificate as Base64 DER (no PEM headers), or "" if none could be found.
    /// </summary>
    public string GetEndEntityCertificate(string pemChain)
    {
        if (string.IsNullOrWhiteSpace(pemChain))
        {
            Logger.LogWarning("Empty PEM input.");
            return string.Empty;
        }

        // 1) Extract certs block-by-block, ignoring any garbage outside of valid fences.
        var certs = ExtractCertificates(pemChain);
        if (certs.Count == 0)
        {
            Logger.LogWarning("No valid certificate blocks found in input.");
            return string.Empty;
        }

        // 2) Pick the leaf (end-entity).
        var leaf = FindLeaf(certs);
        if (leaf is null)
        {
            Logger.LogWarning("Could not determine end-entity certificate from the provided chain.");
            return string.Empty;
        }

        try
        {
            // 3) Export to DER and Base64 (no headers).
            var der = leaf.Export(X509ContentType.Cert);
            var b64 = Convert.ToBase64String(der);
            Logger.LogTrace("End-entity certificate exported successfully.");
            return b64;
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Failed to export end-entity certificate.");
            return string.Empty;
        }
        finally
        {
            // Dispose everything we created.
            foreach (var c in certs) c.Dispose();
        }
    }

    private List<X509Certificate2> ExtractCertificates(string pem)
    {
        var results = new List<X509Certificate2>();

        foreach (Match m in PemBlock.Matches(pem))
        {
            var b64 = m.Groups["b64"].Value;
            if (string.IsNullOrWhiteSpace(b64))
            {
                Logger.LogTrace("Skipping empty PEM block.");
                continue;
            }

            // Normalize: remove all whitespace and non-base64 spacers that sometimes creep in
            b64 = Ws.Replace(b64, string.Empty);

            // Strict Base64 decode with validation.
            try
            {
                // Convert.TryFromBase64String is fast and avoids temporary arrays when possible
                if (!Convert.TryFromBase64String(b64, new Span<byte>(new byte[GetDecodedLength(b64)]),
                        out var bytesWritten))
                {
                    // Fallback to FromBase64String to trigger a clear exception path
                    var discard = Convert.FromBase64String(b64);
                    bytesWritten = discard.Length; // unreachable if invalid
                }

                var der = Convert.FromBase64String(b64);
                var cert = new X509Certificate2(der);
                results.Add(cert);
                Logger.LogTrace($"Imported certificate: Subject='{cert.Subject}', Issuer='{cert.Issuer}'");
            }
            catch (FormatException fex)
            {
                Logger.LogWarning(fex, "Invalid Base64 inside a PEM block; skipping this block.");
            }
            catch (CryptographicException cex)
            {
                Logger.LogWarning(cex, "DER payload failed to parse as X509; skipping this block.");
            }
            catch (Exception ex)
            {
                Logger.LogWarning(ex, "Unexpected error while parsing a PEM block; skipping this block.");
            }
        }

        return results;
    }

    // Heuristic leaf selection:
    //  - Prefer a certificate with CA=false (BasicConstraints) and whose Subject is not an Issuer of any other cert.
    //  - If multiple, prefer the one whose Subject does not appear as any Issuer at all.
    //  - As a last resort, pick the one with the longest chain distance (i.e., not issuing others).
    private X509Certificate2? FindLeaf(IReadOnlyList<X509Certificate2> certs)
    {
        // Build sets for quick lookups
        var issuers = new HashSet<string>(certs.Select(c => c.Issuer), StringComparer.OrdinalIgnoreCase);
        var subjects = new HashSet<string>(certs.Select(c => c.Subject), StringComparer.OrdinalIgnoreCase);

        bool IsCa(X509Certificate2 c)
        {
            try
            {
                var bc = c.Extensions["2.5.29.19"]; // Basic Constraints
                if (bc is X509BasicConstraintsExtension bce)
                    return bce.CertificateAuthority;
            }
            catch
            {
                /* ignore and treat as unknown */
            }

            return false; // if unknown, bias towards non-CA for end-entity picking
        }

        // Candidates that do not issue others (their Subject is not an Issuer of any other).
        var nonIssuers = certs.Where(c =>
            !certs.Any(o =>
                !ReferenceEquals(o, c) && string.Equals(o.Issuer, c.Subject, StringComparison.OrdinalIgnoreCase))
        ).ToList();

        // Prefer non-CA among non-issuers
        var nonIssuerNonCa = nonIssuers.Where(c => !IsCa(c)).ToList();
        if (nonIssuerNonCa.Count == 1) return nonIssuerNonCa[0];
        if (nonIssuerNonCa.Count > 1)
            // If multiple, pick the one whose subject appears least as an issuer (tie-breaker unnecessary here since nonIssuers already exclude issuers).
            return nonIssuerNonCa[0];

        // If that failed, pick any non-CA that is not an issuer in the set of all issuers
        var anyNonCa = certs.Where(c => !IsCa(c)).ToList();
        if (anyNonCa.Count == 1) return anyNonCa[0];
        if (anyNonCa.Count > 1)
        {
            // Prefer one whose subject is not equal to any issuer (a stricter non-issuer check across entire set)
            var strict = anyNonCa.FirstOrDefault(c => !issuers.Contains(c.Subject));
            if (strict != null) return strict;

            return anyNonCa[0];
        }

        // Last resort: pick the cert that issues nobody else (even if CA=true)
        if (nonIssuers.Count > 0) return nonIssuers[0];

        // Give up
        return null;
    }

    private static int GetDecodedLength(string b64)
    {
        // Approximate decoded length: 3/4 of input, minus padding effect
        var len = b64.Length;
        var padding = 0;
        if (len >= 2)
        {
            if (b64[^1] == '=') padding++;
            if (b64[^2] == '=') padding++;
        }

        return Math.Max(0, len / 4 * 3 - padding);
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

    private static readonly Encoding Utf8Strict = new UTF8Encoding(false, true);
    private static readonly Encoding Latin1 = Encoding.GetEncoding("ISO-8859-1");

    private string PreparePemTextFromApi(string? base64)
    {
        if (string.IsNullOrWhiteSpace(base64))
            return string.Empty;

        byte[] raw;
        try
        {
            raw = Convert.FromBase64String(base64);
        }
        catch (FormatException)
        {
            // Not even Base64; nothing we can do.
            return string.Empty;
        }

        // Try UTF-8 first (strict); if it fails, decode as Latin-1 to avoid loss.
        string text;
        try
        {
            text = Utf8Strict.GetString(raw);
        }
        catch (DecoderFallbackException)
        {
            text = Latin1.GetString(raw);
        }

        // Drop UTF-8/UTF-16 BOMs if present
        if (text.Length > 0 && text[0] == '\uFEFF') text = text[1..];

        // Normalize line endings to '\n' (keep line structure!)
        text = text.Replace("\r\n", "\n").Replace("\r", "\n");

        // Remove NUL and non-printable control chars, but keep \n and \t
        text = new string(text.Where(ch =>
            ch == '\n' || ch == '\t' || (ch >= ' ' && ch != '\u007F')
        ).ToArray());

        return text;
    }

    #endregion
}