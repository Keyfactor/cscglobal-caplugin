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
    /// <summary>
    ///     Validation type string passed to <see cref="IDomainValidatorFactory.ResolveDomainValidator"/>.
    ///     CSC's Domain Control Validation publishes a CNAME record, so we resolve a DNS provider
    ///     that advertises the "cname" validation type (e.g. GoDaddy's GoDaddyCnameDomainValidator).
    ///     This is distinct from ACME's "dns-01" challenge, which publishes TXT records — a single
    ///     DNS provider DLL can ship separate validator classes for each type.
    /// </summary>
    private const string DNS_VALIDATION_TYPE = "cname";

    /// <summary>Delay between CSC status polls while waiting for DCV to complete.</summary>
    private static readonly TimeSpan DcvPollInterval = TimeSpan.FromSeconds(10);

    private readonly RequestManager _requestManager;
    private readonly ILogger Logger;
    private readonly IDomainValidatorFactory? _validatorFactory;
    private ICertificateDataReader _certificateDataReader;

    /// <summary>
    ///     Parameterless constructor retained for compatibility with older gateway hosts that don't
    ///     perform DI. When constructed this way the plugin runs without DNS auto-publishing.
    /// </summary>
    public CSCGlobalCAPlugin()
    {
        Logger = LogHandler.GetClassLogger<CSCGlobalCAPlugin>();
        _requestManager = new RequestManager();
        _validatorFactory = null;
    }

    /// <summary>
    ///     DI constructor used by AnyCA Gateway 3.3+ which injects the framework's domain validator
    ///     factory. When non-null, CNAME DCV records returned by CSC are auto-published via the
    ///     framework's registered DNS providers (resolved per-domain).
    /// </summary>
    public CSCGlobalCAPlugin(IDomainValidatorFactory validatorFactory)
    {
        Logger = LogHandler.GetClassLogger<CSCGlobalCAPlugin>();
        _requestManager = new RequestManager();
        _validatorFactory = validatorFactory;
    }

    private ICscGlobalClient CscGlobalClient { get; set; }

    /// <summary>
    ///     Whether the CA is enabled. When false, the plugin returns early from Ping,
    ///     ValidateCAConnectionInfo, ValidateProductInfo, Synchronize, Enroll, and Revoke without
    ///     calling CSC. Primarily used to allow creation of the CA record prior to configuration
    ///     information being available (standard field across Keyfactor CA plugins). Defaults to true
    ///     so existing deployments that don't set this key continue to function.
    /// </summary>
    public bool Enabled { get; set; } = true;

    public int SyncFilterDays { get; set; }

    public int RenewalWindowDays { get; set; }

    /// <summary>
    ///     Maximum seconds to synchronously poll CSC for certificate issuance after submitting an
    ///     order (and publishing CNAME DCV). 0 disables polling — the enrollment returns "pending"
    ///     immediately and the cert is picked up on the next sync. When &gt; 0, fast-validating
    ///     orders can return the issued cert directly in the enrollment response.
    /// </summary>
    public int DcvPollTimeoutSeconds { get; set; }

    //done
    public void Initialize(IAnyCAPluginConfigProvider configProvider, ICertificateDataReader certificateDataReader)
    {
        using var flow = new FlowLogger(Logger, "Initialize");
        Logger.MethodEntry(LogLevel.Debug);
        Logger.LogTrace("Initialize called. configProvider is {Null}, certificateDataReader is {Null2}",
            configProvider == null ? "NULL" : "present",
            certificateDataReader == null ? "NULL" : "present");

        flow.Step("ValidateInputs", () =>
        {
            if (configProvider == null)
                throw new ArgumentNullException(nameof(configProvider), "configProvider cannot be null in Initialize");
            if (certificateDataReader == null)
                throw new ArgumentNullException(nameof(certificateDataReader), "certificateDataReader cannot be null in Initialize");
        });

        _certificateDataReader = certificateDataReader;

        flow.Step("ValidateConnectionData", () =>
        {
            if (configProvider.CAConnectionData == null)
            {
                Logger.LogError("CAConnectionData is null. Cannot read configuration.");
                throw new InvalidOperationException("CAConnectionData is null on configProvider.");
            }
            Logger.LogTrace("CAConnectionData keys: {Keys}", string.Join(", ", configProvider.CAConnectionData.Keys));
        });

        flow.Step("ReadEnabled", () =>
        {
            Enabled = true; // default
            if (configProvider.CAConnectionData.TryGetValue(Constants.Enabled, out var enabledObj))
            {
                Logger.LogTrace("Enabled raw value: '{Value}'", enabledObj?.ToString() ?? "(null)");
                if (bool.TryParse(enabledObj?.ToString(), out var parsed))
                    Enabled = parsed;
                else
                    Logger.LogWarning("Enabled value '{Value}' could not be parsed as bool, defaulting to true.", enabledObj);
            }
            else
            {
                Logger.LogTrace("Enabled key not found in CAConnectionData, defaulting to true.");
            }
            Logger.LogInformation("CA is {State}.", Enabled ? "Enabled" : "Disabled");
        }, $"Enabled={Enabled}");

        // Construct the CSC client only when enabled. When disabled we allow Initialize to complete
        // without valid API credentials — this is the whole point of the Enabled toggle (so ops can
        // create the CA record before credentials are available).
        if (Enabled)
        {
            flow.Step("CreateCscGlobalClient", () =>
            {
                Logger.LogTrace("Creating CscGlobalClient from configProvider...");
                CscGlobalClient = new CscGlobalClient(configProvider);
                Logger.LogTrace("CscGlobalClient created successfully.");
            });
        }
        else
        {
            flow.Skip("CreateCscGlobalClient", "CA is Disabled");
        }

        flow.Step("ReadSyncFilterDays", () =>
        {
            if (configProvider.CAConnectionData.ContainsKey(Constants.SyncFilterDays))
            {
                var syncFilterDaysStr = configProvider.CAConnectionData[Constants.SyncFilterDays]?.ToString();
                Logger.LogTrace("SyncFilterDays raw value: '{Value}'", syncFilterDaysStr ?? "(null)");
                if (int.TryParse(syncFilterDaysStr, out var syncFilterDays))
                {
                    SyncFilterDays = syncFilterDays;
                    Logger.LogDebug("SyncFilterDays configured to {Days} days", SyncFilterDays);
                }
                else
                {
                    Logger.LogWarning("SyncFilterDays value '{Value}' could not be parsed as int, using default 0.", syncFilterDaysStr);
                }
            }
            else
            {
                Logger.LogTrace("SyncFilterDays key not found in CAConnectionData, using default 0.");
            }
        });

        flow.Step("ReadRenewalWindowDays", () =>
        {
            RenewalWindowDays = 30; // default
            if (configProvider.CAConnectionData.TryGetValue(Constants.RenewalWindowDays, out var renewalWindowObj))
            {
                Logger.LogTrace("RenewalWindowDays raw value: '{Value}'", renewalWindowObj?.ToString() ?? "(null)");
                if (int.TryParse(renewalWindowObj?.ToString(), out var renewalWindowDays) && renewalWindowDays > 0)
                    RenewalWindowDays = renewalWindowDays;
                else
                    Logger.LogWarning("RenewalWindowDays value '{Value}' could not be parsed or was <= 0, using default 30.", renewalWindowObj);
            }
            else
            {
                Logger.LogTrace("RenewalWindowDays key not found in CAConnectionData, using default 30.");
            }
            Logger.LogDebug("RenewalWindowDays configured to {Days} days", RenewalWindowDays);
        }, $"RenewalWindowDays={RenewalWindowDays}");

        flow.Step("ReadDcvPollTimeoutSeconds", () =>
        {
            DcvPollTimeoutSeconds = 0; // default: disabled
            if (configProvider.CAConnectionData.TryGetValue(Constants.DcvPollTimeoutSeconds, out var pollObj))
            {
                Logger.LogTrace("DcvPollTimeoutSeconds raw value: '{Value}'", pollObj?.ToString() ?? "(null)");
                if (int.TryParse(pollObj?.ToString(), out var pollSeconds) && pollSeconds >= 0)
                    DcvPollTimeoutSeconds = pollSeconds;
                else
                    Logger.LogWarning("DcvPollTimeoutSeconds value '{Value}' could not be parsed or was < 0, using default 0 (disabled).", pollObj);
            }
            else
            {
                Logger.LogTrace("DcvPollTimeoutSeconds key not found in CAConnectionData, using default 0 (disabled).");
            }
            Logger.LogDebug("DcvPollTimeoutSeconds configured to {Seconds}s ({State})",
                DcvPollTimeoutSeconds, DcvPollTimeoutSeconds > 0 ? "enabled" : "disabled");
        });

        flow.Step("CheckDnsValidatorFactory", () =>
        {
            if (_validatorFactory == null)
                Logger.LogInformation(
                    "No IDomainValidatorFactory was injected by the gateway host. CNAME DCV records will require manual publishing.");
            else
                Logger.LogInformation(
                    "IDomainValidatorFactory available from gateway host. CNAME DCV records will be auto-published per-domain via the framework's registered DNS providers (validation type '{Type}').",
                    DNS_VALIDATION_TYPE);
        });

        Logger.MethodExit(LogLevel.Debug);
    }

    //done
    public async Task<AnyCAPluginCertificate> GetSingleRecord(string caRequestID)
    {
        using var flow = new FlowLogger(Logger, $"GetSingleRecord({caRequestID ?? "null"})");
        Logger.MethodEntry(LogLevel.Debug);
        Logger.LogTrace("GetSingleRecord called with caRequestID='{CaRequestId}'", caRequestID ?? "(null)");

        flow.Step("ValidateInput", () =>
        {
            if (string.IsNullOrEmpty(caRequestID))
                throw new ArgumentNullException(nameof(caRequestID), "caRequestID cannot be null or empty.");
            if (caRequestID.Length < 36)
                throw new ArgumentException($"caRequestID '{caRequestID}' is too short to extract a UUID (need at least 36 chars).", nameof(caRequestID));
        });

        try
        {
            var keyfactorCaId = caRequestID.Substring(0, 36);
            flow.Step("ExtractUUID", $"keyfactorCaId={keyfactorCaId}");

            CertificateResponse certificateResponse = null;
            await flow.StepAsync("FetchCertFromCSC", async () =>
            {
                certificateResponse = await CscGlobalClient.SubmitGetCertificateAsync(keyfactorCaId);
            });

            if (certificateResponse == null)
            {
                flow.Fail("ParseResponse", "API returned null");
                Logger.LogWarning("GetSingleRecord: SubmitGetCertificateAsync returned null for keyfactorCaId='{KeyfactorCaId}'", keyfactorCaId);
                return new AnyCAPluginCertificate
                {
                    CARequestID = keyfactorCaId,
                    Certificate = string.Empty,
                    Status = _requestManager.MapReturnStatus(null)
                };
            }

            flow.Step("ParseResponse", $"Status={certificateResponse.Status ?? "(null)"}");
            Logger.LogTrace("Single Cert JSON: {Json}", JsonConvert.SerializeObject(certificateResponse));

            var rawCert = certificateResponse.Certificate ?? string.Empty;
            string fileContent = string.Empty;
            flow.Step("DecodeBase64", () =>
            {
                try
                {
                    fileContent = Encoding.ASCII.GetString(Convert.FromBase64String(rawCert));
                }
                catch (FormatException fex)
                {
                    Logger.LogError(fex, "GetSingleRecord: Failed to decode Base64 certificate content for keyfactorCaId='{KeyfactorCaId}'", keyfactorCaId);
                    fileContent = string.Empty;
                }
            }, $"length={rawCert.Length}");

            var certData = fileContent.Replace("\r\n", string.Empty);
            var certString = string.Empty;
            if (!string.IsNullOrEmpty(certData))
            {
                flow.Step("ExtractLeafCert", () =>
                {
                    certString = GetEndEntityCertificate(certData);
                }, $"inputLength={certData.Length}");
            }
            else
            {
                flow.Skip("ExtractLeafCert", "certData empty after cleanup");
            }

            var mappedStatus = _requestManager.MapReturnStatus(certificateResponse.Status);
            flow.Step("MapStatus", $"{certificateResponse.Status ?? "(null)"} -> {mappedStatus}");

            Logger.MethodExit(LogLevel.Debug);

            return new AnyCAPluginCertificate
            {
                CARequestID = keyfactorCaId,
                Certificate = certString ?? string.Empty,
                Status = mappedStatus
            };
        }
        catch (AggregateException ae)
        {
            var inner = ae.Flatten().InnerException;
            flow.Fail("UNHANDLED", inner?.Message ?? ae.Message);
            Logger.LogError(inner, "GetSingleRecord: AggregateException for caRequestID='{CaRequestId}': {Message}", caRequestID, inner?.Message ?? ae.Message);
            throw new Exception($"Error Occurred getting single cert for '{caRequestID}': {inner?.Message ?? ae.Message}", inner ?? ae);
        }
        catch (Exception e)
        {
            flow.Fail("UNHANDLED", e.Message);
            Logger.LogError(e, "GetSingleRecord: Exception for caRequestID='{CaRequestId}': {Message}", caRequestID, e.Message);
            throw new Exception($"Error Occurred getting single cert for '{caRequestID}': {e.Message}", e);
        }
    }

    //done
    public async Task Synchronize(BlockingCollection<AnyCAPluginCertificate> blockingBuffer, DateTime? lastSync,
        bool fullSync, CancellationToken cancelToken)
    {
        var syncType = fullSync ? "Full" : "Incremental";
        using var flow = new FlowLogger(Logger, $"Synchronize-{syncType}");
        Logger.MethodEntry();
        Logger.LogTrace("Synchronize called. fullSync={FullSync}, lastSync={LastSync}, blockingBuffer is {Null}",
            fullSync, lastSync?.ToString("o") ?? "(null)",
            blockingBuffer == null ? "NULL" : "present");

        if (blockingBuffer == null)
            throw new ArgumentNullException(nameof(blockingBuffer), "blockingBuffer cannot be null in Synchronize");

        if (!Enabled)
        {
            Logger.LogWarning("The CA is currently in the Disabled state. It must be Enabled to perform operations. Skipping Synchronize.");
            blockingBuffer.CompleteAdding();
            Logger.MethodExit(LogLevel.Debug);
            return;
        }

        try
        {
            if (fullSync)
            {
                flow.Step("DetermineFilter", "Full sync - no date filter");
                await flow.StepAsync("FetchAndProcessCerts", async () =>
                {
                    await SyncCertificates(blockingBuffer, cancelToken, null);
                });
            }
            else
            {
                var filterDays = SyncFilterDays > 0 ? SyncFilterDays : 5;
                var filterDate = DateTime.Today.Subtract(TimeSpan.FromDays(filterDays));
                var dateFilter = filterDate.ToString("yyyy/MM/dd");
                flow.Step("DetermineFilter", $"Incremental, filterDays={filterDays}, cutoff={dateFilter}");
                await flow.StepAsync("FetchAndProcessCerts", async () =>
                {
                    await SyncCertificates(blockingBuffer, cancelToken, dateFilter);
                });
            }

            flow.Step("CompleteAdding");
            blockingBuffer.CompleteAdding();
        }
        catch (OperationCanceledException)
        {
            flow.Fail("Cancelled", "operation was cancelled");
            Logger.LogWarning("Synchronize: operation was cancelled.");
            if (!blockingBuffer.IsAddingCompleted)
                blockingBuffer.CompleteAdding();
            throw;
        }
        catch (Exception e)
        {
            flow.Fail("SyncError", e.Message);
            Logger.LogError(e, "Csc Global Synchronize Task failed! {FlatException}", LogHandler.FlattenException(e));
            if (!blockingBuffer.IsAddingCompleted)
                blockingBuffer.CompleteAdding();
            Logger.MethodExit();
            throw;
        }

        Logger.MethodExit(LogLevel.Debug);
    }

    private async Task SyncCertificates(BlockingCollection<AnyCAPluginCertificate> blockingBuffer,
        CancellationToken cancelToken, string? dateFilter)
    {
        Logger.LogTrace("SyncCertificates: calling SubmitCertificateListRequestAsync with dateFilter='{DateFilter}'", dateFilter ?? "(null)");
        var certs = await CscGlobalClient.SubmitCertificateListRequestAsync(dateFilter);

        if (certs == null)
        {
            Logger.LogWarning("SyncCertificates: SubmitCertificateListRequestAsync returned null.");
            return;
        }

        if (certs.Results == null)
        {
            Logger.LogWarning("SyncCertificates: certificate list response Results collection is null.");
            return;
        }

        Logger.LogTrace("SyncCertificates: received {Count} certificate results.", certs.Results.Count);
        var processedCount = 0;
        var skippedCount = 0;

        foreach (var currentResponseItem in certs.Results)
        {
            cancelToken.ThrowIfCancellationRequested();

            if (currentResponseItem == null)
            {
                Logger.LogTrace("SyncCertificates: skipping null result item.");
                skippedCount++;
                continue;
            }

            Logger.LogTrace("SyncCertificates: processing certificate UUID={Uuid}, Status='{Status}', CertificateType='{CertType}'",
                currentResponseItem.Uuid ?? "(null)",
                currentResponseItem.Status ?? "(null)",
                currentResponseItem.CertificateType ?? "(null)");

            var certStatus = _requestManager.MapReturnStatus(currentResponseItem.Status);
            Logger.LogTrace("SyncCertificates: mapped status for UUID={Uuid}: {MappedStatus}", currentResponseItem.Uuid ?? "(null)", certStatus);

            if (certStatus == Convert.ToInt32(EndEntityStatus.GENERATED) ||
                certStatus == Convert.ToInt32(EndEntityStatus.REVOKED))
            {
                var productId = _requestManager.MapCertificateTypeToProductId(currentResponseItem.CertificateType);

                Logger.LogTrace("SyncCertificates: UUID={Uuid} qualifies for sync. CertificateType='{CertType}' -> ProductId='{ProductId}'",
                    currentResponseItem.Uuid, currentResponseItem.CertificateType ?? "(null)", productId);

                string fileContent;
                try
                {
                    fileContent = PreparePemTextFromApi(currentResponseItem.Certificate ?? string.Empty);
                }
                catch (Exception ex)
                {
                    Logger.LogError(ex, "SyncCertificates: PreparePemTextFromApi failed for UUID={Uuid}", currentResponseItem.Uuid);
                    skippedCount++;
                    continue;
                }

                if (fileContent.Length > 0)
                {
                    Logger.LogTrace("SyncCertificates: fileContent length={Length} for UUID={Uuid}", fileContent.Length, currentResponseItem.Uuid);
                    var certData = fileContent.Replace("\r\n", string.Empty);
                    string certString;
                    try
                    {
                        certString = GetEndEntityCertificate(certData);
                    }
                    catch (Exception ex)
                    {
                        Logger.LogError(ex, "SyncCertificates: GetEndEntityCertificate failed for UUID={Uuid}", currentResponseItem.Uuid);
                        skippedCount++;
                        continue;
                    }

                    if (!string.IsNullOrEmpty(certString))
                    {
                        blockingBuffer.Add(new AnyCAPluginCertificate
                        {
                            CARequestID = $"{currentResponseItem.Uuid}",
                            Certificate = certString,
                            Status = certStatus,
                            ProductID = productId
                        }, cancelToken);
                        processedCount++;
                        Logger.LogTrace("SyncCertificates: added UUID={Uuid} to buffer.", currentResponseItem.Uuid);
                    }
                    else
                    {
                        Logger.LogTrace("SyncCertificates: certString was empty for UUID={Uuid}, skipping.", currentResponseItem.Uuid);
                        skippedCount++;
                    }
                }
                else
                {
                    Logger.LogTrace("SyncCertificates: fileContent was empty for UUID={Uuid}, skipping.", currentResponseItem.Uuid);
                    skippedCount++;
                }
            }
            else
            {
                Logger.LogTrace("SyncCertificates: UUID={Uuid} status {Status} not eligible for sync, skipping.", currentResponseItem.Uuid, certStatus);
                skippedCount++;
            }
        }

        Logger.LogDebug("SyncCertificates: completed. Processed={Processed}, Skipped={Skipped}, Total={Total}",
            processedCount, skippedCount, certs.Results.Count);
    }

    //done
    public async Task<int> Revoke(string caRequestID, string hexSerialNumber, uint revocationReason)
    {
        using var flow = new FlowLogger(Logger, $"Revoke({caRequestID ?? "null"})");
        Logger.MethodEntry(LogLevel.Debug);
        Logger.LogTrace("Revoke called with caRequestID='{CaRequestId}', hexSerialNumber='{SerialNumber}', revocationReason={Reason}",
            caRequestID ?? "(null)", hexSerialNumber ?? "(null)", revocationReason);

        if (!Enabled)
        {
            Logger.LogWarning("The CA is currently in the Disabled state. It must be Enabled to perform operations. Rejecting Revoke.");
            throw new InvalidOperationException("The CSC Global CA is in the Disabled state. Enable it to perform revocations.");
        }

        flow.Step("ValidateInput", () =>
        {
            if (string.IsNullOrEmpty(caRequestID))
                throw new ArgumentNullException(nameof(caRequestID), "caRequestID cannot be null or empty for Revoke.");
            if (caRequestID.Length < 36)
                throw new ArgumentException($"caRequestID '{caRequestID}' is too short to extract a UUID.", nameof(caRequestID));
        });

        try
        {
            var uuid = caRequestID.Substring(0, 36);
            flow.Step("ExtractUUID", $"uuid={uuid}");

            RevokeResponse revokeResponse = null;
            await flow.StepAsync("SubmitRevokeToCSC", async () =>
            {
                revokeResponse = await CscGlobalClient.SubmitRevokeCertificateAsync(uuid);
            });

            if (revokeResponse == null)
            {
                flow.Fail("ParseResponse", "API returned null");
                throw new InvalidOperationException($"Revoke received null response for UUID '{uuid}'.");
            }

            Logger.LogTrace("Revoke Response JSON: {Json}", JsonConvert.SerializeObject(revokeResponse));

            var revokeResult = _requestManager.GetRevokeResult(revokeResponse);
            flow.Step("MapResult", $"result={revokeResult}");

            if (revokeResult == (int)EndEntityStatus.FAILED)
            {
                var errorDesc = revokeResponse.RegistrationError?.Description;
                flow.Fail("RevokeResult", errorDesc ?? "(no description)");
                Logger.LogError("Revoke: failed for UUID='{Uuid}'. Error description: '{ErrorDesc}'",
                    uuid, errorDesc ?? "(no description)");
                if (!string.IsNullOrEmpty(errorDesc))
                    throw new HttpRequestException($"Revoke Failed with message {errorDesc}");
            }

            Logger.MethodExit(LogLevel.Debug);
            return revokeResult;
        }
        catch (AggregateException ae)
        {
            var inner = ae.Flatten().InnerException;
            flow.Fail("UNHANDLED", inner?.Message ?? ae.Message);
            Logger.LogError(inner, "Revoke: AggregateException for caRequestID='{CaRequestId}': {Message}", caRequestID, inner?.Message ?? ae.Message);
            throw new Exception($"Revoke Failed for '{caRequestID}' with message {inner?.Message ?? ae.Message}", inner ?? ae);
        }
        catch (HttpRequestException)
        {
            throw; // already logged in flow above
        }
        catch (Exception e)
        {
            flow.Fail("UNHANDLED", e.Message);
            Logger.LogError(e, "Revoke: Exception for caRequestID='{CaRequestId}': {Message}", caRequestID, e.Message);
            throw new Exception($"Revoke Failed for '{caRequestID}' with message {e.Message}", e);
        }
    }

    //do
    public async Task<EnrollmentResult> Enroll(string csr, string subject, Dictionary<string, string[]> san,
        EnrollmentProductInfo productInfo, RequestFormat requestFormat, EnrollmentType enrollmentType)
    {
        using var flow = new FlowLogger(Logger, $"Enroll-{enrollmentType}");
        Logger.MethodEntry(LogLevel.Debug);
        Logger.LogTrace("Enroll called. enrollmentType={EnrollmentType}, subject='{Subject}', productId='{ProductId}', requestFormat={RequestFormat}",
            enrollmentType, subject ?? "(null)",
            productInfo?.ProductID ?? "(null)", requestFormat);
        Logger.LogTrace("Enroll: csr is {CsrStatus}, san has {SanCount} entries, productInfo is {PiStatus}",
            string.IsNullOrEmpty(csr) ? "empty/null" : $"present ({csr.Length} chars)",
            san?.Count ?? 0,
            productInfo == null ? "NULL" : "present");

        if (!Enabled)
        {
            flow.Fail("Disabled", "CA is Disabled");
            Logger.LogWarning("The CA is currently in the Disabled state. It must be Enabled to perform operations. Rejecting Enroll.");
            return new EnrollmentResult
            {
                Status = (int)EndEntityStatus.FAILED,
                StatusMessage = "The CSC Global CA is in the Disabled state. Enable it to perform enrollments."
            };
        }

        flow.Step("ValidateInputs", () =>
        {
            if (productInfo == null)
                throw new ArgumentNullException(nameof(productInfo), "productInfo cannot be null for Enroll.");
            if (productInfo.ProductParameters == null)
                throw new ArgumentNullException(nameof(productInfo), "productInfo.ProductParameters cannot be null for Enroll.");
            if (string.IsNullOrEmpty(csr))
                throw new ArgumentNullException(nameof(csr), "CSR cannot be null or empty for Enroll.");
        });

        Logger.LogTrace("Enroll: ProductParameters keys: [{Keys}]",
            string.Join(", ", productInfo.ProductParameters.Keys));

        RegistrationRequest enrollmentRequest;
        var priorSn = "";
        ReissueRequest reissueRequest;
        RenewalRequest renewRequest;

        flow.Step("CheckPriorCertSN", () =>
        {
            if (productInfo.ProductParameters.ContainsKey("priorcertsn"))
            {
                if (productInfo.ProductParameters.ContainsKey("PriorCertSN"))
                {
                    priorSn = productInfo.ProductParameters["PriorCertSN"];
                    Logger.LogDebug("Enroll: Prior cert SN: '{PriorSn}'", priorSn ?? "(null)");
                }
                else
                {
                    Logger.LogWarning("Enroll: 'priorcertsn' key exists but 'PriorCertSN' (case-sensitive) not found.");
                }
            }
        }, string.IsNullOrEmpty(priorSn) ? "none" : $"SN={priorSn}");

        string uUId;
        List<GetCustomField> customFields = null;
        await flow.StepAsync("FetchCustomFields", async () =>
        {
            customFields = await CscGlobalClient.SubmitGetCustomFields();
        }, $"count={customFields?.Count ?? 0}");

        if (customFields == null)
        {
            Logger.LogWarning("Enroll: SubmitGetCustomFields returned null, using empty list.");
            customFields = new List<GetCustomField>();
        }

        try
        {
            switch (enrollmentType)
            {
                case EnrollmentType.New:
                    flow.Step("SelectPath", "New Enrollment");
                    IRegistrationResponse enrollmentResponse;
                    if (!productInfo.ProductParameters.ContainsKey("PriorCertSN"))
                    {
                        enrollmentRequest = null;
                        flow.Step("BuildRegistrationRequest", () =>
                        {
                            enrollmentRequest = _requestManager.GetRegistrationRequest(productInfo, csr, san, customFields);
                        });
                        Logger.LogTrace("Enrollment Request JSON: {Json}", JsonConvert.SerializeObject(enrollmentRequest));

                        RegistrationResponse regResponse = null;
                        await flow.StepAsync("SubmitRegistrationToCSC", async () =>
                        {
                            regResponse = await CscGlobalClient.SubmitRegistrationAsync(enrollmentRequest);
                        });
                        enrollmentResponse = regResponse;

                        if (enrollmentResponse == null)
                        {
                            flow.Fail("ParseResponse", "API returned null");
                            return new EnrollmentResult
                            {
                                Status = 30,
                                StatusMessage = "Enrollment failed: CSC API returned a null response."
                            };
                        }
                        flow.Step("ParseResponse", $"error={enrollmentResponse.RegistrationError != null}");
                        Logger.LogTrace("Enrollment Response JSON: {Json}", JsonConvert.SerializeObject(enrollmentResponse));
                    }
                    else
                    {
                        flow.Fail("RejectExpiredRenew", "PriorCertSN present on New enrollment");
                        return new EnrollmentResult
                        {
                            Status = 30,
                            StatusMessage = "You cannot renew an expired cert please perform an new enrollment."
                        };
                    }

                    var enrollResult = _requestManager.GetEnrollmentResult(enrollmentResponse);
                    flow.Step("MapResult", $"Status={enrollResult?.Status}, ID={enrollResult?.CARequestID ?? "(null)"}");

                    await flow.StepAsync("PublishCnameDcv", async () =>
                    {
                        await TryPublishCnameDcvAsync(productInfo, enrollResult);
                    });

                    EnrollmentResult? newPolled = null;
                    await flow.StepAsync("PollForIssuance", async () =>
                    {
                        newPolled = await TryPollForIssuedCertAsync(enrollResult?.CARequestID);
                    });
                    if (newPolled != null)
                    {
                        flow.Step("PollResult", "issued during poll window");
                        Logger.MethodExit(LogLevel.Debug);
                        return newPolled;
                    }

                    Logger.MethodExit(LogLevel.Debug);
                    return enrollResult;

                case EnrollmentType.RenewOrReissue:
                    flow.Step("SelectPath", "RenewOrReissue");

                    if (string.IsNullOrEmpty(priorSn))
                    {
                        flow.Fail("ValidatePriorSN", "PriorCertSN is empty");
                        return new EnrollmentResult
                        {
                            Status = 30,
                            StatusMessage = "RenewOrReissue failed: PriorCertSN is required but was not provided."
                        };
                    }

                    string order_id = null;
                    await flow.StepAsync("LookupOrderId", async () =>
                    {
                        order_id = await _certificateDataReader.GetRequestIDBySerialNumber(priorSn);
                    }, $"orderId={order_id ?? "(null)"}");

                    if (string.IsNullOrEmpty(order_id))
                    {
                        flow.Fail("ValidateOrderId", $"no order found for SN={priorSn}");
                        return new EnrollmentResult
                        {
                            Status = 30,
                            StatusMessage = $"RenewOrReissue failed: could not find order ID for serial number '{priorSn}'."
                        };
                    }

                    if (order_id.Length < 36)
                    {
                        flow.Fail("ValidateOrderId", $"order_id too short ({order_id.Length} chars)");
                        return new EnrollmentResult
                        {
                            Status = 30,
                            StatusMessage = $"RenewOrReissue failed: order ID '{order_id}' is too short to extract a UUID."
                        };
                    }
                    flow.Step("ValidateOrderId", $"orderId={order_id}");

                    // Determine renew vs reissue based on order expiry window.
                    var renewal = false;
                    try
                    {
                        CertificateResponse liveCert = null;
                        await flow.StepAsync("FetchLiveCertForDecision", async () =>
                        {
                            liveCert = await CscGlobalClient.SubmitGetCertificateAsync(order_id[..36]);
                        });

                        if (liveCert != null && DateTime.TryParse(liveCert.OrderDate, out var orderDate))
                        {
                            var orderExpiry = orderDate.AddYears(1);
                            var daysUntilOrderExpiry = (orderExpiry - DateTime.UtcNow).TotalDays;
                            renewal = daysUntilOrderExpiry <= RenewalWindowDays;
                            flow.Step("ComputeRenewalDecision",
                                $"orderDate={liveCert.OrderDate}, expiry={orderExpiry:dd-MMM-yyyy}, daysLeft={(int)daysUntilOrderExpiry}, window={RenewalWindowDays}, isRenewal={renewal}");
                        }
                        else
                        {
                            flow.Skip("ComputeRenewalDecision", "orderDate unavailable, falling back to cert expiry");
                            var expirationDate = _certificateDataReader.GetExpirationDateByRequestId(order_id)
                                ?? (await GetSingleRecord(order_id)).RevocationDate;
                            renewal = expirationDate < DateTime.Now;
                            flow.Step("FallbackExpiryCheck", $"expirationDate={expirationDate?.ToString("o") ?? "(null)"}, isRenewal={renewal}");
                        }
                    }
                    catch (Exception ex)
                    {
                        flow.Fail("FetchLiveCertForDecision", $"falling back: {ex.Message}");
                        Logger.LogWarning(ex, "RenewOrReissue: failed to fetch live cert, falling back to cert expiry.");
                        try
                        {
                            var expirationDate = _certificateDataReader.GetExpirationDateByRequestId(order_id)
                                ?? (await GetSingleRecord(order_id)).RevocationDate;
                            renewal = expirationDate < DateTime.Now;
                            flow.Step("FallbackExpiryCheck", $"isRenewal={renewal}");
                        }
                        catch (Exception fallbackEx)
                        {
                            flow.Fail("FallbackExpiryCheck", fallbackEx.Message);
                            return new EnrollmentResult
                            {
                                Status = 30,
                                StatusMessage = $"RenewOrReissue failed: unable to determine renewal status for order '{order_id}'. {fallbackEx.Message}"
                            };
                        }
                    }

                    flow.Step("RenewalDecision", renewal ? "RENEWAL (paid order)" : "REISSUE (free under active order)");

                    if (renewal)
                    {
                        if (productInfo.ProductParameters.ContainsKey("Applicant Last Name"))
                        {
                            uUId = null;
                            await flow.StepAsync("LookupRenewalUUID", async () =>
                            {
                                uUId = await _certificateDataReader.GetRequestIDBySerialNumber(
                                    productInfo.ProductParameters["PriorCertSN"]);
                            });

                            if (string.IsNullOrEmpty(uUId))
                            {
                                flow.Fail("ValidateRenewalUUID", "could not resolve PriorCertSN");
                                return new EnrollmentResult
                                {
                                    Status = 30,
                                    StatusMessage = "Renewal failed: could not resolve prior certificate serial number to a request ID."
                                };
                            }
                            flow.Step("ValidateRenewalUUID", $"uuid={uUId}");

                            RenewalRequest builtRenewRequest = null;
                            flow.Step("BuildRenewalRequest", () =>
                            {
                                builtRenewRequest = _requestManager.GetRenewalRequest(productInfo, uUId, csr, san, customFields);
                            });
                            renewRequest = builtRenewRequest;
                            Logger.LogTrace("Renewal Request JSON: {Json}", JsonConvert.SerializeObject(renewRequest));

                            RenewalResponse renewResponse = null;
                            await flow.StepAsync("SubmitRenewalToCSC", async () =>
                            {
                                renewResponse = await CscGlobalClient.SubmitRenewalAsync(renewRequest);
                            });

                            if (renewResponse == null)
                            {
                                flow.Fail("ParseRenewalResponse", "API returned null");
                                return new EnrollmentResult
                                {
                                    Status = 30,
                                    StatusMessage = "Renewal failed: CSC API returned a null response."
                                };
                            }

                            Logger.LogTrace("Renewal Response JSON: {Json}", JsonConvert.SerializeObject(renewResponse));
                            var renewResult = _requestManager.GetRenewResponse(renewResponse);
                            flow.Step("MapRenewalResult", $"Status={renewResult?.Status}, Message={renewResult?.StatusMessage ?? "(null)"}");

                            EnrollmentResult? renewPolled = null;
                            await flow.StepAsync("PollForIssuance", async () =>
                            {
                                renewPolled = await TryPollForIssuedCertAsync(renewResult?.CARequestID);
                            });
                            Logger.MethodExit(LogLevel.Debug);
                            return renewPolled ?? renewResult;
                        }

                        flow.Fail("MissingEnrollmentParams", "Applicant Last Name not present — one-click renew unavailable");
                        return new EnrollmentResult
                        {
                            Status = 30,
                            StatusMessage =
                                "One click Renew Is Not Available for this Certificate Type.  Use the configure button instead."
                        };
                    }

                    // Reissue path
                    if (productInfo.ProductParameters.ContainsKey("Applicant Last Name"))
                    {
                        string requestid = null;
                        await flow.StepAsync("LookupReissueRequestId", async () =>
                        {
                            requestid = await _certificateDataReader.GetRequestIDBySerialNumber(
                                productInfo.ProductParameters["PriorCertSN"]);
                        });

                        if (string.IsNullOrEmpty(requestid))
                        {
                            flow.Fail("ValidateReissueRequestId", "could not resolve PriorCertSN");
                            return new EnrollmentResult
                            {
                                Status = 30,
                                StatusMessage = "Reissue failed: could not resolve prior certificate serial number to a request ID."
                            };
                        }

                        if (requestid.Length < 36)
                        {
                            flow.Fail("ValidateReissueRequestId", $"requestid too short ({requestid.Length} chars)");
                            return new EnrollmentResult
                            {
                                Status = 30,
                                StatusMessage = $"Reissue failed: request ID '{requestid}' is too short to extract a UUID."
                            };
                        }

                        uUId = requestid.Substring(0, 36);
                        flow.Step("ExtractReissueUUID", $"uuid={uUId}");

                        ReissueRequest builtReissueRequest = null;
                        flow.Step("BuildReissueRequest", () =>
                        {
                            builtReissueRequest = _requestManager.GetReissueRequest(productInfo, uUId, csr, san, customFields);
                        });
                        reissueRequest = builtReissueRequest;
                        Logger.LogTrace("Reissue JSON: {Json}", JsonConvert.SerializeObject(reissueRequest));

                        ReissueResponse reissueResponse = null;
                        await flow.StepAsync("SubmitReissueToCSC", async () =>
                        {
                            reissueResponse = await CscGlobalClient.SubmitReissueAsync(reissueRequest);
                        });

                        if (reissueResponse == null)
                        {
                            flow.Fail("ParseReissueResponse", "API returned null");
                            return new EnrollmentResult
                            {
                                Status = 30,
                                StatusMessage = "Reissue failed: CSC API returned a null response."
                            };
                        }

                        Logger.LogTrace("Reissue Response JSON: {Json}", JsonConvert.SerializeObject(reissueResponse));
                        var reissueResult = _requestManager.GetReIssueResult(reissueResponse);
                        flow.Step("MapReissueResult", $"Status={reissueResult?.Status}, Message={reissueResult?.StatusMessage ?? "(null)"}");

                        EnrollmentResult? reissuePolled = null;
                        await flow.StepAsync("PollForIssuance", async () =>
                        {
                            reissuePolled = await TryPollForIssuedCertAsync(reissueResult?.CARequestID);
                        });
                        Logger.MethodExit(LogLevel.Debug);
                        return reissuePolled ?? reissueResult;
                    }

                    flow.Fail("MissingEnrollmentParams", "Applicant Last Name not present — one-click reissue unavailable");
                    return new EnrollmentResult
                    {
                        Status = 30,
                        StatusMessage =
                            "One click Renew Is Not Available for this Certificate Type.  Use the configure button instead."
                    };

                default:
                    flow.Fail("UnhandledType", $"enrollmentType={enrollmentType}");
                    return new EnrollmentResult
                    {
                        Status = 30,
                        StatusMessage = $"Enroll failed: unhandled enrollment type '{enrollmentType}'."
                    };
            }
        }
        catch (AggregateException ae)
        {
            var inner = ae.Flatten().InnerException;
            flow.Fail("UNHANDLED", inner?.Message ?? ae.Message);
            Logger.LogError(inner, "Enroll: AggregateException during {EnrollmentType}: {Message}", enrollmentType, inner?.Message ?? ae.Message);
            return new EnrollmentResult
            {
                Status = 30,
                StatusMessage = $"Enrollment failed with error: {inner?.Message ?? ae.Message}"
            };
        }
        catch (Exception ex)
        {
            flow.Fail("UNHANDLED", ex.Message);
            Logger.LogError(ex, "Enroll: unhandled exception during {EnrollmentType}: {Message}", enrollmentType, ex.Message);
            return new EnrollmentResult
            {
                Status = 30,
                StatusMessage = $"Enrollment failed with error: {ex.Message}"
            };
        }
    }

    //done
    public async Task Ping()
    {
        Logger.MethodEntry();
        Logger.LogTrace("Ping: Enabled={Enabled}, CscGlobalClient is {Null}", Enabled, CscGlobalClient == null ? "NULL" : "present");

        if (!Enabled)
        {
            Logger.LogWarning("The CA is currently in the Disabled state. It must be Enabled to perform operations. Skipping Ping.");
            Logger.MethodExit();
            return;
        }

        try
        {
            Logger.LogInformation("Ping request received");
        }
        catch (Exception e)
        {
            Logger.LogError(e, "There was an error contacting CSCGlobal: {Message}", e.Message);
            throw new Exception($"Error attempting to ping CSCGlobal: {e.Message}.", e);
        }

        Logger.MethodExit();
    }

    //do
    public async Task ValidateCAConnectionInfo(Dictionary<string, object> connectionInfo)
    {
        Logger.MethodEntry(LogLevel.Debug);
        Logger.LogTrace("ValidateCAConnectionInfo called. connectionInfo is {Null}, keys=[{Keys}]",
            connectionInfo == null ? "NULL" : "present",
            connectionInfo != null ? string.Join(", ", connectionInfo.Keys) : "");

        if (connectionInfo == null)
        {
            Logger.LogError("ValidateCAConnectionInfo: connectionInfo is null.");
            throw new ArgumentNullException(nameof(connectionInfo), "connectionInfo cannot be null.");
        }

        // Honor the Enabled flag from the incoming connectionInfo (which may differ from Initialize's
        // snapshot when the operator is currently editing the CA). If disabled, skip validation so
        // the CA can be saved without valid credentials.
        var incomingEnabled = true;
        if (connectionInfo.TryGetValue(Constants.Enabled, out var enabledObj) &&
            bool.TryParse(enabledObj?.ToString(), out var parsed))
            incomingEnabled = parsed;

        if (!incomingEnabled)
        {
            Logger.LogWarning("The CA is currently in the Disabled state. It must be Enabled to perform operations. Skipping ValidateCAConnectionInfo.");
            Logger.MethodExit(LogLevel.Debug);
            return;
        }

        Logger.MethodExit(LogLevel.Debug);
    }

    //do
    public async Task ValidateProductInfo(EnrollmentProductInfo productInfo,
        Dictionary<string, object> connectionInfo)
    {
        Logger.MethodEntry(LogLevel.Debug);
        Logger.LogTrace("ValidateProductInfo called. productInfo is {Null}, productId='{ProductId}'",
            productInfo == null ? "NULL" : "present",
            productInfo?.ProductID ?? "(null)");

        if (productInfo == null)
        {
            Logger.LogError("ValidateProductInfo: productInfo is null.");
            throw new ArgumentNullException(nameof(productInfo), "productInfo cannot be null.");
        }

        // Honor the Enabled flag from the incoming connectionInfo. If the CA is disabled, skip
        // validation so a template can be saved on a disabled CA (pre-configuration workflow).
        var incomingEnabled = true;
        if (connectionInfo != null &&
            connectionInfo.TryGetValue(Constants.Enabled, out var enabledObj) &&
            bool.TryParse(enabledObj?.ToString(), out var parsed))
            incomingEnabled = parsed;

        if (!incomingEnabled)
        {
            Logger.LogWarning("The CA is currently in the Disabled state. It must be Enabled to perform operations. Skipping ValidateProductInfo.");
            Logger.MethodExit(LogLevel.Debug);
            return;
        }

        if (string.IsNullOrEmpty(productInfo.ProductID))
        {
            Logger.LogError("ValidateProductInfo: productInfo.ProductID is null or empty.");
            throw new ArgumentException("ProductID cannot be null or empty.", nameof(productInfo));
        }

        var certType = ProductIDs.productIds.Find(x =>
            x.Equals(productInfo.ProductID, StringComparison.InvariantCultureIgnoreCase));

        if (certType == null)
        {
            Logger.LogError("ValidateProductInfo: cannot find product ID '{ProductId}'. Known IDs: [{KnownIds}]",
                productInfo.ProductID, string.Join(", ", ProductIDs.productIds));
            throw new ArgumentException($"Cannot find {productInfo.ProductID}", "ProductId");
        }

        Logger.LogInformation("Validated {CertType} configured for AnyGateway", certType);
        Logger.MethodExit(LogLevel.Debug);
    }

    //done
    public Dictionary<string, PropertyConfigInfo> GetCAConnectorAnnotations()
    {
        return new Dictionary<string, PropertyConfigInfo>
        {
            [Constants.Enabled] = new()
            {
                Comments = "Flag to Enable or Disable gateway functionality. Disabling is primarily used to allow creation of the CA prior to configuration information being available.",
                Hidden = false,
                DefaultValue = true,
                Type = "Boolean"
            },
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
            [Constants.SyncFilterDays] = new()
            {
                Comments = "Number of days from today to filter certificates by expiration date during incremental sync.",
                Hidden = false,
                DefaultValue = "5",
                Type = "Number"
            },
            [Constants.RenewalWindowDays] = new()
            {
                Comments = "Number of days before the annual order expiry within which a RenewOrReissue triggers a paid Renewal rather than a free Reissue. Default is 30.",
                Hidden = false,
                DefaultValue = "30",
                Type = "Number"
            },
            [Constants.DcvPollTimeoutSeconds] = new()
            {
                Comments = "Max seconds to synchronously poll CSC for issuance after submitting an order (and publishing CNAME DCV). 0 disables polling (enrollment returns pending immediately; cert arrives on next sync). When >0, fast-validating orders can return the cert directly. Keep small to avoid long-blocking enrollment requests.",
                Hidden = false,
                DefaultValue = "0",
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

    /// <summary>
    ///     Strip a single trailing dot from a DNS name. CSC returns FQDN-canonical names with
    ///     a trailing dot but the framework's Domain Validation Configurations are stored without
    ///     one, so the strings have to be normalized before lookup or the equality check fails.
    /// </summary>
    private static string StripTrailingDot(string? s)
    {
        if (string.IsNullOrEmpty(s)) return s ?? string.Empty;
        return s.EndsWith('.') ? s[..^1] : s;
    }

    /// <summary>
    ///     Synchronously poll CSC for issuance of the order identified by <paramref name="uuid"/>,
    ///     up to <see cref="DcvPollTimeoutSeconds"/>. Returns a GENERATED <see cref="EnrollmentResult"/>
    ///     carrying the issued leaf certificate if CSC issues within the window, or null if the
    ///     window expires (in which case the caller falls back to its pending/EXTERNALVALIDATION result).
    ///     No-op (returns null) when polling is disabled or the uuid is missing.
    /// </summary>
    private async Task<EnrollmentResult?> TryPollForIssuedCertAsync(string? uuid)
    {
        if (DcvPollTimeoutSeconds <= 0)
        {
            Logger.LogTrace("TryPollForIssuedCertAsync: polling disabled (DcvPollTimeoutSeconds=0), skipping.");
            return null;
        }

        if (string.IsNullOrEmpty(uuid))
        {
            Logger.LogWarning("TryPollForIssuedCertAsync: no UUID/CARequestID to poll, skipping.");
            return null;
        }

        var deadline = DateTime.UtcNow.AddSeconds(DcvPollTimeoutSeconds);
        Logger.LogInformation("TryPollForIssuedCertAsync: polling CSC for issuance of '{Uuid}' for up to {Seconds}s (interval {Interval}s).",
            uuid, DcvPollTimeoutSeconds, (int)DcvPollInterval.TotalSeconds);

        var attempt = 0;
        while (DateTime.UtcNow < deadline)
        {
            attempt++;
            AnyCAPluginCertificate record;
            try
            {
                record = await GetSingleRecord(uuid);
            }
            catch (Exception ex)
            {
                Logger.LogWarning(ex, "TryPollForIssuedCertAsync: poll attempt {Attempt} for '{Uuid}' threw, will retry. {Error}",
                    attempt, uuid, ex.Message);
                record = null;
            }

            if (record != null)
            {
                Logger.LogTrace("TryPollForIssuedCertAsync: attempt {Attempt} for '{Uuid}' — status={Status}, cert={CertState}.",
                    attempt, uuid, record.Status, string.IsNullOrEmpty(record.Certificate) ? "empty" : "present");

                if (record.Status == (int)EndEntityStatus.GENERATED && !string.IsNullOrEmpty(record.Certificate))
                {
                    Logger.LogInformation("TryPollForIssuedCertAsync: '{Uuid}' issued after {Attempt} poll(s); returning cert directly.", uuid, attempt);
                    return new EnrollmentResult
                    {
                        Status = (int)EndEntityStatus.GENERATED,
                        CARequestID = uuid,
                        Certificate = record.Certificate,
                        StatusMessage = $"Certificate issued and retrieved for order {uuid}."
                    };
                }
            }

            // Don't sleep past the deadline.
            if (DateTime.UtcNow.Add(DcvPollInterval) >= deadline)
                break;

            await Task.Delay(DcvPollInterval);
        }

        Logger.LogInformation("TryPollForIssuedCertAsync: '{Uuid}' not issued within {Seconds}s after {Attempts} attempt(s); falling back to pending.",
            uuid, DcvPollTimeoutSeconds, attempt);
        return null;
    }

    /// <summary>
    ///     Publishes CNAME DCV records via the gateway framework's <see cref="IDomainValidatorFactory"/>.
    ///     Per-record resolution: each record is routed to whichever DNS provider plugin the framework
    ///     resolves for its domain. No-op if the factory wasn't injected, the cert isn't using CNAME
    ///     validation, or the response contains no CNAME details. Failures are logged but never thrown —
    ///     manual publishing remains a fallback so the enrollment result is still returned to Keyfactor.
    /// </summary>
    private async Task TryPublishCnameDcvAsync(EnrollmentProductInfo productInfo, EnrollmentResult? enrollResult)
    {
        if (_validatorFactory == null)
        {
            Logger.LogTrace("TryPublishCnameDcvAsync: no IDomainValidatorFactory was injected, skipping auto-publish.");
            return;
        }

        if (enrollResult?.EnrollmentContext == null || enrollResult.EnrollmentContext.Count == 0)
        {
            Logger.LogTrace("TryPublishCnameDcvAsync: no CNAME entries in EnrollmentContext, skipping.");
            return;
        }

        var dcvMethod = productInfo?.ProductParameters != null
            && productInfo.ProductParameters.TryGetValue(EnrollmentConfigConstants.DomainControlValidationMethod, out var m)
            ? m
            : null;

        if (string.IsNullOrEmpty(dcvMethod) ||
            !string.Equals(dcvMethod, "CNAME", StringComparison.OrdinalIgnoreCase))
        {
            Logger.LogTrace("TryPublishCnameDcvAsync: DCV method '{Method}' is not CNAME, skipping auto-publish.", dcvMethod ?? "(null)");
            return;
        }

        Logger.LogInformation(
            "TryPublishCnameDcvAsync: attempting to publish {Count} CNAME record(s) via framework DNS providers (validation type '{Type}').",
            enrollResult.EnrollmentContext.Count, DNS_VALIDATION_TYPE);

        var successCount = 0;
        var failCount = 0;
        var unresolvedCount = 0;

        foreach (var entry in enrollResult.EnrollmentContext)
        {
            var rawRecordName = entry.Key;
            var rawCnameTarget = entry.Value;

            // CSC may also surface DCV email entries in this dictionary (key == value). Skip those.
            if (string.Equals(rawRecordName, rawCnameTarget, StringComparison.OrdinalIgnoreCase))
            {
                Logger.LogTrace("TryPublishCnameDcvAsync: skipping entry '{Key}' (looks like an email DCV passthrough, not a CNAME).", rawRecordName);
                continue;
            }

            // CSC returns FQDN-canonical names with trailing dots (e.g. "foo.example.com.").
            // The framework's Domain Validation Configuration stores domain patterns without
            // the trailing dot, so strip it before resolution and publishing or no provider
            // will match (the framework will look up "*.example.com." which won't equal "*.example.com").
            var recordName = StripTrailingDot(rawRecordName);
            var cnameTarget = StripTrailingDot(rawCnameTarget);

            if (recordName != rawRecordName)
                Logger.LogTrace("TryPublishCnameDcvAsync: normalized record name '{Raw}' -> '{Normalized}'.", rawRecordName, recordName);

            IDomainValidator? validator;
            try
            {
                validator = _validatorFactory.ResolveDomainValidator(recordName, DNS_VALIDATION_TYPE);
            }
            catch (Exception ex)
            {
                unresolvedCount++;
                Logger.LogWarning(ex, "ResolveDomainValidator threw for '{Record}' (type '{Type}'): {Error}",
                    recordName, DNS_VALIDATION_TYPE, ex.Message);
                continue;
            }

            if (validator == null)
            {
                unresolvedCount++;
                Logger.LogWarning(
                    "No DNS provider matched domain '{Record}' for validation type '{Type}'. Manual publish required for this record.",
                    recordName, DNS_VALIDATION_TYPE);
                continue;
            }

            try
            {
                Logger.LogTrace("StageValidation: '{Name}' -> '{Target}' via validator type '{ValType}'.",
                    recordName, cnameTarget, validator.GetValidationType());
                var result = await validator.StageValidation(recordName, cnameTarget, CancellationToken.None);

                if (result?.Success == true)
                {
                    successCount++;
                    Logger.LogInformation("Published CNAME '{Name}' -> '{Target}' (status='{Status}').",
                        recordName, cnameTarget, result.Status ?? "(none)");
                }
                else
                {
                    failCount++;
                    Logger.LogWarning(
                        "StageValidation reported failure for CNAME '{Name}'. Status='{Status}', Error='{Error}'. Manual publish may be required.",
                        recordName, result?.Status ?? "(none)", result?.ErrorMessage ?? "(none)");
                }
            }
            catch (Exception ex)
            {
                failCount++;
                Logger.LogError(ex, "StageValidation threw publishing CNAME '{Name}'. Manual publish may be required. {Error}",
                    recordName, ex.Message);
            }
        }

        Logger.LogInformation(
            "TryPublishCnameDcvAsync: complete. Published={Published}, Failed={Failed}, Unresolved={Unresolved}",
            successCount, failCount, unresolvedCount);
    }

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