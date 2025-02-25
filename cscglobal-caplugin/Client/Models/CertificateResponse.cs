// Copyright 2021 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.
using Keyfactor.Extensions.CAPlugin.CSCGlobal.Interfaces;
using Newtonsoft.Json;

namespace Keyfactor.Extensions.CAPlugin.CSCGlobal.Client.Models;

public class CertificateResponse : ICertificateResponse
{
    [JsonProperty("uuid")] public string Uuid { get; set; }
    [JsonProperty("commonName")] public string CommonName { get; set; }
    [JsonProperty("additionalNames")] public List<string> AdditionalNames { get; set; }
    [JsonProperty("certificateType")] public string CertificateType { get; set; }
    [JsonProperty("status")] public string Status { get; set; }
    [JsonProperty("effectiveDate")] public string EffectiveDate { get; set; }
    [JsonProperty("expirationDate")] public string ExpirationDate { get; set; }
    [JsonProperty("businessUnit")] public string BusinessUnit { get; set; }
    [JsonProperty("orderedBy")] public string OrderedBy { get; set; }
    [JsonProperty("orderDate")] public string OrderDate { get; set; }
    [JsonProperty("serverSoftware")] public object ServerSoftware { get; set; }
    [JsonProperty("certificate")] public string Certificate { get; set; }
}