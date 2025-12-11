// Copyright 2021 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using Keyfactor.Extensions.CAPlugin.CSCGlobal.Interfaces;
using Newtonsoft.Json;

namespace Keyfactor.Extensions.CAPlugin.CSCGlobal.Client.Models;

public class ReissueRequest : IReissueRequest
{
    [JsonProperty("uuid")] public string Uuid { get; set; }
    [JsonProperty("csr")] public string Csr { get; set; }
    [JsonProperty("certificateType")] public string CertificateType { get; set; }
    [JsonProperty("businessUnit")] public string BusinessUnit { get; set; }
    [JsonProperty("term")] public string Term { get; set; }
    [JsonProperty("serverSoftware")] public string ServerSoftware { get; set; }
    [JsonProperty("organizationContact")] public string OrganizationContact { get; set; }

    [JsonProperty("domainControlValidation")]
    public DomainControlValidation DomainControlValidation { get; set; }

    [JsonProperty("notifications")] public Notifications Notifications { get; set; }
    [JsonProperty("showPrice")] public bool ShowPrice { get; set; }
    [JsonProperty("customFields")] public List<CustomField> CustomFields { get; set; }
    [JsonProperty("applicantFirstName")] public string ApplicantFirstName { get; set; }
    [JsonProperty("applicantLastName")] public string ApplicantLastName { get; set; }

    [JsonProperty("applicantEmailAddress")]
    public string ApplicantEmailAddress { get; set; }

    [JsonProperty("applicantPhoneNumber")] public string ApplicantPhoneNumber { get; set; }

    [JsonProperty("subjectAlternativeNames", NullValueHandling = NullValueHandling.Ignore)]
    public List<SubjectAlternativeName> SubjectAlternativeNames { get; set; }

    [JsonProperty("evCertificateDetails", NullValueHandling = NullValueHandling.Ignore)]
    public EvCertificateDetails EvCertificateDetails { get; set; }
}