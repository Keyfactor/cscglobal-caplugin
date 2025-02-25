﻿// Copyright 2021 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.
using Keyfactor.Extensions.CAPlugin.CSCGlobal.Client.Models;

namespace Keyfactor.Extensions.CAPlugin.CSCGlobal.Interfaces;

public interface IRenewalRequest
{
    string Uuid { get; set; }
    string Csr { get; set; }
    string CertificateType { get; set; }
    string BusinessUnit { get; set; }
    string Term { get; set; }
    string ServerSoftware { get; set; }
    string OrganizationContact { get; set; }
    DomainControlValidation DomainControlValidation { get; set; }
    Notifications Notifications { get; set; }
    bool ShowPrice { get; set; }
    List<CustomField> CustomFields { get; set; }
    string ApplicantFirstName { get; set; }
    string ApplicantLastName { get; set; }
    string ApplicantEmailAddress { get; set; }
    string ApplicantPhoneNumber { get; set; }
    List<SubjectAlternativeName> SubjectAlternativeNames { get; set; }
    EvCertificateDetails EvCertificateDetails { get; set; }
}