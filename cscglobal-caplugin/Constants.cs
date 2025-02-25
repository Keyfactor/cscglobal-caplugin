// Copyright 2021 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

namespace Keyfactor.Extensions.CAPlugin.CSCGlobal;

public class Constants
{
    public static string CscGlobalUrl = "CscGlobalUrl";
    public static string CscGlobalApiKey = "ApiKey";
    public static string BearerToken = "BearerToken";
    public static string DefaultPageSize = "DefaultPageSize";
    public static string TemplateSync = "TemplateSync";
}




public static class EnrollmentConfigConstants
{
    public const string LastName = "LastName";
    public const string FirstName = "FirstName";
    public const string Email = "Email";
    public const string Phone = "Phone";

    public const string OrganizationName = "OrganizationName";
    public const string OrganizationAddress = "OrganizationAddress";
    public const string OrganizationCity = "OrganizationCity";
    public const string OrganizationState = "OrganizationState";
    public const string OrganizationCountry = "OrganizationCountry";
    public const string OrganizationPhone = "OrganizationPhone";

    public const string JobTitle = "JobTitle";
    public const string RegistrationAgent = "RegistrationAgent";
    public const string RegistrationNumber = "RegistrationNumber";

    public const string RootCAType = "RootCAType";
    public const string SlotSize = "SlotSize";
    public const string CertificateValidityInYears = "CertificateValidityInYears";
}