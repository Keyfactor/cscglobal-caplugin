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
    
public class ProductIDs
{
    public static List<String> productIds = new List<string>()
    {
        "CSC TrustedSecure Premium Certificate",
        "CSC TrustedSecure EV Certificate",
        "CSC TrustedSecure UC Certificate",
        "CSC TrustedSecure Premium Wildcard Certificate",
        "CSC TrustedSecure Domain Validated SSL",
        "CSC TrustedSecure Domain Validated Wildcard SSL",
        "CSC TrustedSecure Domain Validated UC Certificate"
    };
}

public class EnrollmentConfigConstants
{
    public const string Term = "Term";
    public const string ApplicantFirstName = "Applicant First Name";
    public const string ApplicantLastName = "Applicant Last Name";
    public const string ApplicantEmailAddress = "Applicant Email Address";
    public const string ApplicantPhone = "Applicant Phone";
    public const string DomainControlValidationMethod = "Domain Control Validation Method";
    public const string OrganizationContact = "Organization Contact";
    public const string BusinessUnit = "Business Unit";
    public const string NotificationEmailsCommaSeparated = "Notification Email(s) Comma Separated";
    public const string CnDcvEmail = "CN DCV Email";
    public const string OrganizationCountry = "Organization Country";
    public const string AdditionalSansCommaSeparatedDcvEmails = "Addtl Sans Comma Separated DCV Emails";
}