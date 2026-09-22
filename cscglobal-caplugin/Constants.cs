// Copyright 2021 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

namespace Keyfactor.Extensions.CAPlugin.CSCGlobal;

public class Constants
{
    public static string Enabled = "Enabled";
    public static string CscGlobalUrl = "CscGlobalUrl";
    public static string CscGlobalApiKey = "ApiKey";
    public static string BearerToken = "BearerToken";
    public static string DefaultPageSize = "DefaultPageSize";
    public static string SyncFilterDays = "SyncFilterDays";
    public static string RenewalWindowDays = "RenewalWindowDays";
}
    
public class ProductIDs
{
    public static List<String> productIds = new List<string>()
    {
        "CSC TrustedSecure OV",
        "CSC TrustedSecure OV Wildcard",
        "CSC TrustedSecure OV, Multiple Names",
        "CSC TrustedSecure EV",
        "CSC TrustedSecure DV",
        "CSC TrustedSecure DV Wildcard",
        "CSC TrustedSecure DV, Multiple Names",
        "CSC TrustedSecure EV, Multiple Names",
        "CSC TrustedSecure OV Wildcard, Multiple Names",
        "CSC TrustedSecure DV Wildcard, Multiple Names"
    };

    // Pre-1.2.0 template names. Existing Certificate Templates in Command may still
    // reference these, so they're accepted as aliases for their canonical replacement.
    public static Dictionary<string, string> legacyProductIdAliases =
        new(StringComparer.InvariantCultureIgnoreCase)
        {
            ["CSC TrustedSecure Premium Certificate"] = "CSC TrustedSecure OV",
            ["CSC TrustedSecure Premium Wildcard Certificate"] = "CSC TrustedSecure OV Wildcard",
            ["CSC TrustedSecure UC Certificate"] = "CSC TrustedSecure OV, Multiple Names",
            ["CSC TrustedSecure EV Certificate"] = "CSC TrustedSecure EV",
            ["CSC TrustedSecure Domain Validated SSL"] = "CSC TrustedSecure DV",
            ["CSC TrustedSecure Domain Validated Wildcard SSL"] = "CSC TrustedSecure DV Wildcard",
            ["CSC TrustedSecure Domain Validated UC Certificate"] = "CSC TrustedSecure DV, Multiple Names"
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