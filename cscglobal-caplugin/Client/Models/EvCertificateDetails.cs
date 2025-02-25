// Copyright 2021 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.
using Keyfactor.Extensions.CAPlugin.CSCGlobal.Interfaces;
using Newtonsoft.Json;

namespace Keyfactor.Extensions.CAPlugin.CSCGlobal.Client.Models;

public class EvCertificateDetails : IEvCertificateDetails
{
    [JsonProperty("country")] public string Country { get; set; }
    [JsonProperty("city")] public string City { get; set; }
    [JsonProperty("state")] public string State { get; set; }
    [JsonProperty("dateOfIncorporation")] public string DateOfIncorporation { get; set; }
    [JsonProperty("doingBusinessAs")] public string DoingBusinessAs { get; set; }
    [JsonProperty("businessCategory")] public string BusinessCategory { get; set; }
}