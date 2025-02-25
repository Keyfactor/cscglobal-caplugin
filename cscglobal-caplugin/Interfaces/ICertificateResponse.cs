// Copyright 2021 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.
namespace Keyfactor.Extensions.CAPlugin.CSCGlobal.Interfaces;

public interface ICertificateResponse
{
    string Uuid { get; set; }
    string CommonName { get; set; }
    List<string> AdditionalNames { get; set; }
    string CertificateType { get; set; }
    string Status { get; set; }
    string EffectiveDate { get; set; }
    string ExpirationDate { get; set; }
    string BusinessUnit { get; set; }
    string OrderedBy { get; set; }
    string OrderDate { get; set; }
    object ServerSoftware { get; set; }
    string Certificate { get; set; }
}