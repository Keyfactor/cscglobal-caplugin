// Copyright 2021 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

namespace Keyfactor.Extensions.CAPlugin.CSCGlobal.Interfaces;

/// <summary>
///     Contract implemented by external DNS provider plugins so the CSC plugin can
///     auto-publish CNAME records required by CSC's Domain Control Validation (DCV).
///
///     Resolution happens **per domain** at enrollment time. The framework asks each
///     registered provider <see cref="CanHandleDomain"/> and uses the first match —
///     so a single CA can publish across multiple DNS providers (e.g. some domains
///     on Cloudflare, others on Route 53) without per-CA configuration.
/// </summary>
public interface IDnsProvider
{
    /// <summary>The unique provider name (e.g. "Cloudflare", "Route53", "Azure").</summary>
    string Name { get; }

    /// <summary>
    ///     Returns true if this provider owns the DNS zone for the given record name and can
    ///     therefore publish a CNAME on its behalf. Typically implemented by listing managed
    ///     zones from the provider's API and matching by suffix.
    /// </summary>
    /// <param name="recordName">The FQDN of the record being considered (e.g. "_dcv.example.com").</param>
    bool CanHandleDomain(string recordName);

    /// <summary>
    ///     Publish a CNAME DCV record for the given record name pointing at the supplied target.
    /// </summary>
    /// <param name="recordName">FQDN of the record to create (e.g. "_dcv.example.com").</param>
    /// <param name="cnameTarget">Target value the CNAME should resolve to (supplied by CSC).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>True if the record was created (or already existed and matches); false on failure.</returns>
    Task<bool> CreateCnameRecordAsync(string recordName, string cnameTarget, CancellationToken cancellationToken = default);

    /// <summary>
    ///     Remove a previously created CNAME DCV record. Called after CSC validation completes
    ///     (or during cleanup). Implementations should be tolerant of missing records.
    /// </summary>
    /// <param name="recordName">FQDN of the record to remove.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>True if the record was removed (or not present); false on failure.</returns>
    Task<bool> DeleteCnameRecordAsync(string recordName, CancellationToken cancellationToken = default);
}
