// Copyright 2021 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.CSCGlobal.Interfaces;
using Keyfactor.Logging;
using Microsoft.Extensions.Logging;

namespace Keyfactor.Extensions.CAPlugin.CSCGlobal.Dns;

/// <summary>
///     Registry of available <see cref="IDnsProvider"/> implementations. Resolution is
///     **per domain** — at enrollment time we ask each registered provider whether it
///     owns the DNS zone for a given record, and use the first match. This mirrors the
///     pattern used by the Keyfactor ACME CA plugin and avoids per-CA configuration of
///     a single global provider, so one CA can publish across multiple DNS providers.
///
///     Providers register themselves by being added to the <see cref="LoadProviders"/>
///     switch below as their concrete implementations land in the codebase.
/// </summary>
public class DnsProviderFactory
{
    private readonly ILogger _logger;
    private readonly List<IDnsProvider> _providers;

    public DnsProviderFactory(IAnyCAPluginConfigProvider configProvider)
    {
        _logger = LogHandler.GetClassLogger<DnsProviderFactory>();
        _providers = LoadProviders(configProvider);
        _logger.LogInformation("DnsProviderFactory initialized with {Count} provider(s): [{Names}]",
            _providers.Count,
            string.Join(", ", _providers.Select(p => p.Name)));
    }

    /// <summary>The set of providers known to this factory, in registration order.</summary>
    public IReadOnlyList<IDnsProvider> Providers => _providers;

    /// <summary>
    ///     Find the first registered provider that can handle the given record name.
    ///     Returns null if no provider claims ownership of the zone (in which case the
    ///     CNAME must be published manually).
    /// </summary>
    public IDnsProvider? ResolveForDomain(string recordName)
    {
        _logger.LogTrace("ResolveForDomain: looking up provider for '{Record}' across {Count} provider(s).",
            recordName ?? "(null)", _providers.Count);

        if (string.IsNullOrWhiteSpace(recordName))
        {
            _logger.LogWarning("ResolveForDomain: record name is null/empty, cannot resolve.");
            return null;
        }

        foreach (var provider in _providers)
        {
            try
            {
                if (provider.CanHandleDomain(recordName))
                {
                    _logger.LogTrace("ResolveForDomain: provider '{Provider}' claims '{Record}'.", provider.Name, recordName);
                    return provider;
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "ResolveForDomain: provider '{Provider}' threw in CanHandleDomain('{Record}'); skipping. {Error}",
                    provider.Name, recordName, ex.Message);
            }
        }

        _logger.LogDebug("ResolveForDomain: no provider claims '{Record}'.", recordName);
        return null;
    }

    /// <summary>
    ///     Instantiate the set of providers available to this gateway. Each provider
    ///     receives the full CA connection data so it can read its own configuration
    ///     keys (credentials, endpoints, etc.). Add new providers here as their
    ///     implementations land.
    /// </summary>
    private List<IDnsProvider> LoadProviders(IAnyCAPluginConfigProvider configProvider)
    {
        var providers = new List<IDnsProvider>();

        if (configProvider?.CAConnectionData == null)
        {
            _logger.LogWarning("LoadProviders: configProvider or CAConnectionData is null, no providers will be loaded.");
            return providers;
        }

        // Register concrete providers below as they are implemented. Each provider should
        // be defensive about its own configuration — only instantiate if required keys
        // are present so a missing/optional provider doesn't break the gateway.
        //
        // Example:
        //   if (configProvider.CAConnectionData.ContainsKey("Cloudflare_ApiToken"))
        //       providers.Add(new CloudflareDnsProvider(configProvider.CAConnectionData));

        return providers;
    }
}
