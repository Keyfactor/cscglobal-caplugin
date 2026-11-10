// Copyright 2021 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.

using System.Collections.Concurrent;
using System.Net;
using System.Text;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.CSCGlobal;
using Keyfactor.Extensions.CAPlugin.CSCGlobal.Client.Models;
using Keyfactor.Extensions.CAPlugin.CSCGlobal.MockData;
using Newtonsoft.Json;

// Starts a real HTTP server on localhost implementing CSC's list/get certificate endpoints,
// backed by MidCycleReissueFixtures, then runs the real (unmodified) CSCGlobalCAPlugin.Synchronize
// against it over an actual HTTP connection - not a mocked ICscGlobalClient. This is the "does it
// actually behave this way when sync runs for real" check that a unit test alone can't give you.

const string baseUrl = "http://localhost:58242/";

var results = new List<CertificateResponse>
{
    MidCycleReissueFixtures.SingleNameBaseline(),
    MidCycleReissueFixtures.SingleNameMidCycleReissue(),
    MidCycleReissueFixtures.WildcardMultiNameBaseline(),
    MidCycleReissueFixtures.WildcardMultiNameMidCycleReissue()
};

using var listener = new HttpListener();
listener.Prefixes.Add(baseUrl);
listener.Start();
Console.WriteLine($"Mock CSC server listening on {baseUrl}");

var serverCts = new CancellationTokenSource();
var serverTask = Task.Run(() => RunServerAsync(listener, results, serverCts.Token));

try
{
    var config = new MockConfigProvider
    {
        CAConnectionData = new Dictionary<string, object>
        {
            [Constants.CscGlobalUrl] = baseUrl,
            [Constants.CscGlobalApiKey] = "mock-api-key",
            [Constants.BearerToken] = "mock-bearer-token"
        }
    };

    var plugin = new CSCGlobalCAPlugin();
    plugin.Initialize(config, new MockCertificateDataReader());

    var buffer = new BlockingCollection<AnyCAPluginCertificate>();

    Console.WriteLine("\nRunning a real Synchronize() call against the mock server...\n");
    await plugin.Synchronize(buffer, null, true, CancellationToken.None);

    var synced = buffer.ToList();
    Console.WriteLine($"Synchronize queued {synced.Count} certificate(s):\n");
    foreach (var cert in synced)
    {
        Console.WriteLine($"  CARequestID: {cert.CARequestID}");
        Console.WriteLine($"  ProductID:   {cert.ProductID}");
        Console.WriteLine($"  Status:      {cert.Status}");
        Console.WriteLine($"  Certificate: {cert.Certificate?[..40]}...");
        Console.WriteLine();
    }

    var byUuid = synced.GroupBy(c => c.CARequestID).Where(g => g.Count() > 1);
    foreach (var group in byUuid)
    {
        var distinctCerts = group.Select(c => c.Certificate).Distinct().Count();
        Console.WriteLine($"CARequestID {group.Key} appeared {group.Count()} time(s) " +
                           $"with {distinctCerts} distinct certificate value(s) - " +
                           "this is the mid-cycle-reissue collision: nothing above " +
                           "distinguishes the reissue from an ordinary re-sync.");
    }
}
finally
{
    serverCts.Cancel();
    listener.Stop();
}

static async Task RunServerAsync(HttpListener listener, List<CertificateResponse> results, CancellationToken token)
{
    while (!token.IsCancellationRequested)
    {
        HttpListenerContext ctx;
        try
        {
            ctx = await listener.GetContextAsync().WaitAsync(token);
        }
        catch (OperationCanceledException)
        {
            return;
        }
        catch (ObjectDisposedException)
        {
            return;
        }

        var path = ctx.Request.Url?.AbsolutePath ?? "";
        Console.WriteLine($"[mock] {ctx.Request.HttpMethod} {ctx.Request.Url}");

        object responseBody;
        if (path == "/dbs/api/v2/tls/certificate")
        {
            responseBody = new CertificateListResponse
            {
                Meta = new Meta { NumResults = results.Count },
                Results = results
            };
        }
        else if (path.StartsWith("/dbs/api/v2/tls/certificate/"))
        {
            var uuid = path[(path.LastIndexOf('/') + 1)..];
            responseBody = results.FirstOrDefault(r => r.Uuid == uuid)
                           ?? (object)new { error = "not found" };
        }
        else
        {
            ctx.Response.StatusCode = 404;
            ctx.Response.Close();
            continue;
        }

        var json = JsonConvert.SerializeObject(responseBody);
        var bytes = Encoding.UTF8.GetBytes(json);
        ctx.Response.ContentType = "application/json";
        ctx.Response.ContentLength64 = bytes.Length;
        await ctx.Response.OutputStream.WriteAsync(bytes);
        ctx.Response.Close();
    }
}

internal sealed class MockConfigProvider : IAnyCAPluginConfigProvider
{
    public Dictionary<string, object> CAConnectionData { get; set; } = new();
}

internal sealed class MockCertificateDataReader : ICertificateDataReader
{
    public Task<int> GetStatusByRequestID(string caRequestID) => Task.FromResult(0);
    public Task<bool> DoesCertExistForRequestID(string caRequestID) => Task.FromResult(false);
    public Task<string> GetRequestIDBySerialNumber(string serialNumber) => Task.FromResult(string.Empty);
    public DateTime? GetExpirationDateByRequestId(string caRequestID) => null;
}
