// Copyright 2021 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.

using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.CSCGlobal;
using Xunit;

namespace CscGlobalCAPluginTests;

public class CSCGlobalCAPluginTests
{
    private static EnrollmentProductInfo ProductInfo(string productId) =>
        new EnrollmentProductInfo { ProductID = productId, ProductParameters = new Dictionary<string, string>() };

    [Theory]
    [InlineData("CSC TrustedSecure DV")]
    [InlineData("CSC TrustedSecure DV Wildcard, Multiple Names")]
    public async Task ValidateProductInfo_CanonicalProductName_DoesNotThrow(string productId)
    {
        var plugin = new CSCGlobalCAPlugin();
        // Parameterless constructor per plugin's own doc comment: runs without DNS
        // auto-publishing, which ValidateProductInfo does not depend on.
        await plugin.ValidateProductInfo(ProductInfo(productId), new Dictionary<string, object>());
    }

    [Theory]
    [InlineData("CSC TrustedSecure UC Certificate")]
    [InlineData("CSC TrustedSecure Domain Validated SSL")]
    [InlineData("CSC Trusted Secure Domain Validated Wildcard SSL")]
    public async Task ValidateProductInfo_LegacyProductName_DoesNotThrow(string legacyProductId)
    {
        var plugin = new CSCGlobalCAPlugin();
        await plugin.ValidateProductInfo(ProductInfo(legacyProductId), new Dictionary<string, object>());
    }

    [Fact]
    public async Task ValidateProductInfo_UnknownProduct_Throws()
    {
        var plugin = new CSCGlobalCAPlugin();
        await Assert.ThrowsAsync<ArgumentException>(() =>
            plugin.ValidateProductInfo(ProductInfo("Not A Real Product"), new Dictionary<string, object>()));
    }

    [Fact]
    public async Task ValidateProductInfo_DisabledConnector_SkipsValidationEvenForUnknownProduct()
    {
        var plugin = new CSCGlobalCAPlugin();
        var connectionInfo = new Dictionary<string, object> { [Constants.Enabled] = "false" };

        // Should not throw even though the product is unknown - Enabled=false short-circuits
        // validation entirely (pre-configuration workflow).
        await plugin.ValidateProductInfo(ProductInfo("Not A Real Product"), connectionInfo);
    }
}
