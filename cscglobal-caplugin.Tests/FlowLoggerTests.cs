// Copyright 2021 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.

using Keyfactor.Extensions.CAPlugin.CSCGlobal;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace CscGlobalCAPluginTests;

public class FlowLoggerTests
{
    private static Mock<ILogger> NewLoggerMock()
    {
        var mock = new Mock<ILogger>();
        mock.Setup(l => l.IsEnabled(It.IsAny<LogLevel>())).Returns(true);
        return mock;
    }

    [Fact]
    public void Constructor_NullLogger_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => new FlowLogger(null!, "Flow"));
    }

    [Fact]
    public void Constructor_NullFlowName_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => new FlowLogger(NewLoggerMock().Object, null!));
    }

    [Fact]
    public void Step_NoDetail_DoesNotThrowAndMarksNoFailure()
    {
        using var flow = new FlowLogger(NewLoggerMock().Object, "Flow");
        flow.Step("StepOne");
        Assert.False(flow.HasFailures);
    }

    [Fact]
    public void Step_WithDetail_DoesNotThrow()
    {
        using var flow = new FlowLogger(NewLoggerMock().Object, "Flow");
        flow.Step("StepOne", "some detail");
        Assert.False(flow.HasFailures);
    }

    [Fact]
    public void Step_Action_Success_RecordsSuccess()
    {
        using var flow = new FlowLogger(NewLoggerMock().Object, "Flow");
        var ran = false;
        flow.Step("Action", () => ran = true);
        Assert.True(ran);
        Assert.False(flow.HasFailures);
    }

    [Fact]
    public void Step_Action_Throws_RecordsFailureAndRethrows()
    {
        using var flow = new FlowLogger(NewLoggerMock().Object, "Flow");
        Assert.Throws<InvalidOperationException>(() =>
            flow.Step("Action", () => throw new InvalidOperationException("boom")));
        Assert.True(flow.HasFailures);
    }

    [Fact]
    public void Step_ActionWithDetail_Success()
    {
        using var flow = new FlowLogger(NewLoggerMock().Object, "Flow");
        flow.Step("Action", () => { }, "detail");
        Assert.False(flow.HasFailures);
    }

    [Fact]
    public async Task StepAsync_NoReturnValue_Success()
    {
        using var flow = new FlowLogger(NewLoggerMock().Object, "Flow");
        await flow.StepAsync("AsyncStep", () => Task.CompletedTask);
        Assert.False(flow.HasFailures);
    }

    [Fact]
    public async Task StepAsync_NoReturnValue_Throws_RecordsFailureAndRethrows()
    {
        using var flow = new FlowLogger(NewLoggerMock().Object, "Flow");
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            flow.StepAsync("AsyncStep", () => throw new InvalidOperationException("boom")));
        Assert.True(flow.HasFailures);
    }

    [Fact]
    public async Task StepAsync_WithReturnValue_Success_ReturnsResult()
    {
        using var flow = new FlowLogger(NewLoggerMock().Object, "Flow");
        var result = await flow.StepAsync("AsyncStep", () => Task.FromResult(42));
        Assert.Equal(42, result);
        Assert.False(flow.HasFailures);
    }

    [Fact]
    public async Task StepAsync_WithReturnValue_Throws_RecordsFailureAndRethrows()
    {
        using var flow = new FlowLogger(NewLoggerMock().Object, "Flow");
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            flow.StepAsync<int>("AsyncStep", () => throw new InvalidOperationException("boom")));
        Assert.True(flow.HasFailures);
    }

    [Fact]
    public void StepFunc_Success_ReturnsResult()
    {
        using var flow = new FlowLogger(NewLoggerMock().Object, "Flow");
        var result = flow.Step("Func", () => 99);
        Assert.Equal(99, result);
        Assert.False(flow.HasFailures);
    }

    [Fact]
    public void StepFunc_Throws_RecordsFailureAndRethrows()
    {
        using var flow = new FlowLogger(NewLoggerMock().Object, "Flow");
        Assert.Throws<InvalidOperationException>(() =>
            flow.Step<int>("Func", () => throw new InvalidOperationException("boom")));
        Assert.True(flow.HasFailures);
    }

    [Fact]
    public void Fail_RecordsFailure()
    {
        using var flow = new FlowLogger(NewLoggerMock().Object, "Flow");
        flow.Fail("StepOne", "reason");
        Assert.True(flow.HasFailures);
    }

    [Fact]
    public void Skip_DoesNotRecordFailure()
    {
        using var flow = new FlowLogger(NewLoggerMock().Object, "Flow");
        flow.Skip("StepOne", "not applicable");
        Assert.False(flow.HasFailures);
    }

    [Fact]
    public void Branch_EndBranch_RoundTrips()
    {
        using var flow = new FlowLogger(NewLoggerMock().Object, "Flow");
        flow.Branch("Inner");
        flow.Step("NestedStep");
        flow.EndBranch();
        Assert.False(flow.HasFailures);
    }

    [Fact]
    public void EndBranch_WithoutBranch_DoesNotThrow()
    {
        using var flow = new FlowLogger(NewLoggerMock().Object, "Flow");
        flow.EndBranch();
    }

    [Fact]
    public void GetSummary_IncludesAllStepKindsAndCounts()
    {
        using var flow = new FlowLogger(NewLoggerMock().Object, "Flow");
        flow.Step("Ok");
        flow.Skip("Skipped", "n/a");
        flow.Fail("Failed", "bad");

        var summary = flow.GetSummary();

        Assert.Contains("FAILED", summary);
        Assert.Contains("Steps: 3 total, 1 ok, 1 failed, 1 skipped", summary);
        Assert.Contains("[OK]", summary);
        Assert.Contains("[FAIL]", summary);
        Assert.Contains("[SKIP]", summary);
    }

    [Fact]
    public void GetSummary_NoFailures_ReportsOk()
    {
        using var flow = new FlowLogger(NewLoggerMock().Object, "Flow");
        flow.Step("Ok");
        Assert.Contains("[OK]", flow.GetSummary());
        Assert.DoesNotContain("FAILED", flow.GetSummary());
    }

    [Fact]
    public void GetSummaryEntries_OneEntryPerStepPlusOverview()
    {
        using var flow = new FlowLogger(NewLoggerMock().Object, "Flow");
        flow.Step("Ok");
        flow.Skip("Skipped", "n/a");
        flow.Fail("Failed", "bad");

        var entries = flow.GetSummaryEntries();

        // 1 overview entry + 3 step entries.
        Assert.Equal(4, entries.Count);
        Assert.Contains(entries.Keys, k => k.StartsWith("Flow: Flow"));
        Assert.Contains("FAILED", entries.Single(e => e.Key.StartsWith("Flow: Flow")).Value);
        Assert.Contains(entries, e => e.Key.EndsWith(": Ok") && e.Value.StartsWith("[OK]"));
        Assert.Contains(entries, e => e.Key.EndsWith(": Skipped") && e.Value.Contains("n/a"));
        Assert.Contains(entries, e => e.Key.EndsWith(": Failed") && e.Value.Contains("bad"));
    }

    [Fact]
    public void GetSummaryEntries_NoSteps_ReturnsOnlyOverview()
    {
        using var flow = new FlowLogger(NewLoggerMock().Object, "Flow");
        var entries = flow.GetSummaryEntries();
        Assert.Single(entries);
    }

    [Fact]
    public void Dispose_DoesNotThrow()
    {
        var flow = new FlowLogger(NewLoggerMock().Object, "Flow");
        flow.Step("Ok");
        flow.Dispose();
    }
}
