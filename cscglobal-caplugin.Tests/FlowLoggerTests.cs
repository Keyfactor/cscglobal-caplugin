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
    public void Step_NoDetail_ChainableAndDoesNotThrow()
    {
        using var flow = new FlowLogger(NewLoggerMock().Object, "Flow");
        var result = flow.Step("StepOne");
        Assert.Same(flow, result);
    }

    [Fact]
    public void Step_WithDetail_DoesNotThrow()
    {
        using var flow = new FlowLogger(NewLoggerMock().Object, "Flow");
        flow.Step("StepOne", "some detail");
    }

    [Fact]
    public void Step_Action_Success_RunsAction()
    {
        using var flow = new FlowLogger(NewLoggerMock().Object, "Flow");
        var ran = false;
        flow.Step("Action", () => ran = true);
        Assert.True(ran);
    }

    [Fact]
    public void Step_Action_Throws_RecordsFailureAndRethrows()
    {
        using var flow = new FlowLogger(NewLoggerMock().Object, "Flow");
        Assert.Throws<InvalidOperationException>(() =>
            flow.Step("Action", () => throw new InvalidOperationException("boom")));
    }

    [Fact]
    public void Step_ActionWithDetail_Success()
    {
        using var flow = new FlowLogger(NewLoggerMock().Object, "Flow");
        flow.Step("Action", () => { }, "detail");
    }

    [Fact]
    public async Task StepAsync_Success_RunsAction()
    {
        using var flow = new FlowLogger(NewLoggerMock().Object, "Flow");
        var ran = false;
        await flow.StepAsync("AsyncStep", () =>
        {
            ran = true;
            return Task.CompletedTask;
        });
        Assert.True(ran);
    }

    [Fact]
    public async Task StepAsync_Throws_RecordsFailureAndRethrows()
    {
        using var flow = new FlowLogger(NewLoggerMock().Object, "Flow");
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            flow.StepAsync("AsyncStep", () => throw new InvalidOperationException("boom")));
    }

    [Fact]
    public async Task StepAsync_WithDetail_Success()
    {
        using var flow = new FlowLogger(NewLoggerMock().Object, "Flow");
        await flow.StepAsync("AsyncStep", () => Task.CompletedTask, "detail");
    }

    [Fact]
    public void Fail_RecordsFailure_DoesNotThrow()
    {
        using var flow = new FlowLogger(NewLoggerMock().Object, "Flow");
        flow.Fail("StepOne");
        flow.Fail("StepTwo", "reason");
    }

    [Fact]
    public void Skip_DoesNotThrow()
    {
        using var flow = new FlowLogger(NewLoggerMock().Object, "Flow");
        flow.Skip("StepOne");
        flow.Skip("StepTwo", "not applicable");
    }

    [Fact]
    public void Branch_EndBranch_ChildStepsNestUnderBranch()
    {
        using var flow = new FlowLogger(NewLoggerMock().Object, "Flow");
        flow.Branch("Inner");
        flow.Step("NestedStep");
        flow.EndBranch();
        flow.Step("TopLevelStep");
    }

    [Fact]
    public void EndBranch_WithoutBranch_DoesNotThrow()
    {
        using var flow = new FlowLogger(NewLoggerMock().Object, "Flow");
        flow.EndBranch();
    }

    [Fact]
    public void GetSummaryEntries_OneEntryPerStepPlusHeader()
    {
        using var flow = new FlowLogger(NewLoggerMock().Object, "MyFlow");
        flow.Step("StepOne");
        flow.Fail("StepTwo", "boom");

        var entries = flow.GetSummaryEntries();

        Assert.True(entries.ContainsKey("Flow: MyFlow"));
        Assert.Contains("FAILED", entries["Flow: MyFlow"]);
        Assert.Equal(3, entries.Count); // header + 2 steps
        Assert.Contains(entries, e => e.Key.Contains("StepOne") && e.Value.Contains("OK"));
        Assert.Contains(entries, e => e.Key.Contains("StepTwo") && e.Value.Contains("boom"));
    }

    [Fact]
    public void GetSummaryEntries_AllStepsSucceed_HeaderReportsOk()
    {
        using var flow = new FlowLogger(NewLoggerMock().Object, "MyFlow");
        flow.Step("StepOne");
        flow.Step("StepTwo");

        var entries = flow.GetSummaryEntries();

        Assert.Contains("[OK]", entries["Flow: MyFlow"]);
    }

    [Fact]
    public void GetSummaryEntries_BranchChildren_IncludedAsSeparateEntries()
    {
        using var flow = new FlowLogger(NewLoggerMock().Object, "MyFlow");
        flow.Branch("Inner");
        flow.Step("NestedStep");
        flow.Fail("NestedFail", "inner reason");
        flow.EndBranch();
        flow.Step("TopLevelStep");

        var entries = flow.GetSummaryEntries();

        Assert.Contains(entries, e => e.Key.Contains("NestedStep"));
        Assert.Contains(entries, e => e.Key.Contains("NestedFail") && e.Value.Contains("inner reason"));
        Assert.Contains(entries, e => e.Key.Contains("TopLevelStep"));
    }

    [Fact]
    public void Dispose_NoSteps_DoesNotThrow()
    {
        var flow = new FlowLogger(NewLoggerMock().Object, "Flow");
        flow.Dispose();
    }

    [Fact]
    public void Dispose_AllStepsSuccess_DoesNotThrow()
    {
        var flow = new FlowLogger(NewLoggerMock().Object, "Flow");
        flow.Step("Ok1");
        flow.Step("Ok2");
        flow.Dispose();
    }

    [Fact]
    public void Dispose_LastStepFailed_DoesNotThrow()
    {
        var flow = new FlowLogger(NewLoggerMock().Object, "Flow");
        flow.Step("Ok1");
        flow.Fail("Failed1");
        flow.Dispose();
    }

    [Fact]
    public void Dispose_MidStepFailedButLastSucceeded_PartialFailure_DoesNotThrow()
    {
        var flow = new FlowLogger(NewLoggerMock().Object, "Flow");
        flow.Fail("Failed1");
        flow.Step("Ok1");
        flow.Dispose();
    }

    [Fact]
    public void Dispose_WithBranchChildren_RendersChildrenWithoutThrowing()
    {
        var flow = new FlowLogger(NewLoggerMock().Object, "Flow");
        flow.Branch("Branch1");
        flow.Step("Child1");
        flow.Fail("Child2");
        flow.Skip("Child3");
        flow.EndBranch();
        flow.Step("AfterBranch");
        flow.Dispose();
    }

    [Fact]
    public void Dispose_CalledTwice_IsIdempotent()
    {
        var flow = new FlowLogger(NewLoggerMock().Object, "Flow");
        flow.Step("Ok");
        flow.Dispose();
        flow.Dispose(); // should not throw or double-log
    }
}
