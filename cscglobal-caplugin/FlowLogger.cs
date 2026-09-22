// Copyright 2021 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System.Diagnostics;
using System.Text;
using Microsoft.Extensions.Logging;

namespace Keyfactor.Extensions.CAPlugin.CSCGlobal;

public enum FlowStepStatus
{
    Success,
    Failed,
    Skipped,
    InProgress
}

public class FlowStep
{
    public string Name { get; set; }
    public FlowStepStatus Status { get; set; }
    public string Detail { get; set; }
    public long ElapsedMs { get; set; }
    public List<FlowStep> Children { get; } = new();
}

/// <summary>
///     Tracks high-level operation flow and renders a visual step diagram to Trace logs.
///     Usage:
///       using var flow = new FlowLogger(logger, "Enroll-New");
///       flow.Step("ParseCSR");
///       flow.Step("ValidateCSR", () => { ... });
///       flow.Fail("CreateOrder", "API returned 400");
///       // flow renders automatically on Dispose
/// </summary>
public sealed class FlowLogger : IDisposable
{
    private readonly ILogger _logger;
    private readonly string _flowName;
    private readonly Stopwatch _totalTimer;
    private readonly List<FlowStep> _steps = new();
    private FlowStep _currentParent;
    private bool _disposed;

    public FlowLogger(ILogger logger, string flowName)
    {
        _logger = logger;
        _flowName = flowName;
        _totalTimer = Stopwatch.StartNew();
        _logger.LogTrace("===== FLOW START: {FlowName} =====", _flowName);
    }

    /// <summary>Record a completed step.</summary>
    public FlowLogger Step(string name, string detail = null)
    {
        var step = new FlowStep { Name = name, Status = FlowStepStatus.Success, Detail = detail };
        AddStep(step);
        _logger.LogTrace("  [{FlowName}] {StepName} ... OK{Detail}",
            _flowName, name, detail != null ? $" ({detail})" : "");
        return this;
    }

    /// <summary>Record a step that executes an action and times it.</summary>
    public FlowLogger Step(string name, Action action, string detail = null)
    {
        var sw = Stopwatch.StartNew();
        var step = new FlowStep { Name = name, Detail = detail };
        try
        {
            _logger.LogTrace("  [{FlowName}] {StepName} ...", _flowName, name);
            action();
            sw.Stop();
            step.Status = FlowStepStatus.Success;
            step.ElapsedMs = sw.ElapsedMilliseconds;
            AddStep(step);
            _logger.LogTrace("  [{FlowName}] {StepName} ... OK ({Elapsed}ms){Detail}",
                _flowName, name, sw.ElapsedMilliseconds, detail != null ? $" {detail}" : "");
        }
        catch (Exception ex)
        {
            sw.Stop();
            step.Status = FlowStepStatus.Failed;
            step.ElapsedMs = sw.ElapsedMilliseconds;
            step.Detail = ex.Message;
            AddStep(step);
            _logger.LogTrace("  [{FlowName}] {StepName} ... FAILED ({Elapsed}ms): {Error}",
                _flowName, name, sw.ElapsedMilliseconds, ex.Message);
            throw;
        }
        return this;
    }

    /// <summary>Record an async step that executes and times it.</summary>
    public async Task<FlowLogger> StepAsync(string name, Func<Task> action, string detail = null)
    {
        var sw = Stopwatch.StartNew();
        var step = new FlowStep { Name = name, Detail = detail };
        try
        {
            _logger.LogTrace("  [{FlowName}] {StepName} ...", _flowName, name);
            await action();
            sw.Stop();
            step.Status = FlowStepStatus.Success;
            step.ElapsedMs = sw.ElapsedMilliseconds;
            AddStep(step);
            _logger.LogTrace("  [{FlowName}] {StepName} ... OK ({Elapsed}ms){Detail}",
                _flowName, name, sw.ElapsedMilliseconds, detail != null ? $" {detail}" : "");
        }
        catch (Exception ex)
        {
            sw.Stop();
            step.Status = FlowStepStatus.Failed;
            step.ElapsedMs = sw.ElapsedMilliseconds;
            step.Detail = ex.Message;
            AddStep(step);
            _logger.LogTrace("  [{FlowName}] {StepName} ... FAILED ({Elapsed}ms): {Error}",
                _flowName, name, sw.ElapsedMilliseconds, ex.Message);
            throw;
        }
        return this;
    }

    /// <summary>
    ///     Record an async step whose own return value becomes the step's detail - unlike the
    ///     <paramref name="detail" /> parameter on the other overload (which is evaluated before
    ///     the action runs and so can't reflect anything the action decided), this reflects what
    ///     actually happened during execution (e.g. why a conditional step was a no-op).
    /// </summary>
    public async Task<FlowLogger> StepAsync(string name, Func<Task<string>> action)
    {
        var sw = Stopwatch.StartNew();
        var step = new FlowStep { Name = name };
        try
        {
            _logger.LogTrace("  [{FlowName}] {StepName} ...", _flowName, name);
            var detail = await action();
            sw.Stop();
            step.Status = FlowStepStatus.Success;
            step.ElapsedMs = sw.ElapsedMilliseconds;
            step.Detail = detail;
            AddStep(step);
            _logger.LogTrace("  [{FlowName}] {StepName} ... OK ({Elapsed}ms){Detail}",
                _flowName, name, sw.ElapsedMilliseconds, detail != null ? $" {detail}" : "");
        }
        catch (Exception ex)
        {
            sw.Stop();
            step.Status = FlowStepStatus.Failed;
            step.ElapsedMs = sw.ElapsedMilliseconds;
            step.Detail = ex.Message;
            AddStep(step);
            _logger.LogTrace("  [{FlowName}] {StepName} ... FAILED ({Elapsed}ms): {Error}",
                _flowName, name, sw.ElapsedMilliseconds, ex.Message);
            throw;
        }
        return this;
    }

    /// <summary>Record a failed step without throwing.</summary>
    public FlowLogger Fail(string name, string reason = null)
    {
        var step = new FlowStep { Name = name, Status = FlowStepStatus.Failed, Detail = reason };
        AddStep(step);
        _logger.LogTrace("  [{FlowName}] {StepName} ... FAILED{Reason}",
            _flowName, name, reason != null ? $": {reason}" : "");
        return this;
    }

    /// <summary>Record a skipped step.</summary>
    public FlowLogger Skip(string name, string reason = null)
    {
        var step = new FlowStep { Name = name, Status = FlowStepStatus.Skipped, Detail = reason };
        AddStep(step);
        _logger.LogTrace("  [{FlowName}] {StepName} ... SKIPPED{Reason}",
            _flowName, name, reason != null ? $": {reason}" : "");
        return this;
    }

    /// <summary>Start a branch (group of child steps).</summary>
    public FlowLogger Branch(string name)
    {
        var step = new FlowStep { Name = name, Status = FlowStepStatus.InProgress };
        AddStep(step);
        _currentParent = step;
        _logger.LogTrace("  [{FlowName}] >> Branch: {BranchName}", _flowName, name);
        return this;
    }

    /// <summary>End the current branch.</summary>
    public FlowLogger EndBranch()
    {
        _currentParent = null;
        return this;
    }

    private void AddStep(FlowStep step)
    {
        if (_currentParent != null)
            _currentParent.Children.Add(step);
        else
            _steps.Add(step);
    }

    /// <summary>Render the visual flow diagram to Trace log.</summary>
    private string RenderFlow()
    {
        var sb = new StringBuilder();
        sb.AppendLine();
        sb.AppendLine($"  ===== FLOW: {_flowName} ({_totalTimer.ElapsedMilliseconds}ms total) =====");
        sb.AppendLine();

        for (var i = 0; i < _steps.Count; i++)
        {
            var step = _steps[i];
            var icon = GetStatusIcon(step.Status);
            var elapsed = step.ElapsedMs > 0 ? $" ({step.ElapsedMs}ms)" : "";
            var detail = !string.IsNullOrEmpty(step.Detail) ? $" [{step.Detail}]" : "";

            sb.AppendLine($"    {icon} {step.Name}{elapsed}{detail}");

            // Render children (branch)
            if (step.Children.Count > 0)
            {
                for (var j = 0; j < step.Children.Count; j++)
                {
                    var child = step.Children[j];
                    var childIcon = GetStatusIcon(child.Status);
                    var childElapsed = child.ElapsedMs > 0 ? $" ({child.ElapsedMs}ms)" : "";
                    var childDetail = !string.IsNullOrEmpty(child.Detail) ? $" [{child.Detail}]" : "";
                    var connector = j < step.Children.Count - 1 ? "|   " : "    ";
                    sb.AppendLine($"    |");
                    sb.AppendLine($"    +-- {childIcon} {child.Name}{childElapsed}{childDetail}");
                }
            }

            // Connector between top-level steps
            if (i < _steps.Count - 1)
            {
                sb.AppendLine("    |");
                sb.AppendLine("    v");
            }
        }

        sb.AppendLine();

        // Final status line
        var finalStatus = _steps.Count > 0 && _steps.Last().Status == FlowStepStatus.Failed
            ? "FAILED" : _steps.Any(s => s.Status == FlowStepStatus.Failed) ? "PARTIAL FAILURE" : "SUCCESS";
        sb.AppendLine($"  ===== FLOW RESULT: {finalStatus} =====");

        return sb.ToString();
    }

    /// <summary>
    ///     Concise step-by-step summary suitable for surfacing in a user-facing failure message
    ///     (unlike <see cref="RenderFlow" />'s ASCII-art tree, which is meant for Trace logs only).
    /// </summary>
    public string GetSummary()
    {
        var hasFailures = _steps.Any(s => s.Status == FlowStepStatus.Failed) ||
            _steps.SelectMany(s => s.Children).Any(c => c.Status == FlowStepStatus.Failed);
        var overallStatus = hasFailures ? "FAILED" : "OK";

        var sb = new StringBuilder();
        sb.AppendLine($"Flow: {_flowName}  [{overallStatus}]  Total: {_totalTimer.ElapsedMilliseconds}ms");
        sb.AppendLine("----------------------------------------");

        foreach (var step in _steps)
        {
            AppendSummaryLine(sb, step, 0);
            foreach (var child in step.Children)
                AppendSummaryLine(sb, child, 1);
        }

        return sb.ToString();
    }

    private static void AppendSummaryLine(StringBuilder sb, FlowStep step, int indentLevel)
    {
        var indent = new string(' ', indentLevel * 2);
        var icon = GetStatusIcon(step.Status);
        var elapsed = step.ElapsedMs > 0 ? $" ({step.ElapsedMs}ms)" : "";
        var detail = !string.IsNullOrEmpty(step.Detail) ? $" - {step.Detail}" : "";
        sb.AppendLine($"{indent}{icon} {step.Name}{elapsed}{detail}");
    }

    /// <summary>
    ///     Same information as <see cref="GetSummary" />, but as one entry per step instead of a
    ///     single multi-line block. Intended for callers (e.g. EnrollmentResult.EnrollmentContext)
    ///     whose rendering surface displays a dictionary as a bulleted list and doesn't respect
    ///     embedded newlines - each step becomes its own bullet instead of one run-on line.
    /// </summary>
    public Dictionary<string, string> GetSummaryEntries()
    {
        var allSteps = _steps.Concat(_steps.SelectMany(s => s.Children)).ToList();
        var hasFailures = allSteps.Any(s => s.Status == FlowStepStatus.Failed);
        var overallStatus = hasFailures ? "FAILED" : "OK";
        var succeeded = allSteps.Count(s => s.Status == FlowStepStatus.Success);
        var failed = allSteps.Count(s => s.Status == FlowStepStatus.Failed);
        var skipped = allSteps.Count(s => s.Status == FlowStepStatus.Skipped);

        var entries = new Dictionary<string, string>
        {
            [$"Flow: {_flowName}"] =
                $"[{overallStatus}] {_totalTimer.ElapsedMilliseconds}ms total - " +
                $"{allSteps.Count} steps ({succeeded} ok, {failed} failed, {skipped} skipped)"
        };

        var stepNumber = 0;
        foreach (var step in _steps)
        {
            stepNumber++;
            AddSummaryEntry(entries, step, stepNumber, false);

            foreach (var child in step.Children)
            {
                stepNumber++;
                AddSummaryEntry(entries, child, stepNumber, true);
            }
        }

        return entries;
    }

    private static void AddSummaryEntry(Dictionary<string, string> entries, FlowStep step, int stepNumber, bool indent)
    {
        var icon = GetStatusIcon(step.Status);
        var time = step.ElapsedMs > 0 ? $" ({step.ElapsedMs}ms)" : "";
        var detail = !string.IsNullOrEmpty(step.Detail) ? $" - {step.Detail}" : "";
        var prefix = indent ? "  " : "";
        entries[$"Flow Step {stepNumber:00}: {prefix}{step.Name}"] = $"{icon}{time}{detail}";
    }

    private static string GetStatusIcon(FlowStepStatus status)
    {
        return status switch
        {
            FlowStepStatus.Success => "[OK]",
            FlowStepStatus.Failed => "[FAIL]",
            FlowStepStatus.Skipped => "[SKIP]",
            FlowStepStatus.InProgress => "[...]",
            _ => "[?]"
        };
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _totalTimer.Stop();
        _logger.LogTrace(RenderFlow());
    }
}
