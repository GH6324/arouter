package main

import (
	"fmt"
	"time"
)

func newDiagRun(nodes []string) *diagRun {
	runID := fmt.Sprintf("diag-%d", time.Now().UnixNano())
	run := &diagRun{
		RunID:     runID,
		CreatedAt: time.Now(),
		Nodes:     nodes,
		Reports:   make(map[string]DiagReport),
	}
	diagMu.Lock()
	diagRuns[runID] = run
	diagRunOrder = append(diagRunOrder, runID)
	if len(diagRunOrder) > 20 {
		old := diagRunOrder[0]
		delete(diagRuns, old)
		diagRunOrder = diagRunOrder[1:]
	}
	diagMu.Unlock()
	return run
}

func ensureDiagRun(runID string, nodes []string) {
	if runID == "" {
		return
	}
	diagMu.Lock()
	run := diagRuns[runID]
	if run == nil {
		run = &diagRun{
			RunID:     runID,
			CreatedAt: time.Now(),
			Nodes:     append([]string(nil), nodes...),
			Reports:   make(map[string]DiagReport),
		}
		diagRuns[runID] = run
		diagRunOrder = append(diagRunOrder, runID)
	} else if len(run.Nodes) == 0 && len(nodes) > 0 {
		run.Nodes = append([]string(nil), nodes...)
	}
	diagMu.Unlock()
}

func storeDiagReport(runID string, report DiagReport) {
	if runID == "" || report.Node == "" {
		return
	}
	diagMu.Lock()
	run := diagRuns[runID]
	if run == nil {
		run = &diagRun{
			RunID:     runID,
			CreatedAt: time.Now(),
			Reports:   make(map[string]DiagReport),
		}
		diagRuns[runID] = run
		diagRunOrder = append(diagRunOrder, runID)
	}
	if prev, ok := run.Reports[report.Node]; ok {
		if report.At.After(prev.At) {
			prev.At = report.At
		}
		if report.Limit > 0 {
			prev.Limit = report.Limit
		}
		if report.Filter != "" {
			prev.Filter = report.Filter
		}
		seen := make(map[string]struct{}, len(prev.Lines))
		for _, line := range prev.Lines {
			seen[line] = struct{}{}
		}
		for _, line := range report.Lines {
			if _, ok := seen[line]; ok {
				continue
			}
			prev.Lines = append(prev.Lines, line)
			seen[line] = struct{}{}
		}
		if len(prev.Lines) > 2000 {
			prev.Lines = prev.Lines[len(prev.Lines)-2000:]
		}
		run.Reports[report.Node] = prev
	} else {
		run.Reports[report.Node] = report
	}
	diagMu.Unlock()
}

func getDiagRun(runID string) *diagRun {
	diagMu.Lock()
	defer diagMu.Unlock()
	if runID == "" && len(diagRunOrder) > 0 {
		runID = diagRunOrder[len(diagRunOrder)-1]
	}
	if runID == "" {
		return nil
	}
	run := diagRuns[runID]
	if run == nil {
		return nil
	}
	clone := &diagRun{
		RunID:     run.RunID,
		CreatedAt: run.CreatedAt,
		Nodes:     append([]string(nil), run.Nodes...),
		Reports:   make(map[string]DiagReport, len(run.Reports)),
	}
	for k, v := range run.Reports {
		clone.Reports[k] = v
	}
	return clone
}

func newDiagTraceRun() *diagTraceRun {
	runID := fmt.Sprintf("trace-%d", time.Now().UnixNano())
	run := &diagTraceRun{
		RunID:     runID,
		CreatedAt: time.Now(),
		Events:    make([]DiagTraceEvent, 0),
	}
	diagTraceMu.Lock()
	diagTraceRuns[runID] = run
	diagTraceMu.Unlock()
	return run
}

func storeDiagTraceEvent(ev DiagTraceEvent) {
	if ev.RunID == "" {
		return
	}
	diagTraceMu.Lock()
	run := diagTraceRuns[ev.RunID]
	if run == nil {
		run = &diagTraceRun{RunID: ev.RunID, CreatedAt: time.Now()}
		diagTraceRuns[ev.RunID] = run
	}
	run.Events = append(run.Events, ev)
	if len(run.Events) > 2000 {
		run.Events = run.Events[len(run.Events)-2000:]
	}
	diagTraceMu.Unlock()
}

func getDiagTraceRun(runID string) *diagTraceRun {
	diagTraceMu.Lock()
	defer diagTraceMu.Unlock()
	if runID == "" {
		return nil
	}
	run := diagTraceRuns[runID]
	if run == nil {
		return nil
	}
	clone := &diagTraceRun{
		RunID:     run.RunID,
		CreatedAt: run.CreatedAt,
		Events:    append([]DiagTraceEvent(nil), run.Events...),
	}
	return clone
}

func newEndpointCheckRun(nodes []string) *endpointCheckRun {
	runID := fmt.Sprintf("ep-%d", time.Now().UnixNano())
	run := &endpointCheckRun{
		RunID:     runID,
		CreatedAt: time.Now(),
		Nodes:     append([]string(nil), nodes...),
		Results:   make([]EndpointCheckResult, 0),
	}
	endpointCheckMu.Lock()
	endpointCheckRuns[runID] = run
	endpointCheckMu.Unlock()
	return run
}

func storeEndpointCheckResults(runID string, results []EndpointCheckResult) {
	if runID == "" {
		return
	}
	endpointCheckMu.Lock()
	run := endpointCheckRuns[runID]
	if run == nil {
		run = &endpointCheckRun{RunID: runID, CreatedAt: time.Now()}
		endpointCheckRuns[runID] = run
	}
	if len(results) > 0 {
		run.Results = append(run.Results, results...)
	}
	endpointCheckMu.Unlock()
}

func getEndpointCheckRun(runID string) *endpointCheckRun {
	endpointCheckMu.Lock()
	defer endpointCheckMu.Unlock()
	if runID == "" {
		return nil
	}
	run := endpointCheckRuns[runID]
	if run == nil {
		return nil
	}
	clone := &endpointCheckRun{
		RunID:     run.RunID,
		CreatedAt: run.CreatedAt,
		Nodes:     append([]string(nil), run.Nodes...),
		Results:   append([]EndpointCheckResult(nil), run.Results...),
	}
	return clone
}

func newTimeSyncRun(nodes []string) *timeSyncRun {
	runID := fmt.Sprintf("timesync-%d", time.Now().UnixNano())
	run := &timeSyncRun{
		RunID:     runID,
		CreatedAt: time.Now(),
		Nodes:     append([]string(nil), nodes...),
		Results:   make([]TimeSyncResult, 0),
	}
	timeSyncMu.Lock()
	timeSyncRuns[runID] = run
	timeSyncMu.Unlock()
	return run
}

func storeTimeSyncResult(runID string, res TimeSyncResult) {
	if runID == "" {
		return
	}
	timeSyncMu.Lock()
	run := timeSyncRuns[runID]
	if run == nil {
		run = &timeSyncRun{RunID: runID, CreatedAt: time.Now()}
		timeSyncRuns[runID] = run
	}
	for i := range run.Results {
		if run.Results[i].Node == res.Node {
			run.Results[i] = res
			timeSyncMu.Unlock()
			return
		}
	}
	run.Results = append(run.Results, res)
	timeSyncMu.Unlock()
}

func getTimeSyncRun(runID string) *timeSyncRun {
	timeSyncMu.Lock()
	defer timeSyncMu.Unlock()
	if runID == "" {
		return nil
	}
	run := timeSyncRuns[runID]
	if run == nil {
		return nil
	}
	clone := &timeSyncRun{
		RunID:     run.RunID,
		CreatedAt: run.CreatedAt,
		Nodes:     append([]string(nil), run.Nodes...),
		Results:   append([]TimeSyncResult(nil), run.Results...),
	}
	return clone
}
