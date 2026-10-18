package sched

import (
	"context"
	"errors"
	"net/netip"
	"strings"

	"github.com/sjoerd305/tlswatch/internal/core"
	"github.com/sjoerd305/tlswatch/internal/probe"
)

// scanChunk is how many addresses one part of a scan covers at most. A
// local scan reports its progress as it goes; a node reports a chunk when
// it is done, so its chunks are cut to about nodeChunkTime of connects at
// the scan's rate: the progress moves, and a node that drops out loses
// little.
const (
	scanChunk     = 256
	nodeChunkTime = 10 // seconds
)

// chunkSize is how many addresses go in one part of sc.
func chunkSize(sc core.Scan) int {
	if sc.NodeID == 0 {
		return scanChunk
	}
	return min(scanChunk, max(1, sc.Rate*nodeChunkTime/max(len(sc.Ports), 1)))
}

// StartScan runs a scan that core.CreateScan recorded, in the background:
// chunk by chunk, from this server or from its node, each chunk's findings
// stored as it completes. It ends with the scheduler.
func (s *Scheduler) StartScan(sc core.Scan, addrs []netip.Addr) {
	s.init()
	s.mu.Lock()
	ctx := s.base
	s.mu.Unlock()
	if ctx == nil {
		ctx = context.Background()
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		failure := ""
		if err := s.scan(ctx, sc, addrs); err != nil {
			failure = err.Error()
			switch {
			case errors.Is(err, context.Canceled):
				failure = "stopped by a restart of the server"
			case strings.Contains(err.Error(), "unsupported kind"):
				// A node whose facts predate its downgrade, or an old node.
				failure = "the node runs a version that cannot scan; update it under Settings › Nodes"
			}
			s.Log.Warn("scan failed", "scan", sc.ID, "err", err)
		}
		// The scan's own context may be gone; recording its end must not be.
		if err := s.Core.FinishScan(context.WithoutCancel(ctx), sc.ID, failure); err != nil {
			s.Log.Error("finish scan", "scan", sc.ID, "err", err)
		}
	}()
}

func (s *Scheduler) scan(ctx context.Context, sc core.Scan, addrs []netip.Addr) error {
	allowLocal := s.Core.CurrentSettings(ctx).General.AllowLocal
	size := chunkSize(sc)
	var recordErr error
	for start := 0; start < len(addrs); start += size {
		req := probe.ScanRequest{Addresses: addrs[start:min(start+size, len(addrs))], Ports: sc.Ports, Rate: sc.Rate,
			Timeout: probe.ScanTimeout, AllowLocal: allowLocal}
		if sc.NodeID == 0 {
			// Stored as it comes, so the scan page shows the progress.
			req.Progress = func(part probe.ScanResult) {
				if err := s.Core.RecordScan(ctx, sc.ID, part); err != nil && recordErr == nil {
					recordErr = err
				}
			}
		}
		var res probe.ScanResult
		var err error
		switch {
		case sc.NodeID != 0 && s.Nodes != nil:
			res, err = s.Nodes.Scan(ctx, sc.NodeID, req)
		case sc.NodeID != 0:
			err = core.ErrNodeOffline
		case s.Scan != nil:
			res, err = s.Scan(ctx, req)
		default:
			res, err = probe.Scan(ctx, req)
		}
		if err != nil {
			return err
		}
		if recordErr != nil {
			return recordErr
		}
		if err := s.Core.RecordScan(ctx, sc.ID, res); err != nil {
			return err
		}
	}
	return nil
}
