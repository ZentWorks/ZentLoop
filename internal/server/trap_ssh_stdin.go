package server

import (
	"io"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	maxVirtualExecStdinBytes    = 512 * 1024
	virtualExecStdinInitialWait = 3 * time.Second
	virtualExecStdinIdleWait    = 1500 * time.Millisecond
	virtualExecStdinTotalWait   = 8 * time.Second
)

func commandMayConsumeExecStdin(command string) bool {
	return virtualCommandConsumesInput(command)
}

func readVirtualExecStdin(channel ssh.Channel) ([]byte, bool) {
	if channel == nil {
		return nil, false
	}
	return readVirtualExecStdinReader(channel, virtualExecStdinInitialWait, virtualExecStdinIdleWait, virtualExecStdinTotalWait)
}

// readVirtualExecStdinReader gives stdin-consuming exec requests enough time to
// behave like their Linux counterparts without allowing a client to hold a trap
// goroutine forever. After the first byte it keeps reading until EOF, the bounded
// capture limit, a short idle gap, or the hard total deadline. The virtual file
// itself remains bounded separately; this larger capture lets exported payload
// metadata describe the transferred stream rather than only its file preview.
func readVirtualExecStdinReader(reader io.Reader, initialWait, idleWait, totalWait time.Duration) ([]byte, bool) {
	if reader == nil {
		return nil, false
	}
	type readChunk struct {
		data []byte
		done bool
	}
	chunks := make(chan readChunk, 4)
	cancel := make(chan struct{})
	defer close(cancel)
	send := func(chunk readChunk) bool {
		select {
		case chunks <- chunk:
			return true
		case <-cancel:
			return false
		}
	}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := reader.Read(buf)
			if n > 0 {
				cp := append([]byte(nil), buf[:n]...)
				if !send(readChunk{data: cp}) {
					return
				}
			}
			if err != nil {
				_ = send(readChunk{done: true})
				return
			}
		}
	}()

	totalTimer := time.NewTimer(totalWait)
	defer totalTimer.Stop()
	idle := time.NewTimer(initialWait)
	defer idle.Stop()

	data := make([]byte, 0, 8192)
	for {
		select {
		case chunk := <-chunks:
			if len(chunk.data) > 0 {
				remaining := maxVirtualExecStdinBytes - len(data)
				if remaining <= 0 {
					return data, true
				}
				if len(chunk.data) > remaining {
					data = append(data, chunk.data[:remaining]...)
					return data, true
				}
				data = append(data, chunk.data...)
				if !idle.Stop() {
					select {
					case <-idle.C:
					default:
					}
				}
				idle.Reset(idleWait)
			}
			if chunk.done {
				return data, false
			}
		case <-idle.C:
			return data, len(data) > 0
		case <-totalTimer.C:
			return data, len(data) > 0
		}
	}
}
