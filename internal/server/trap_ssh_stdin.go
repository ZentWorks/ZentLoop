package server

import (
	"io"
	"time"

	"golang.org/x/crypto/ssh"
)

func commandMayConsumeExecStdin(command string) bool {
	return virtualCommandConsumesInput(command)
}

func readVirtualExecStdin(channel ssh.Channel) ([]byte, bool) {
	if channel == nil {
		return nil, false
	}
	type readResult struct{ data []byte }
	done := make(chan readResult, 1)
	go func() {
		data, _ := io.ReadAll(io.LimitReader(channel, int64(maxVirtualFileBytes+1)))
		done <- readResult{data: data}
	}()
	select {
	case got := <-done:
		if len(got.data) > maxVirtualFileBytes {
			return got.data[:maxVirtualFileBytes], true
		}
		return got.data, false
	case <-time.After(450 * time.Millisecond):
		return nil, false
	}
}
