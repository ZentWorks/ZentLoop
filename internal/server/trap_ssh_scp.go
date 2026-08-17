package server

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"path"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
)

const maxVirtualSCPUploadBytes = 1 << 20

func isVirtualSCPSink(command string) bool {
	words := virtualWords(command)
	if len(words) == 0 || path.Base(words[0]) != "scp" {
		return false
	}
	for _, a := range words[1:] {
		if strings.HasPrefix(a, "-") && strings.Contains(a, "t") {
			return true
		}
	}
	return false
}

func virtualSCPTarget(command string) string {
	words := virtualWords(command)
	target := "."
	for _, a := range words[1:] {
		if !strings.HasPrefix(a, "-") {
			target = a
		}
	}
	return target
}

func (w *virtualSSHWorld) runVirtualSCPSink(ch ssh.Channel, command string) virtualSSHResult {
	r := virtualBaseResult("scp", "file-transfer", 6, 98, "payload-staging", "virtual SCP upload received")
	target := w.resolve(virtualSCPTarget(command))
	br := bufio.NewReader(io.LimitReader(ch, maxVirtualSCPUploadBytes+64*1024))
	_, _ = ch.Write([]byte{0}) // receiver ready
	for records := 0; records < 32; records++ {
		line, err := br.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			r.Status = 1
			break
		}
		line = strings.TrimSuffix(line, "\n")
		if line == "" {
			continue
		}
		switch line[0] {
		case 'T':
			_, _ = ch.Write([]byte{0})
			continue
		case 'D':
			_, _ = ch.Write([]byte{0})
			continue
		case 'E':
			_, _ = ch.Write([]byte{0})
			continue
		case 'C':
			parts := strings.SplitN(line[1:], " ", 3)
			if len(parts) != 3 {
				r.Status = 1
				return r
			}
			sz, err := strconv.ParseInt(parts[1], 10, 64)
			if err != nil || sz < 0 || sz > maxVirtualSCPUploadBytes {
				r.Status = 1
				r.Output = "scp: file too large"
				return r
			}
			name := path.Base(parts[2])
			dest := target
			if w.dirs[target] || strings.HasSuffix(virtualSCPTarget(command), "/") {
				dest = path.Join(target, name)
			}
			_, _ = ch.Write([]byte{0})
			h := sha256.New()
			var preview strings.Builder
			remain := sz
			buf := make([]byte, 8192)
			for remain > 0 {
				nWant := int64(len(buf))
				if remain < nWant {
					nWant = remain
				}
				n, er := io.ReadFull(br, buf[:nWant])
				if n > 0 {
					h.Write(buf[:n])
					if preview.Len() < maxVirtualFileBytes {
						take := n
						if preview.Len()+take > maxVirtualFileBytes {
							take = maxVirtualFileBytes - preview.Len()
						}
						preview.Write(buf[:take])
					}
					remain -= int64(n)
				}
				if er != nil {
					r.Status = 1
					return r
				}
			}
			// Sender terminator byte.
			if b, er := br.ReadByte(); er != nil || b != 0 {
				r.Status = 1
				return r
			}
			sum := h.Sum(nil)
			hashHex := hex.EncodeToString(sum)
			prevHash, had := w.stagingPayloadHash[dest]
			var hashArr [32]byte
			// Full transfer hash is authoritative for retry detection and event metadata.
			copy(hashArr[:], sum)
			if !w.setVirtualFile(dest, preview.String()) {
				r.Status = 1
				r.Output = "scp: " + dest + ": " + w.virtualWriteFailure(dest)
				return r
			}
			meta := w.fileMeta[dest]
			meta.Size = sz
			meta.Kind = inferVirtualFileKind(dest, preview.String())
			w.fileMeta[dest] = meta
			if strings.HasPrefix(parts[0], "0755") || strings.HasPrefix(parts[0], "0777") {
				w.fileModes[dest] = 0o755
			} else {
				w.fileModes[dest] = 0o644
			}
			w.stagingAttempts[dest]++
			w.stagingPayloadHash[dest] = hashArr
			r.StdinBytes = int(sz)
			r.StdinSHA256 = hashHex
			r.StdinKind = meta.Kind
			r.PayloadPath = dest
			r.PayloadStage = "completed"
			if had && prevHash == hashArr {
				r.PayloadStage = "retry"
				r.Message = "identical virtual SCP payload staging retry"
				r.LoopInc++
			}
			_, _ = ch.Write([]byte{0})
			return r
		default:
			r.Status = 1
			return r
		}
	}
	return r
}

func (w *virtualSSHWorld) fakeSCP(args []string) virtualSSHResult {
	r := virtualBaseResult("scp", "file-transfer", 6, 97, "lateral-movement", "simulated SCP transfer")
	// -t is handled at SSH channel level because it speaks the SCP wire protocol.
	for _, a := range args {
		if strings.HasPrefix(a, "-") && strings.Contains(a, "t") {
			r.Output = ""
			return r
		}
	}
	var vals []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "-F" || a == "-i" || a == "-P" || a == "-o" {
			i++
			continue
		}
		if strings.HasPrefix(a, "-") {
			continue
		}
		vals = append(vals, a)
	}
	if len(vals) < 2 {
		r.Output = "usage: scp [-346ABCOpqRrsTv] source ... target"
		r.Status = 1
		return r
	}
	src, dst := vals[len(vals)-2], vals[len(vals)-1]
	if strings.Contains(src, ":") {
		remotePath := strings.SplitN(src, ":", 2)[1]
		u := "https://remote.invalid/" + strings.TrimPrefix(remotePath, "/")
		payload := w.virtualPayloadForURL(u)
		if path.Base(remotePath) == "sh" {
			payload = w.virtualPayloadForURL("https://remote.invalid/sh")
		}
		if !w.storeDownloadedVirtualFile(dst, payload) {
			r.Status = 1
			r.Output = "scp: " + dst + ": No space left on device"
			return r
		}
		r.Output = ""
		r.LoopInc = 1
		return r
	}
	if strings.Contains(dst, ":") {
		r.Output = ""
		r.LoopInc = 1
		return r
	}
	content, ok := w.virtualReadFile(src)
	if !ok {
		r.Status = 1
		r.Output = fmt.Sprintf("scp: stat local %q: No such file or directory", src)
		return r
	}
	if !w.setVirtualFile(w.resolve(dst), content) {
		r.Status = 1
		r.Output = "scp: " + dst + ": No space left on device"
	}
	return r
}
