package server

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"path"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"zentloop/internal/model"
)

const (
	sftpInit     = 1
	sftpVersion  = 2
	sftpOpen     = 3
	sftpClose    = 4
	sftpRead     = 5
	sftpWrite    = 6
	sftpLstat    = 7
	sftpSetstat  = 9
	sftpOpendir  = 11
	sftpReaddir  = 12
	sftpRemove   = 13
	sftpMkdir    = 14
	sftpRmdir    = 15
	sftpRealpath = 16
	sftpStat     = 17
	sftpRename   = 18
	sftpStatus   = 101
	sftpHandle   = 102
	sftpData     = 103
	sftpName     = 104
	sftpAttrs    = 105

	sftpFXOK               = 0
	sftpFXEOF              = 1
	sftpFXNoSuchFile       = 2
	sftpFXPermissionDenied = 3
	sftpFXFailure          = 4
	sftpFXOpUnsupported    = 8
)

type virtualSFTPHandle struct {
	path       string
	dir        bool
	write      bool
	read       bool
	listed     bool
	data       []byte
	total      int64
	hasher     hash.Hash
	nextOffset uint64
}

func sftpReadPacket(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > 1<<20 {
		return nil, fmt.Errorf("invalid sftp packet length %d", n)
	}
	b := make([]byte, n)
	_, err := io.ReadFull(r, b)
	return b, err
}

func sftpWritePacket(w io.Writer, payload []byte) error {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func sftpPutU32(b *[]byte, v uint32) {
	var x [4]byte
	binary.BigEndian.PutUint32(x[:], v)
	*b = append(*b, x[:]...)
}
func sftpPutU64(b *[]byte, v uint64) {
	var x [8]byte
	binary.BigEndian.PutUint64(x[:], v)
	*b = append(*b, x[:]...)
}
func sftpPutString(b *[]byte, s string) { sftpPutU32(b, uint32(len(s))); *b = append(*b, s...) }

func sftpGetU32(b []byte, off *int) (uint32, bool) {
	if *off+4 > len(b) {
		return 0, false
	}
	v := binary.BigEndian.Uint32(b[*off : *off+4])
	*off += 4
	return v, true
}
func sftpGetU64(b []byte, off *int) (uint64, bool) {
	if *off+8 > len(b) {
		return 0, false
	}
	v := binary.BigEndian.Uint64(b[*off : *off+8])
	*off += 8
	return v, true
}
func sftpGetString(b []byte, off *int) (string, bool) {
	n, ok := sftpGetU32(b, off)
	if !ok || int(n) > len(b)-*off {
		return "", false
	}
	s := string(b[*off : *off+int(n)])
	*off += int(n)
	return s, true
}

func sftpReplyStatus(ch ssh.Channel, id, code uint32, msg string) error {
	b := []byte{sftpStatus}
	sftpPutU32(&b, id)
	sftpPutU32(&b, code)
	sftpPutString(&b, msg)
	sftpPutString(&b, "")
	return sftpWritePacket(ch, b)
}

func sftpAttrsForWorld(w *virtualSSHWorld, target string) []byte {
	var b []byte
	meta := w.fileMeta[target]
	mode := w.fileModes[target]
	isDir := w.dirs[target]
	if isDir {
		mode = 0o755
	}
	flags := uint32(0x1 | 0x4 | 0x8) // size, permissions, atime/mtime
	sftpPutU32(&b, flags)
	size := meta.Size
	if isDir {
		size = 4096
	}
	sftpPutU64(&b, uint64(max64(size, 0)))
	perm := uint32(mode & 0o7777)
	if isDir {
		perm |= 0o040000
	} else {
		perm |= 0o100000
	}
	sftpPutU32(&b, perm)
	ts := uint32(time.Now().Unix())
	if !meta.ModTime.IsZero() {
		ts = uint32(meta.ModTime.Unix())
	}
	sftpPutU32(&b, ts)
	sftpPutU32(&b, ts)
	return b
}

func max64(v, min int64) int64 {
	if v < min {
		return min
	}
	return v
}

func (s *TrapSSH) runVirtualSFTP(ch ssh.Channel, base model.SSHEvent, world *virtualSSHWorld) {
	handles := map[string]*virtualSFTPHandle{}
	nextHandle := 1
	for {
		pkt, err := sftpReadPacket(ch)
		if err != nil {
			return
		}
		if len(pkt) < 1 {
			return
		}
		typ := pkt[0]
		if typ == sftpInit {
			off := 1
			_, _ = sftpGetU32(pkt, &off)
			resp := []byte{sftpVersion}
			sftpPutU32(&resp, 3)
			if sftpWritePacket(ch, resp) != nil {
				return
			}
			continue
		}
		off := 1
		id, ok := sftpGetU32(pkt, &off)
		if !ok {
			return
		}
		lock := func() {
			if world.shared != nil {
				world.shared.mu.Lock()
			}
		}
		unlock := func() {
			if world.shared != nil {
				world.shared.mu.Unlock()
			}
		}
		switch typ {
		case sftpRealpath:
			p, ok := sftpGetString(pkt, &off)
			if !ok {
				_ = sftpReplyStatus(ch, id, sftpFXFailure, "Failure")
				continue
			}
			lock()
			target := world.resolve(p)
			attrs := sftpAttrsForWorld(world, target)
			unlock()
			resp := []byte{sftpName}
			sftpPutU32(&resp, id)
			sftpPutU32(&resp, 1)
			sftpPutString(&resp, target)
			sftpPutString(&resp, target)
			resp = append(resp, attrs...)
			_ = sftpWritePacket(ch, resp)
		case sftpStat, sftpLstat:
			p, ok := sftpGetString(pkt, &off)
			if !ok {
				_ = sftpReplyStatus(ch, id, sftpFXFailure, "Failure")
				continue
			}
			lock()
			target := world.resolve(p)
			_, fileOK := world.virtualReadFile(target)
			dirOK := world.dirs[target]
			attrs := sftpAttrsForWorld(world, target)
			unlock()
			if !fileOK && !dirOK {
				_ = sftpReplyStatus(ch, id, sftpFXNoSuchFile, "No such file")
				continue
			}
			resp := []byte{sftpAttrs}
			sftpPutU32(&resp, id)
			resp = append(resp, attrs...)
			_ = sftpWritePacket(ch, resp)
		case sftpOpen:
			p, ok := sftpGetString(pkt, &off)
			if !ok {
				_ = sftpReplyStatus(ch, id, sftpFXFailure, "Failure")
				continue
			}
			flags, ok := sftpGetU32(pkt, &off)
			if !ok {
				_ = sftpReplyStatus(ch, id, sftpFXFailure, "Failure")
				continue
			}
			target := world.resolve(p)
			h := fmt.Sprintf("f%d", nextHandle)
			nextHandle++
			write := flags&(0x2|0x4|0x8|0x10) != 0
			read := flags&0x1 != 0
			lock()
			content, exists := world.virtualReadFile(target)
			if write && flags&0x10 != 0 {
				content = ""
				exists = true
				_ = world.setVirtualFile(target, "")
			}
			unlock()
			if !exists && !write {
				_ = sftpReplyStatus(ch, id, sftpFXNoSuchFile, "No such file")
				continue
			}
			vh := &virtualSFTPHandle{path: target, write: write, read: read, data: []byte(content), total: int64(len(content))}
			if write {
				vh.hasher = sha256.New()
			}
			handles[h] = vh
			resp := []byte{sftpHandle}
			sftpPutU32(&resp, id)
			sftpPutString(&resp, h)
			_ = sftpWritePacket(ch, resp)
		case sftpWrite:
			hs, ok := sftpGetString(pkt, &off)
			if !ok {
				_ = sftpReplyStatus(ch, id, sftpFXFailure, "Failure")
				continue
			}
			offset, ok := sftpGetU64(pkt, &off)
			if !ok {
				_ = sftpReplyStatus(ch, id, sftpFXFailure, "Failure")
				continue
			}
			data, ok := sftpGetString(pkt, &off)
			if !ok {
				_ = sftpReplyStatus(ch, id, sftpFXFailure, "Failure")
				continue
			}
			h := handles[hs]
			if h == nil || !h.write {
				_ = sftpReplyStatus(ch, id, sftpFXFailure, "Failure")
				continue
			}
			end := int64(offset) + int64(len(data))
			if end > maxVirtualSCPUploadBytes {
				_ = sftpReplyStatus(ch, id, sftpFXFailure, "No space left on device")
				continue
			}
			if int(offset) < maxVirtualFileBytes {
				need := int(offset) + len(data)
				if need > maxVirtualFileBytes {
					need = maxVirtualFileBytes
				}
				if len(h.data) < need {
					h.data = append(h.data, make([]byte, need-len(h.data))...)
				}
				n := len(data)
				if int(offset)+n > maxVirtualFileBytes {
					n = maxVirtualFileBytes - int(offset)
				}
				if n > 0 {
					copy(h.data[int(offset):int(offset)+n], []byte(data[:n]))
				}
			}
			if h.hasher != nil && offset == h.nextOffset {
				_, _ = h.hasher.Write([]byte(data))
				h.nextOffset += uint64(len(data))
			}
			if end > h.total {
				h.total = end
			}
			_ = sftpReplyStatus(ch, id, sftpFXOK, "OK")
		case sftpRead:
			hs, ok := sftpGetString(pkt, &off)
			if !ok {
				_ = sftpReplyStatus(ch, id, sftpFXFailure, "Failure")
				continue
			}
			offset, ok := sftpGetU64(pkt, &off)
			if !ok {
				_ = sftpReplyStatus(ch, id, sftpFXFailure, "Failure")
				continue
			}
			n, ok := sftpGetU32(pkt, &off)
			if !ok {
				_ = sftpReplyStatus(ch, id, sftpFXFailure, "Failure")
				continue
			}
			h := handles[hs]
			if h == nil || !h.read {
				_ = sftpReplyStatus(ch, id, sftpFXFailure, "Failure")
				continue
			}
			if int(offset) >= len(h.data) {
				_ = sftpReplyStatus(ch, id, sftpFXEOF, "EOF")
				continue
			}
			end := int(offset) + int(n)
			if end > len(h.data) {
				end = len(h.data)
			}
			resp := []byte{sftpData}
			sftpPutU32(&resp, id)
			sftpPutString(&resp, string(h.data[int(offset):end]))
			_ = sftpWritePacket(ch, resp)
		case sftpClose:
			hs, ok := sftpGetString(pkt, &off)
			if !ok {
				_ = sftpReplyStatus(ch, id, sftpFXFailure, "Failure")
				continue
			}
			h := handles[hs]
			if h == nil {
				_ = sftpReplyStatus(ch, id, sftpFXFailure, "Failure")
				continue
			}
			if h.write {
				lock()
				stored := world.setVirtualFile(h.path, string(h.data))
				if stored {
					meta := world.fileMeta[h.path]
					meta.Size = h.total
					world.fileMeta[h.path] = meta
				}
				unlock()
				if !stored {
					delete(handles, hs)
					_ = sftpReplyStatus(ch, id, sftpFXFailure, "No space left on device")
					continue
				}
				var sum [32]byte
				if h.hasher != nil && h.nextOffset == uint64(h.total) {
					copy(sum[:], h.hasher.Sum(nil))
				} else {
					sum = sha256.Sum256(h.data)
				}
				kind := inferVirtualFileKind(h.path, string(h.data))
				isPayloadKind := kind == "script" || strings.Contains(strings.ToLower(kind), "elf")
				isPayload := isPayloadKind && (world.isVirtualPayloadStagingPath(h.path) || isStealthPayloadPath(h.path))
				result := virtualSSHResult{CommandName: "sftp", Family: "file-transfer", Depth: 5, Risk: 92, Persona: "file-transfer", Message: "virtual SFTP upload received", StdinBytes: int(h.total), StdinSHA256: hex.EncodeToString(sum[:]), StdinKind: kind}
				if isPayload {
					lock()
					stage, relation, stageMessage := world.classifyVirtualPayloadStage(h.path, sum)
					world.stagingAttempts[h.path]++
					world.stagingPayloadHash[h.path] = sum
					unlock()
					result.Depth, result.Risk, result.Persona = 6, 97, "payload-staging"
					result.PayloadStage, result.PayloadPath, result.PayloadRelation = stage, h.path, relation
					result.Message = stageMessage
					if stage == "retry" {
						result.LoopInc++
						result.Risk = 98
					}
				}
				s.recordSSHCommand(base, "request", `sftp put "`+h.path+`"`, world, result, classifySSHActor(base.ClientVersion, false))
			}
			delete(handles, hs)
			_ = sftpReplyStatus(ch, id, sftpFXOK, "OK")
		case sftpRename:
			oldp, ok1 := sftpGetString(pkt, &off)
			newp, ok2 := sftpGetString(pkt, &off)
			if !ok1 || !ok2 {
				_ = sftpReplyStatus(ch, id, sftpFXFailure, "Failure")
				continue
			}
			lock()
			oldTarget, newTarget := world.resolve(oldp), world.resolve(newp)
			content, exists := world.virtualReadFile(oldTarget)
			if exists {
				meta := world.fileMeta[oldTarget]
				mode := world.fileModes[oldTarget]
				attrs := world.fileAttrs[oldTarget]
				exists = world.setVirtualFile(newTarget, content)
				if exists {
					world.fileMeta[newTarget] = meta
					world.fileModes[newTarget] = mode
					world.fileAttrs[newTarget] = attrs
					world.deleteVirtualFile(oldTarget)
				}
			}
			unlock()
			if !exists {
				_ = sftpReplyStatus(ch, id, sftpFXNoSuchFile, "No such file")
				continue
			}
			_ = sftpReplyStatus(ch, id, sftpFXOK, "OK")
		case sftpRemove:
			p, ok := sftpGetString(pkt, &off)
			if !ok {
				_ = sftpReplyStatus(ch, id, sftpFXFailure, "Failure")
				continue
			}
			lock()
			target := world.resolve(p)
			_, exists := world.virtualReadFile(target)
			if exists {
				world.deleteVirtualFile(target)
			}
			unlock()
			if !exists {
				_ = sftpReplyStatus(ch, id, sftpFXNoSuchFile, "No such file")
				continue
			}
			_ = sftpReplyStatus(ch, id, sftpFXOK, "OK")
		case sftpMkdir:
			p, ok := sftpGetString(pkt, &off)
			if !ok {
				_ = sftpReplyStatus(ch, id, sftpFXFailure, "Failure")
				continue
			}
			lock()
			target := world.resolve(p)
			good := world.setVirtualDir(target)
			unlock()
			if !good {
				_ = sftpReplyStatus(ch, id, sftpFXFailure, "Failure")
			} else {
				_ = sftpReplyStatus(ch, id, sftpFXOK, "OK")
			}
		case sftpRmdir:
			p, ok := sftpGetString(pkt, &off)
			if !ok {
				_ = sftpReplyStatus(ch, id, sftpFXFailure, "Failure")
				continue
			}
			lock()
			target := world.resolve(p)
			exists := world.dirs[target]
			if exists {
				delete(world.dirs, target)
			}
			unlock()
			if !exists {
				_ = sftpReplyStatus(ch, id, sftpFXNoSuchFile, "No such file")
			} else {
				_ = sftpReplyStatus(ch, id, sftpFXOK, "OK")
			}
		case sftpSetstat:
			p, ok := sftpGetString(pkt, &off)
			if !ok {
				_ = sftpReplyStatus(ch, id, sftpFXFailure, "Failure")
				continue
			}
			flags, ok := sftpGetU32(pkt, &off)
			if !ok {
				_ = sftpReplyStatus(ch, id, sftpFXFailure, "Failure")
				continue
			}
			lock()
			target := world.resolve(p)
			_, fileOK := world.virtualReadFile(target)
			dirOK := world.dirs[target]
			if flags&0x1 != 0 {
				_, _ = sftpGetU64(pkt, &off)
			}
			if flags&0x2 != 0 {
				_, _ = sftpGetU32(pkt, &off)
				_, _ = sftpGetU32(pkt, &off)
			}
			if flags&0x4 != 0 {
				if perm, ok := sftpGetU32(pkt, &off); ok && fileOK {
					world.fileModes[target] = perm & 0o7777
				}
			}
			unlock()
			if !fileOK && !dirOK {
				_ = sftpReplyStatus(ch, id, sftpFXNoSuchFile, "No such file")
			} else {
				_ = sftpReplyStatus(ch, id, sftpFXOK, "OK")
			}
		case sftpOpendir:
			p, ok := sftpGetString(pkt, &off)
			if !ok {
				_ = sftpReplyStatus(ch, id, sftpFXFailure, "Failure")
				continue
			}
			target := world.resolve(p)
			lock()
			exists := world.dirs[target]
			unlock()
			if !exists {
				_ = sftpReplyStatus(ch, id, sftpFXNoSuchFile, "No such file")
				continue
			}
			h := fmt.Sprintf("d%d", nextHandle)
			nextHandle++
			handles[h] = &virtualSFTPHandle{path: target, dir: true}
			resp := []byte{sftpHandle}
			sftpPutU32(&resp, id)
			sftpPutString(&resp, h)
			_ = sftpWritePacket(ch, resp)
		case sftpReaddir:
			hs, ok := sftpGetString(pkt, &off)
			if !ok {
				_ = sftpReplyStatus(ch, id, sftpFXFailure, "Failure")
				continue
			}
			h := handles[hs]
			if h == nil || !h.dir || h.listed {
				_ = sftpReplyStatus(ch, id, sftpFXEOF, "EOF")
				continue
			}
			lock()
			names := []string{}
			for d := range world.dirs {
				if d != h.path && path.Dir(d) == h.path {
					names = append(names, path.Base(d))
				}
			}
			for f := range world.files {
				if path.Dir(f) == h.path {
					names = append(names, path.Base(f))
				}
			}
			sort.Strings(names)
			resp := []byte{sftpName}
			sftpPutU32(&resp, id)
			sftpPutU32(&resp, uint32(len(names)))
			for _, name := range names {
				target := path.Join(h.path, name)
				sftpPutString(&resp, name)
				sftpPutString(&resp, name)
				resp = append(resp, sftpAttrsForWorld(world, target)...)
			}
			unlock()
			h.listed = true
			_ = sftpWritePacket(ch, resp)
		default:
			_ = sftpReplyStatus(ch, id, sftpFXOpUnsupported, "Operation unsupported")
		}
	}
}
