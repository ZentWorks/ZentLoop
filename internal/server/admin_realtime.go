package server

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	wsOpcodeText  = 0x1
	wsOpcodeClose = 0x8
	wsOpcodePing  = 0x9
	wsOpcodePong  = 0xA
	wsMaxPayload  = 64 << 10
)

type wsFrame struct {
	opcode  byte
	payload []byte
}

func (s *AdminServer) realtime(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	if !headerHasToken(r.Header, "Connection", "upgrade") || !strings.EqualFold(strings.TrimSpace(r.Header.Get("Upgrade")), "websocket") || strings.TrimSpace(r.Header.Get("Sec-WebSocket-Version")) != "13" {
		http.Error(w, "websocket upgrade required", http.StatusUpgradeRequired)
		return
	}
	key := strings.TrimSpace(r.Header.Get("Sec-WebSocket-Key"))
	if key == "" {
		http.Error(w, "missing websocket key", http.StatusBadRequest)
		return
	}
	if origin := strings.TrimSpace(r.Header.Get("Origin")); origin != "" && !sameAdminOrigin(origin, r.Host) {
		http.Error(w, "origin not allowed", http.StatusForbidden)
		return
	}

	ch, cancel, ok := s.store.SubscribeRealtime()
	if !ok {
		http.Error(w, "too many realtime subscribers", http.StatusTooManyRequests)
		return
	}
	defer cancel()

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "websocket unsupported", http.StatusInternalServerError)
		return
	}
	conn, rw, err := hj.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()

	accept := websocketAccept(key)
	if _, err := fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", accept); err != nil {
		return
	}
	if err := rw.Flush(); err != nil {
		return
	}

	incoming := make(chan wsFrame, 4)
	readErr := make(chan error, 1)
	go func() {
		for {
			frame, err := readWebSocketFrame(rw.Reader)
			if err != nil {
				readErr <- err
				return
			}
			select {
			case incoming <- frame:
			case <-r.Context().Done():
				return
			}
		}
	}()

	heartbeat := time.NewTicker(20 * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case msg, open := <-ch:
			if !open {
				return
			}
			payload, err := json.Marshal(msg)
			if err != nil || writeWebSocketFrame(rw.Writer, wsOpcodeText, payload) != nil {
				return
			}
		case <-heartbeat.C:
			payload, _ := json.Marshal(map[string]any{"type": "heartbeat", "at": time.Now().UTC()})
			if writeWebSocketFrame(rw.Writer, wsOpcodeText, payload) != nil {
				return
			}
		case frame := <-incoming:
			switch frame.opcode {
			case wsOpcodeClose:
				_ = writeWebSocketFrame(rw.Writer, wsOpcodeClose, frame.payload)
				return
			case wsOpcodePing:
				if writeWebSocketFrame(rw.Writer, wsOpcodePong, frame.payload) != nil {
					return
				}
			}
		case <-readErr:
			return
		case <-r.Context().Done():
			return
		}
	}
}

func headerHasToken(h http.Header, name, token string) bool {
	for _, value := range h.Values(name) {
		for _, part := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}
	return false
}

func sameAdminOrigin(origin, host string) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	return strings.EqualFold(u.Host, host)
}

func websocketAccept(key string) string {
	sum := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(sum[:])
}

func writeWebSocketFrame(w *bufio.Writer, opcode byte, payload []byte) error {
	if len(payload) > wsMaxPayload {
		return errors.New("websocket payload too large")
	}
	header := []byte{0x80 | (opcode & 0x0f)}
	switch n := len(payload); {
	case n < 126:
		header = append(header, byte(n))
	case n <= 0xffff:
		header = append(header, 126, byte(n>>8), byte(n))
	default:
		header = append(header, 127, 0, 0, 0, 0, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
	if _, err := w.Write(header); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := w.Write(payload); err != nil {
			return err
		}
	}
	return w.Flush()
}

func readWebSocketFrame(r *bufio.Reader) (wsFrame, error) {
	var head [2]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return wsFrame{}, err
	}
	if head[0]&0x80 == 0 {
		return wsFrame{}, errors.New("fragmented websocket frames unsupported")
	}
	opcode := head[0] & 0x0f
	masked := head[1]&0x80 != 0
	if !masked {
		return wsFrame{}, errors.New("unmasked client websocket frame")
	}
	length := uint64(head[1] & 0x7f)
	if length == 126 {
		var ext [2]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return wsFrame{}, err
		}
		length = uint64(binary.BigEndian.Uint16(ext[:]))
	} else if length == 127 {
		var ext [8]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return wsFrame{}, err
		}
		length = binary.BigEndian.Uint64(ext[:])
	}
	if length > wsMaxPayload {
		return wsFrame{}, errors.New("websocket frame too large")
	}
	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(r, mask[:]); err != nil {
			return wsFrame{}, err
		}
	}
	payload := make([]byte, int(length))
	if len(payload) > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return wsFrame{}, err
		}
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	return wsFrame{opcode: opcode, payload: payload}, nil
}
