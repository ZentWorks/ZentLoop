package server

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/crypto/ssh"

	"zentloop/internal/config"
	"zentloop/internal/tui"
)

// AdminSSH exposes only the ZentLoop live TUI over SSH. It intentionally does
// not provide a shell, command execution, subsystems or forwarding.
type AdminSSH struct {
	listener net.Listener
	config   *ssh.ServerConfig
	close    sync.Once
}

func NewAdminSSH(cfg config.Config) (*AdminSSH, error) {
	authorized, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(cfg.AdminSSHAuthorizedKey))
	if err != nil {
		return nil, fmt.Errorf("parse ZENTLOOP_ADMIN_SSH_AUTHORIZED_KEY: %w", err)
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("ZENTLOOP_ADMIN_SSH_AUTHORIZED_KEY must contain exactly one public key")
	}
	hostSigner, err := loadOrCreateSSHHostSigner(cfg.AdminSSHHostKeyPath)
	if err != nil {
		return nil, fmt.Errorf("admin ssh host key: %w", err)
	}

	algorithms := ssh.SupportedAlgorithms()
	sshCfg := &ssh.ServerConfig{
		Config: ssh.Config{
			KeyExchanges: algorithms.KeyExchanges,
			Ciphers:      algorithms.Ciphers,
			MACs:         algorithms.MACs,
		},
		PublicKeyAuthAlgorithms: algorithms.PublicKeyAuths,
		ServerVersion:           "SSH-2.0-ZentLoop_Admin",
		MaxAuthTries:            3,
		PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if meta.User() != cfg.AdminSSHUser {
				return nil, errors.New("unauthorized user")
			}
			if !bytes.Equal(key.Marshal(), authorized.Marshal()) {
				return nil, errors.New("unauthorized key")
			}
			return nil, nil
		},
	}
	sshCfg.AddHostKey(hostSigner)

	ln, err := net.Listen("tcp", cfg.AdminSSHAddr)
	if err != nil {
		return nil, err
	}
	return &AdminSSH{listener: ln, config: sshCfg}, nil
}

func (s *AdminSSH) Addr() net.Addr {
	return s.listener.Addr()
}

func (s *AdminSSH) Serve() error {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go s.handleConn(conn)
	}
}

func (s *AdminSSH) Close() error {
	var err error
	s.close.Do(func() { err = s.listener.Close() })
	return err
}

func (s *AdminSSH) handleConn(conn net.Conn) {
	defer conn.Close()

	serverConn, channels, requests, err := ssh.NewServerConn(conn, s.config)
	if err != nil {
		return
	}
	defer serverConn.Close()
	log.Printf("ZentLoop admin SSH authenticated from %s", serverConn.RemoteAddr())

	go ssh.DiscardRequests(requests)
	for ch := range channels {
		if ch.ChannelType() != "session" {
			_ = ch.Reject(ssh.Prohibited, "ZentLoop admin SSH only supports an interactive session")
			continue
		}
		channel, reqs, err := ch.Accept()
		if err != nil {
			continue
		}
		go handleAdminSSHSession(channel, reqs)
	}
}

func handleAdminSSHSession(channel ssh.Channel, requests <-chan *ssh.Request) {
	defer channel.Close()
	started := false
	done := make(chan struct{})

	for {
		select {
		case req, ok := <-requests:
			if !ok {
				return
			}
			switch req.Type {
			case "pty-req", "window-change":
				replySSHRequest(req, true)
			case "shell":
				if started {
					replySSHRequest(req, false)
					continue
				}
				started = true
				replySSHRequest(req, true)
				go func() {
					if err := tui.RunRemote(nil, channel, channel); err != nil {
						_, _ = fmt.Fprintf(channel.Stderr(), "ZentLoop top: %v\r\n", err)
					}
					_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
					close(done)
				}()
			default:
				replySSHRequest(req, false)
			}
		case <-done:
			return
		}
	}
}

func replySSHRequest(req *ssh.Request, ok bool) {
	if req.WantReply {
		_ = req.Reply(ok, nil)
	}
}

func loadOrCreateSSHHostSigner(path string) (ssh.Signer, error) {
	if data, err := os.ReadFile(path); err == nil {
		if err := os.Chmod(path, 0o600); err != nil {
			return nil, err
		}
		return ssh.ParsePrivateKey(data)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if len(pemBytes) == 0 {
		return nil, errors.New("encode generated host key")
	}

	tmp, err := os.CreateTemp(dir, ".ssh_host_ed25519_key-*")
	if err != nil {
		return nil, err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return nil, err
	}
	if _, err := tmp.Write(pemBytes); err != nil {
		_ = tmp.Close()
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKey(pemBytes)
}
