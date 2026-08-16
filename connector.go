package remarkable

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PlakarKorp/kloset/connectors"
	"github.com/PlakarKorp/kloset/connectors/importer"
	"github.com/PlakarKorp/kloset/location"
	"github.com/PlakarKorp/kloset/objects"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

const defaultRoot = "/home/root"

var (
	defaultTargets = []string{
		defaultRoot + "/.local/share/remarkable/xochitl",
		defaultRoot + "/.config/remarkable/xochitl.conf",
	}
	defaultPrefixes = []string{
		defaultRoot,
		defaultRoot + "/.local",
		defaultRoot + "/.local/share",
		defaultRoot + "/.local/share/remarkable",
		defaultRoot + "/.config",
		defaultRoot + "/.config/remarkable",
	}
)

type config struct {
	address              string
	user                 string
	password             string
	privateKey           string
	privateKeyPassphrase string
	agentSocket          string
	knownHosts           string
	insecureHostKey      bool
	root                 string
	targets              []string
}

type remoteClient interface {
	Lstat(string) (os.FileInfo, error)
	ReadDir(string) ([]os.FileInfo, error)
	ReadLink(string) (string, error)
	Open(string) (io.ReadCloser, error)
	Close() error
}

type sftpRemote struct {
	*sftp.Client
}

func (r *sftpRemote) Open(name string) (io.ReadCloser, error) {
	return r.Client.Open(name)
}

type Remarkable struct {
	origin  string
	root    string
	targets []string
	remote  remoteClient

	sshClient   *ssh.Client
	agentCloser io.Closer
	closeOnce   sync.Once
	closeErr    error
}

func init() {
	importer.Register("remarkable", 0, NewImporter)
}

func NewImporter(ctx context.Context, opts *connectors.Options, proto string, values map[string]string) (importer.Importer, error) {
	if proto != "remarkable" {
		return nil, fmt.Errorf("invalid protocol %q", proto)
	}

	cfg, err := parseConfig(values)
	if err != nil {
		return nil, err
	}
	remote, sshClient, agentCloser, err := connect(ctx, cfg)
	if err != nil {
		return nil, err
	}

	imp := &Remarkable{
		origin:      cfg.address,
		root:        cfg.root,
		targets:     cfg.targets,
		remote:      remote,
		sshClient:   sshClient,
		agentCloser: agentCloser,
	}
	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := imp.Ping(pingCtx); err != nil {
		_ = imp.Close(ctx)
		return nil, err
	}
	return imp, nil
}

func parseConfig(values map[string]string) (*config, error) {
	rawLocation := values["location"]
	endpoint, err := url.Parse(rawLocation)
	if err != nil {
		return nil, fmt.Errorf("parse location: %w", err)
	}
	if endpoint.Scheme != "remarkable" {
		return nil, fmt.Errorf("location must use remarkable://")
	}
	if endpoint.Hostname() == "" {
		return nil, fmt.Errorf("location is missing a hostname")
	}
	if endpoint.Path != "" && endpoint.Path != "/" {
		return nil, fmt.Errorf("location path is fixed; got %q", endpoint.Path)
	}
	if endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return nil, fmt.Errorf("location must not contain a query or fragment")
	}
	if endpoint.User != nil {
		if _, set := endpoint.User.Password(); set {
			return nil, fmt.Errorf("passwords are not allowed in location URIs")
		}
	}

	username := values["username"]
	if endpoint.User != nil && username != "" {
		return nil, fmt.Errorf("username cannot be set both in location and configuration")
	}
	if endpoint.User != nil {
		username = endpoint.User.Username()
	}
	if username == "" {
		username = "root"
	}

	address := endpoint.Host
	if endpoint.Port() == "" {
		address = net.JoinHostPort(endpoint.Hostname(), "22")
	}

	insecure, err := parseBool(values, "insecure_ignore_host_key")
	if err != nil {
		return nil, err
	}
	if insecure && values["known_hosts"] != "" {
		return nil, fmt.Errorf("known_hosts and insecure_ignore_host_key cannot be used together")
	}

	knownHosts := values["known_hosts"]
	if !insecure && knownHosts == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("find home directory for known_hosts: %w", err)
		}
		knownHosts = filepath.Join(home, ".ssh", "known_hosts")
	}

	agentSocket, agentConfigured := values["ssh_auth_sock"]
	if !agentConfigured && values["password"] == "" && values["private_key"] == "" {
		agentSocket = os.Getenv("SSH_AUTH_SOCK")
	}

	cfg := &config{
		address:              address,
		user:                 username,
		password:             values["password"],
		privateKey:           values["private_key"],
		privateKeyPassphrase: values["private_key_passphrase"],
		agentSocket:          agentSocket,
		knownHosts:           knownHosts,
		insecureHostKey:      insecure,
		root:                 defaultRoot,
		targets:              append([]string(nil), defaultTargets...),
	}
	if cfg.password == "" && cfg.privateKey == "" && cfg.agentSocket == "" {
		return nil, fmt.Errorf("configure password, private_key, or ssh_auth_sock")
	}
	return cfg, nil
}

func parseBool(values map[string]string, name string) (bool, error) {
	raw := values[name]
	if raw == "" {
		return false, nil
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("%s: %w", name, err)
	}
	return value, nil
}

func expandPath(name string) (string, error) {
	if name == "~" || strings.HasPrefix(name, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		if name == "~" {
			return home, nil
		}
		return filepath.Join(home, strings.TrimPrefix(name, "~/")), nil
	}
	return name, nil
}

func authMethods(cfg *config) ([]ssh.AuthMethod, io.Closer, error) {
	var signers []ssh.Signer
	if cfg.privateKey != "" {
		keyPath, err := expandPath(cfg.privateKey)
		if err != nil {
			return nil, nil, fmt.Errorf("expand private key path: %w", err)
		}
		keyData, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, nil, fmt.Errorf("read private key %q: %w", keyPath, err)
		}
		var signer ssh.Signer
		if cfg.privateKeyPassphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(keyData, []byte(cfg.privateKeyPassphrase))
		} else {
			signer, err = ssh.ParsePrivateKey(keyData)
		}
		if err != nil {
			return nil, nil, fmt.Errorf("parse private key %q: %w", keyPath, err)
		}
		signers = append(signers, signer)
	}

	var agentConn net.Conn
	var agentClient agent.ExtendedAgent
	if cfg.agentSocket != "" {
		conn, err := net.DialTimeout("unix", cfg.agentSocket, 10*time.Second)
		if err != nil {
			return nil, nil, fmt.Errorf("connect to SSH agent: %w", err)
		}
		agentConn = conn
		agentClient = agent.NewClient(conn)
	}

	var methods []ssh.AuthMethod
	if len(signers) > 0 || agentClient != nil {
		methods = append(methods, ssh.PublicKeysCallback(func() ([]ssh.Signer, error) {
			available := append([]ssh.Signer(nil), signers...)
			if agentClient != nil {
				agentSigners, err := agentClient.Signers()
				if err != nil {
					return nil, err
				}
				available = append(available, agentSigners...)
			}
			return available, nil
		}))
	}
	if cfg.password != "" {
		methods = append(methods, ssh.Password(cfg.password))
	}
	if len(methods) == 0 {
		return nil, agentConn, fmt.Errorf("no SSH authentication method available")
	}
	return methods, agentConn, nil
}

func hostKeyCallback(cfg *config) (ssh.HostKeyCallback, error) {
	if cfg.insecureHostKey {
		return ssh.InsecureIgnoreHostKey(), nil
	}
	knownHostsPath, err := expandPath(cfg.knownHosts)
	if err != nil {
		return nil, fmt.Errorf("expand known_hosts path: %w", err)
	}
	callback, err := knownhosts.New(knownHostsPath)
	if err != nil {
		return nil, fmt.Errorf("load known_hosts %q: %w", knownHostsPath, err)
	}
	return callback, nil
}

func connect(ctx context.Context, cfg *config) (remoteClient, *ssh.Client, io.Closer, error) {
	auth, agentCloser, err := authMethods(cfg)
	if err != nil {
		return nil, nil, nil, err
	}
	closeAgent := func() {
		if agentCloser != nil {
			_ = agentCloser.Close()
		}
	}

	hostKey, err := hostKeyCallback(cfg)
	if err != nil {
		closeAgent()
		return nil, nil, nil, err
	}
	algorithms := append([]string(nil), ssh.SupportedAlgorithms().HostKeys...)
	// reMarkable 1 ships an older Dropbear that may only offer an ssh-rsa host key.
	algorithms = append(algorithms, ssh.KeyAlgoRSA)
	clientConfig := &ssh.ClientConfig{
		User:              cfg.user,
		Auth:              auth,
		HostKeyCallback:   hostKey,
		HostKeyAlgorithms: algorithms,
	}

	netConn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", cfg.address)
	if err != nil {
		closeAgent()
		return nil, nil, nil, fmt.Errorf("connect to %s: %w", cfg.address, err)
	}
	stopHandshakeWatch := watchConnection(ctx, netConn, 10*time.Second)
	conn, channels, requests, err := ssh.NewClientConn(netConn, cfg.address, clientConfig)
	if err != nil {
		stopHandshakeWatch()
		_ = netConn.Close()
		closeAgent()
		return nil, nil, nil, fmt.Errorf("SSH handshake with %s: %w", cfg.address, err)
	}
	sshClient := ssh.NewClient(conn, channels, requests)
	sftpClient, err := sftp.NewClient(sshClient)
	stopHandshakeWatch()
	if err != nil {
		_ = sshClient.Close()
		closeAgent()
		return nil, nil, nil, fmt.Errorf("start SFTP subsystem: %w", err)
	}
	if err := ctx.Err(); err != nil {
		_ = sftpClient.Close()
		_ = sshClient.Close()
		closeAgent()
		return nil, nil, nil, err
	}
	return &sftpRemote{Client: sftpClient}, sshClient, agentCloser, nil
}

func watchConnection(ctx context.Context, conn net.Conn, timeout time.Duration) func() {
	deadline := time.Now().Add(timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	_ = conn.SetDeadline(deadline)

	done := make(chan struct{})
	var once sync.Once
	go func() {
		select {
		case <-ctx.Done():
			select {
			case <-done:
				return
			default:
				_ = conn.SetDeadline(time.Now())
			}
		case <-done:
		}
	}()
	return func() {
		once.Do(func() {
			close(done)
			_ = conn.SetDeadline(time.Time{})
		})
	}
}

func (r *Remarkable) Root() string          { return r.root }
func (r *Remarkable) Origin() string        { return r.origin }
func (r *Remarkable) Type() string          { return "remarkable" }
func (r *Remarkable) Flags() location.Flags { return 0 }

func (r *Remarkable) Ping(ctx context.Context) error {
	stop := r.watchCancellation(ctx)
	defer stop()
	for _, target := range r.targets {
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, err := r.remote.Lstat(target); err != nil {
			return fmt.Errorf("access required backup path %q: %w", target, err)
		}
	}
	return nil
}

func (r *Remarkable) Import(ctx context.Context, records chan<- *connectors.Record, results <-chan *connectors.Result) error {
	defer close(records)
	stop := r.watchCancellation(ctx)
	defer stop()

	for _, pathname := range defaultPrefixes {
		if err := r.emit(ctx, records, pathname, nil); err != nil {
			return err
		}
	}
	for _, target := range r.targets {
		if err := r.walk(ctx, records, target, nil); err != nil {
			return err
		}
	}
	return nil
}

func (r *Remarkable) walk(ctx context.Context, records chan<- *connectors.Record, pathname string, info os.FileInfo) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if info == nil {
		var err error
		info, err = r.remote.Lstat(pathname)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return r.reportError(ctx, records, pathname, fmt.Errorf("lstat %q: %w", pathname, err))
		}
	}
	if err := r.emit(ctx, records, pathname, info); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return r.reportError(ctx, records, pathname, err)
	}
	if !info.IsDir() {
		return nil
	}
	entries, err := r.remote.ReadDir(pathname)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return r.reportError(ctx, records, pathname, fmt.Errorf("read directory %q: %w", pathname, err))
	}
	for _, entry := range entries {
		if err := r.walk(ctx, records, path.Join(pathname, entry.Name()), entry); err != nil {
			return err
		}
	}
	return nil
}

func (r *Remarkable) emit(ctx context.Context, records chan<- *connectors.Record, pathname string, info os.FileInfo) error {
	if info == nil {
		var err error
		info, err = r.remote.Lstat(pathname)
		if err != nil {
			return fmt.Errorf("lstat %q: %w", pathname, err)
		}
	}

	var uid, gid uint64
	if stat, ok := info.Sys().(*sftp.FileStat); ok {
		uid, gid = uint64(stat.UID), uint64(stat.GID)
	}
	fileInfo := objects.FileInfo{
		Lname:    info.Name(),
		Lsize:    info.Size(),
		Lmode:    info.Mode(),
		LmodTime: info.ModTime(),
		Luid:     uid,
		Lgid:     gid,
	}

	var target string
	if info.Mode()&os.ModeSymlink != 0 {
		var err error
		target, err = r.remote.ReadLink(pathname)
		if err != nil {
			return fmt.Errorf("read symlink %q: %w", pathname, err)
		}
	}

	record := &connectors.Record{
		Pathname: pathname,
		Target:   target,
		FileInfo: fileInfo,
	}
	if info.Mode().IsRegular() {
		record = connectors.NewRecord(pathname, target, fileInfo, nil, func() (io.ReadCloser, error) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			stop := r.watchCancellation(ctx)
			reader, err := r.remote.Open(pathname)
			if err != nil {
				stop()
				return nil, fmt.Errorf("open %q: %w", pathname, err)
			}
			return &watchedReader{ReadCloser: reader, stop: stop}, nil
		})
	}
	select {
	case records <- record:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (r *Remarkable) reportError(ctx context.Context, records chan<- *connectors.Record, pathname string, err error) error {
	select {
	case records <- connectors.NewError(pathname, err):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type watchedReader struct {
	io.ReadCloser
	stop func()
}

func (r *watchedReader) Close() error {
	r.stop()
	return r.ReadCloser.Close()
}

func (r *Remarkable) watchCancellation(ctx context.Context) func() {
	done := make(chan struct{})
	var once sync.Once
	go func() {
		select {
		case <-ctx.Done():
			select {
			case <-done:
				return
			default:
				_ = r.closeTransport()
			}
		case <-done:
		}
	}()
	return func() { once.Do(func() { close(done) }) }
}

func (r *Remarkable) closeTransport() error {
	r.closeOnce.Do(func() {
		var errs []error
		if r.sshClient != nil {
			errs = append(errs, r.sshClient.Close())
		}
		if r.remote != nil {
			errs = append(errs, r.remote.Close())
		}
		if r.agentCloser != nil {
			errs = append(errs, r.agentCloser.Close())
		}
		r.closeErr = errors.Join(errs...)
	})
	return r.closeErr
}

func (r *Remarkable) Close(ctx context.Context) error {
	return r.closeTransport()
}
