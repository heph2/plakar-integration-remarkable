package remarkable

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
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
	address         string
	host            string
	port            string
	user            string
	privateKey      string
	agentSocket     string
	knownHosts      string
	insecureHostKey bool
	root            string
	targets         []string
}

type remoteClient interface {
	Lstat(string) (os.FileInfo, error)
	ReadDir(string) ([]os.FileInfo, error)
	ReadLink(string) (string, error)
	Open(string) (io.ReadCloser, error)
	Close() error
}

type lockedBuffer struct {
	mu sync.Mutex
	bytes.Buffer
}

func (b *lockedBuffer) Write(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Buffer.Write(data)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Buffer.String()
}

type commandRemote struct {
	*sftp.Client
	cmd    *exec.Cmd
	wait   <-chan error
	stderr *lockedBuffer

	closeOnce sync.Once
	closeErr  error
}

func (r *commandRemote) Open(name string) (io.ReadCloser, error) {
	return r.Client.Open(name)
}

func (r *commandRemote) Close() error {
	r.closeOnce.Do(func() {
		killTimer := time.AfterFunc(2*time.Second, func() {
			_ = r.cmd.Process.Kill()
		})
		clientErr := r.Client.Close()
		processErr := <-r.wait
		killTimer.Stop()
		if processErr != nil {
			processErr = fmt.Errorf("SSH process: %w: %s", processErr, strings.TrimSpace(r.stderr.String()))
		}
		r.closeErr = errors.Join(clientErr, processErr)
	})
	return r.closeErr
}

type Remarkable struct {
	origin  string
	root    string
	targets []string
	remote  remoteClient

	closeOnce sync.Once
	closeErr  error
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
	remote, err := connect(ctx, cfg)
	if err != nil {
		return nil, err
	}

	imp := &Remarkable{
		origin:  cfg.address,
		root:    cfg.root,
		targets: cfg.targets,
		remote:  remote,
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
	endpoint, err := url.Parse(values["location"])
	if err != nil {
		return nil, fmt.Errorf("parse location: %w", err)
	}
	if endpoint.Scheme != "remarkable" {
		return nil, fmt.Errorf("location must use remarkable://")
	}
	if endpoint.Hostname() == "" {
		return nil, fmt.Errorf("location is missing a hostname")
	}
	if strings.HasPrefix(endpoint.Hostname(), "-") {
		return nil, fmt.Errorf("location hostname must not begin with '-'")
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
	if values["password"] != "" || values["private_key_passphrase"] != "" {
		return nil, fmt.Errorf("password authentication is not supported; configure OpenSSH key authentication")
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

	insecure, err := parseBool(values, "insecure_ignore_host_key")
	if err != nil {
		return nil, err
	}
	if insecure && values["known_hosts"] != "" {
		return nil, fmt.Errorf("known_hosts and insecure_ignore_host_key cannot be used together")
	}

	address := endpoint.Host
	if endpoint.Port() == "" {
		address = net.JoinHostPort(endpoint.Hostname(), "22")
	}
	return &config{
		address:         address,
		host:            endpoint.Hostname(),
		port:            endpoint.Port(),
		user:            username,
		privateKey:      values["private_key"],
		agentSocket:     values["ssh_auth_sock"],
		knownHosts:      values["known_hosts"],
		insecureHostKey: insecure,
		root:            defaultRoot,
		targets:         append([]string(nil), defaultTargets...),
	}, nil
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

func sshArgs(cfg *config) ([]string, error) {
	args := []string{
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=10",
		"-o", "ServerAliveInterval=15",
		"-o", "ServerAliveCountMax=2",
	}
	if cfg.insecureHostKey {
		args = append(args,
			"-o", "StrictHostKeyChecking=no",
			"-o", "UserKnownHostsFile=/dev/null",
		)
	} else if cfg.knownHosts != "" {
		knownHosts, err := expandPath(cfg.knownHosts)
		if err != nil {
			return nil, fmt.Errorf("expand known_hosts path: %w", err)
		}
		args = append(args, "-o", "UserKnownHostsFile="+knownHosts)
	}
	if cfg.privateKey != "" {
		privateKey, err := expandPath(cfg.privateKey)
		if err != nil {
			return nil, fmt.Errorf("expand private key path: %w", err)
		}
		args = append(args, "-i", privateKey)
	}
	if cfg.user != "" {
		args = append(args, "-l", cfg.user)
	}
	if cfg.port != "" {
		args = append(args, "-p", cfg.port)
	}
	return append(args, cfg.host, "-s", "sftp"), nil
}

func connect(ctx context.Context, cfg *config) (remoteClient, error) {
	args, err := sshArgs(cfg)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command("ssh", args...)
	if cfg.agentSocket != "" {
		cmd.Env = append(cmd.Environ(), "SSH_AUTH_SOCK="+cfg.agentSocket)
	}
	stderr := &lockedBuffer{}
	cmd.Stderr = stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("SSH stdout: %w", err)
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("SSH stdin: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start SSH: %w", err)
	}
	wait := make(chan error, 1)
	go func() { wait <- cmd.Wait() }()

	startupDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = cmd.Process.Kill()
		case <-time.After(15 * time.Second):
			_ = cmd.Process.Kill()
		case <-startupDone:
		}
	}()
	sftpClient, err := sftp.NewClientPipe(stdout, stdin)
	close(startupDone)
	if err != nil {
		_ = cmd.Process.Kill()
		processErr := <-wait
		return nil, fmt.Errorf("start SFTP subsystem: %w (SSH: %v): %s", err, processErr, strings.TrimSpace(stderr.String()))
	}
	if err := ctx.Err(); err != nil {
		_ = sftpClient.Close()
		_ = cmd.Process.Kill()
		<-wait
		return nil, err
	}
	return &commandRemote{Client: sftpClient, cmd: cmd, wait: wait, stderr: stderr}, nil
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
		if r.remote != nil {
			r.closeErr = r.remote.Close()
		}
	})
	return r.closeErr
}

func (r *Remarkable) Close(ctx context.Context) error {
	return r.closeTransport()
}
