package remarkable

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PlakarKorp/kloset/connectors"
	"github.com/pkg/sftp"
)

func TestSchemaLocationPatternMatchesRuntimePolicy(t *testing.T) {
	data, err := os.ReadFile("importer/schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Properties struct {
			Location struct {
				Pattern string `json:"pattern"`
			} `json:"location"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatal(err)
	}
	pattern, err := regexp.Compile(schema.Properties.Location.Pattern)
	if err != nil {
		t.Fatal(err)
	}
	for _, location := range []string{
		"remarkable://10.11.99.1",
		"remarkable://root@remarkable.local:22",
		"remarkable://root@[fe80::1]:22",
	} {
		if !pattern.MatchString(location) {
			t.Errorf("valid location rejected: %s", location)
		}
	}
	for _, location := range []string{
		"remarkable://-F",
		"remarkable://root:secret@10.11.99.1",
		"remarkable://10.11.99.1?profile=other",
		"remarkable://10.11.99.1/tmp",
	} {
		if pattern.MatchString(location) {
			t.Errorf("invalid location accepted: %s", location)
		}
	}
}

func TestSchemaRequiredKeysAreDefinedInEachSubschema(t *testing.T) {
	data, err := os.ReadFile("importer/schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema any
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatal(err)
	}
	var check func(any, string)
	check = func(value any, location string) {
		switch value := value.(type) {
		case map[string]any:
			if required, ok := value["required"].([]any); ok {
				properties, _ := value["properties"].(map[string]any)
				for _, key := range required {
					if _, ok := properties[key.(string)]; !ok {
						t.Errorf("%s: required key %q is not locally defined", location, key)
					}
				}
			}
			for key, child := range value {
				check(child, location+"/"+key)
			}
		case []any:
			for index, child := range value {
				check(child, fmt.Sprintf("%s/%d", location, index))
			}
		}
	}
	check(schema, "#")
}

func TestSystemSSHArgumentsHonorAliasesAndSecureDefaults(t *testing.T) {
	cfg, err := parseConfig(map[string]string{
		"location": "remarkable://remarkable",
	})
	if err != nil {
		t.Fatal(err)
	}
	args, err := sshArgs(cfg)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(args, " ")
	for _, required := range []string{
		"-o BatchMode=yes",
		"-o ConnectTimeout=10",
		"-l root",
		"remarkable -s sftp",
	} {
		if !strings.Contains(got, required) {
			t.Errorf("SSH arguments %q do not contain %q", got, required)
		}
	}
	if strings.Contains(got, " -p ") {
		t.Fatalf("default port should be left to OpenSSH config: %q", got)
	}
}

func TestSystemSSHArgumentsApplyExplicitSecurityOptions(t *testing.T) {
	cfg, err := parseConfig(map[string]string{
		"location":      "remarkable://root@10.11.99.1:2222",
		"private_key":   "~/id_remarkable",
		"known_hosts":   "~/known_remarkable",
		"ssh_auth_sock": "/tmp/remarkable-agent.sock",
	})
	if err != nil {
		t.Fatal(err)
	}
	args, err := sshArgs(cfg)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(args, " ")
	for _, required := range []string{
		"-p 2222",
		"-i ",
		"-o UserKnownHostsFile=",
		"10.11.99.1 -s sftp",
	} {
		if !strings.Contains(got, required) {
			t.Errorf("SSH arguments %q do not contain %q", got, required)
		}
	}
}

func TestParseConfigDefaultsForRemarkableOne(t *testing.T) {
	cfg, err := parseConfig(map[string]string{
		"location": "remarkable://10.11.99.1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.address != "10.11.99.1:22" {
		t.Fatalf("address = %q", cfg.address)
	}
	if cfg.user != "root" {
		t.Fatalf("user = %q", cfg.user)
	}
	if cfg.root != "/home/root" {
		t.Fatalf("root = %q", cfg.root)
	}
	want := []string{
		"/home/root/.local/share/remarkable/xochitl",
		"/home/root/.config/remarkable/xochitl.conf",
	}
	if strings.Join(cfg.targets, "\n") != strings.Join(want, "\n") {
		t.Fatalf("targets = %#v", cfg.targets)
	}
}

func TestParseConfigRejectsUnsafeOrAmbiguousLocations(t *testing.T) {
	tests := []struct {
		name   string
		config map[string]string
	}{
		{"missing host", map[string]string{"location": "remarkable://"}},
		{"option-like host", map[string]string{"location": "remarkable://-F"}},
		{"wrong scheme", map[string]string{"location": "ssh://10.11.99.1"}},
		{"custom path", map[string]string{"location": "remarkable://10.11.99.1/tmp"}},
		{"password in URI", map[string]string{"location": "remarkable://root:secret@10.11.99.1"}},
		{"password option", map[string]string{"location": "remarkable://10.11.99.1", "password": "secret"}},
		{"two usernames", map[string]string{"location": "remarkable://root@10.11.99.1", "username": "root"}},
		{"invalid boolean", map[string]string{"location": "remarkable://10.11.99.1", "insecure_ignore_host_key": "sometimes"}},
		{"conflicting host policy", map[string]string{"location": "remarkable://10.11.99.1", "known_hosts": "/tmp/known_hosts", "insecure_ignore_host_key": "true"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := parseConfig(tt.config); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

type fakeNode struct {
	mode    os.FileMode
	content string
	target  string
}

type fakeRemote struct {
	nodes         map[string]fakeNode
	readDirErrors map[string]error
	closed        bool
}

func (f *fakeRemote) Lstat(name string) (os.FileInfo, error) {
	node, ok := f.nodes[name]
	if !ok {
		return nil, os.ErrNotExist
	}
	return fakeInfo{name: path.Base(name), node: node}, nil
}

func (f *fakeRemote) ReadDir(name string) ([]os.FileInfo, error) {
	if err := f.readDirErrors[name]; err != nil {
		return nil, err
	}
	if node, ok := f.nodes[name]; !ok || !node.mode.IsDir() {
		return nil, os.ErrNotExist
	}
	var entries []os.FileInfo
	for pathname, node := range f.nodes {
		if path.Dir(pathname) == name && pathname != name {
			entries = append(entries, fakeInfo{name: path.Base(pathname), node: node})
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	return entries, nil
}

func (f *fakeRemote) ReadLink(name string) (string, error) {
	node, ok := f.nodes[name]
	if !ok || node.mode&os.ModeSymlink == 0 {
		return "", os.ErrInvalid
	}
	return node.target, nil
}

func (f *fakeRemote) Open(name string) (io.ReadCloser, error) {
	node, ok := f.nodes[name]
	if !ok || !node.mode.IsRegular() {
		return nil, os.ErrInvalid
	}
	return io.NopCloser(strings.NewReader(node.content)), nil
}

func (f *fakeRemote) Close() error {
	f.closed = true
	return nil
}

type fakeInfo struct {
	name string
	node fakeNode
}

func (i fakeInfo) Name() string       { return i.name }
func (i fakeInfo) Size() int64        { return int64(len(i.node.content)) }
func (i fakeInfo) Mode() os.FileMode  { return i.node.mode }
func (i fakeInfo) ModTime() time.Time { return time.Unix(1_700_000_000, 0) }
func (i fakeInfo) IsDir() bool        { return i.node.mode.IsDir() }
func (i fakeInfo) Sys() any           { return nil }

func TestImportBacksUpRawDocumentsAndSensitiveConfiguration(t *testing.T) {
	const dir = os.ModeDir | 0700
	remote := &fakeRemote{nodes: map[string]fakeNode{
		"/home/root":                                                   {mode: dir},
		"/home/root/.config":                                           {mode: dir},
		"/home/root/.config/remarkable":                                {mode: dir},
		"/home/root/.config/remarkable/xochitl.conf":                   {mode: 0600, content: "DeveloperPassword=secret\n"},
		"/home/root/.local":                                            {mode: dir},
		"/home/root/.local/share":                                      {mode: dir},
		"/home/root/.local/share/remarkable":                           {mode: dir},
		"/home/root/.local/share/remarkable/xochitl":                   {mode: dir},
		"/home/root/.local/share/remarkable/xochitl/document.metadata": {mode: 0600, content: `{"visibleName":"Notes"}`},
		"/home/root/.local/share/remarkable/xochitl/document":          {mode: dir},
		"/home/root/.local/share/remarkable/xochitl/document/page.rm":  {mode: 0600, content: "raw strokes"},
		"/home/root/.local/share/remarkable/xochitl/latest":            {mode: os.ModeSymlink | 0777, target: "document"},
	}}
	imp := &Remarkable{
		origin:  "10.11.99.1:22",
		root:    "/home/root",
		targets: defaultTargets,
		remote:  remote,
	}

	records := make(chan *connectors.Record, 32)
	if err := imp.Import(context.Background(), records, nil); err != nil {
		t.Fatal(err)
	}

	got := make(map[string]string)
	var symlinkTarget string
	for record := range records {
		if record.Err != nil {
			t.Fatalf("record %s: %v", record.Pathname, record.Err)
		}
		if !record.FileInfo.Lmode.IsRegular() && record.Reader != nil {
			t.Fatalf("non-regular record %s has a content reader", record.Pathname)
		}
		if record.Pathname == "/home/root/.local/share/remarkable/xochitl/latest" {
			symlinkTarget = record.Target
		}
		if record.Reader != nil && record.FileInfo.Lmode.IsRegular() {
			body, err := io.ReadAll(record.Reader)
			if err != nil {
				t.Fatal(err)
			}
			if err := record.Reader.Close(); err != nil {
				t.Fatal(err)
			}
			got[record.Pathname] = string(body)
		}
	}

	if got["/home/root/.local/share/remarkable/xochitl/document/page.rm"] != "raw strokes" {
		t.Fatalf("page content = %q", got["/home/root/.local/share/remarkable/xochitl/document/page.rm"])
	}
	if got["/home/root/.config/remarkable/xochitl.conf"] != "DeveloperPassword=secret\n" {
		t.Fatalf("config content = %q", got["/home/root/.config/remarkable/xochitl.conf"])
	}
	if symlinkTarget != "document" {
		t.Fatalf("symlink target = %q", symlinkTarget)
	}
	if _, ok := got["/home/root/.local/share/remarkable/xochitl/document.metadata"]; !ok {
		t.Fatal("metadata sidecar was not backed up")
	}
}

func TestImportReportsOneDirectoryErrorAndContinues(t *testing.T) {
	const dir = os.ModeDir | 0700
	remote := &fakeRemote{
		nodes: map[string]fakeNode{
			"/home/root":                                 {mode: dir},
			"/home/root/.config":                         {mode: dir},
			"/home/root/.config/remarkable":              {mode: dir},
			"/home/root/.config/remarkable/xochitl.conf": {mode: 0600, content: "config"},
			"/home/root/.local":                          {mode: dir},
			"/home/root/.local/share":                    {mode: dir},
			"/home/root/.local/share/remarkable":         {mode: dir},
			"/home/root/.local/share/remarkable/xochitl": {mode: dir},
		},
		readDirErrors: map[string]error{
			"/home/root/.local/share/remarkable/xochitl": errors.New("document changed during backup"),
		},
	}
	imp := &Remarkable{origin: "tablet:22", root: defaultRoot, targets: defaultTargets, remote: remote}
	records := make(chan *connectors.Record, 32)
	if err := imp.Import(context.Background(), records, nil); err != nil {
		t.Fatal(err)
	}

	var gotError, gotConfig bool
	for record := range records {
		if record.Pathname == "/home/root/.local/share/remarkable/xochitl" && record.Err != nil {
			gotError = true
		}
		if record.Pathname == "/home/root/.config/remarkable/xochitl.conf" && record.Err == nil {
			gotConfig = true
		}
	}
	if !gotError || !gotConfig {
		t.Fatalf("error record = %v, config record = %v", gotError, gotConfig)
	}
}

type blockingRemote struct {
	started chan struct{}
	closed  chan struct{}
	once    sync.Once
}

func (r *blockingRemote) Lstat(string) (os.FileInfo, error) {
	r.once.Do(func() { close(r.started) })
	<-r.closed
	return nil, net.ErrClosed
}
func (r *blockingRemote) ReadDir(string) ([]os.FileInfo, error) { return nil, net.ErrClosed }
func (r *blockingRemote) ReadLink(string) (string, error)       { return "", net.ErrClosed }
func (r *blockingRemote) Open(string) (io.ReadCloser, error)    { return nil, net.ErrClosed }
func (r *blockingRemote) Close() error {
	select {
	case <-r.closed:
	default:
		close(r.closed)
	}
	return nil
}

func TestImportCancellationInterruptsBlockedRemoteIO(t *testing.T) {
	remote := &blockingRemote{started: make(chan struct{}), closed: make(chan struct{})}
	imp := &Remarkable{root: defaultRoot, targets: defaultTargets, remote: remote}
	ctx, cancel := context.WithCancel(context.Background())
	records := make(chan *connectors.Record, 1)
	done := make(chan error, 1)
	go func() { done <- imp.Import(ctx, records, nil) }()
	<-remote.started
	cancel()

	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		remote.Close()
		t.Fatal("Import did not interrupt blocked remote I/O after cancellation")
	}
}

func TestSSHHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_REMARKABLE_SSH_HELPER") != "1" {
		return
	}
	_, _ = os.Stdout.Write([]byte{0, 0, 0, 5, 2, 0, 0, 0, 3})
	_, _ = io.Copy(io.Discard, os.Stdin)
	time.Sleep(30 * time.Second)
}

func TestCommandRemoteCloseKillsHungSSHProcess(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=TestSSHHelperProcess")
	cmd.Env = append(cmd.Environ(), "GO_WANT_REMARKABLE_SSH_HELPER=1")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	wait := make(chan error, 1)
	go func() { wait <- cmd.Wait() }()
	client, err := sftp.NewClientPipe(stdout, stdin)
	if err != nil {
		t.Fatal(err)
	}
	remote := &commandRemote{Client: client, cmd: cmd, wait: wait, stderr: &lockedBuffer{}}
	done := make(chan error, 1)
	go func() { done <- remote.Close() }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		_ = cmd.Process.Kill()
		<-done
		t.Fatal("Close did not kill a hung SSH process")
	}
}

func TestConnectCancellationStopsSystemSSH(t *testing.T) {
	binDir := t.TempDir()
	sshPath := path.Join(binDir, "ssh")
	if err := os.WriteFile(sshPath, []byte("#!/bin/sh\nexec sleep 10\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err := connect(ctx, &config{host: "remarkable", user: "root"})
	if err == nil {
		t.Fatal("expected system SSH cancellation error")
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("system SSH cancellation took %s", elapsed)
	}
}

func TestCloseClosesRemoteClient(t *testing.T) {
	remote := &fakeRemote{}
	imp := &Remarkable{remote: remote}
	if err := imp.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !remote.closed {
		t.Fatal("remote client was not closed")
	}
}
