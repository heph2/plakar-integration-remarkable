package remarkable

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"io"
	"net"
	"os"
	"path"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/PlakarKorp/kloset/connectors"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func TestParseConfigDefaultsForRemarkableOne(t *testing.T) {
	cfg, err := parseConfig(map[string]string{
		"location":                 "remarkable://10.11.99.1",
		"password":                 "device-password",
		"insecure_ignore_host_key": "true",
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
		{"missing host", map[string]string{"location": "remarkable://", "password": "x", "insecure_ignore_host_key": "true"}},
		{"wrong scheme", map[string]string{"location": "ssh://10.11.99.1", "password": "x", "insecure_ignore_host_key": "true"}},
		{"custom path", map[string]string{"location": "remarkable://10.11.99.1/tmp", "password": "x", "insecure_ignore_host_key": "true"}},
		{"password in URI", map[string]string{"location": "remarkable://root:secret@10.11.99.1", "insecure_ignore_host_key": "true"}},
		{"two usernames", map[string]string{"location": "remarkable://root@10.11.99.1", "username": "root", "password": "x", "insecure_ignore_host_key": "true"}},
		{"no authentication", map[string]string{"location": "remarkable://10.11.99.1", "insecure_ignore_host_key": "true", "ssh_auth_sock": ""}},
		{"invalid boolean", map[string]string{"location": "remarkable://10.11.99.1", "password": "x", "insecure_ignore_host_key": "sometimes"}},
		{"conflicting host policy", map[string]string{"location": "remarkable://10.11.99.1", "password": "x", "known_hosts": "/tmp/known_hosts", "insecure_ignore_host_key": "true"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := parseConfig(tt.config); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestPrivateKeyUsesItsOwnPassphrase(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(key, "remarkable test key", []byte("key-passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	keyFile := path.Join(t.TempDir(), "id_remarkable")
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(block), 0600); err != nil {
		t.Fatal(err)
	}

	cfg := &config{
		password:             "device-password",
		privateKey:           keyFile,
		privateKeyPassphrase: "key-passphrase",
	}
	methods, closer, err := authMethods(cfg)
	if closer != nil {
		defer closer.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	if len(methods) != 2 {
		t.Fatalf("got %d auth methods, want password and private key", len(methods))
	}
}

func TestKnownHostsPinsTheTabletKey(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostKey, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	knownHosts := path.Join(t.TempDir(), "known_hosts")
	line := knownhosts.Line([]string{"10.11.99.1"}, hostKey) + "\n"
	if err := os.WriteFile(knownHosts, []byte(line), 0600); err != nil {
		t.Fatal(err)
	}

	callback, err := hostKeyCallback(&config{knownHosts: knownHosts})
	if err != nil {
		t.Fatal(err)
	}
	if err := callback("10.11.99.1:22", &net.TCPAddr{IP: net.ParseIP("10.11.99.1"), Port: 22}, hostKey); err != nil {
		t.Fatalf("pinned key rejected: %v", err)
	}

	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherKey, err := ssh.NewPublicKey(otherPub)
	if err != nil {
		t.Fatal(err)
	}
	if err := callback("10.11.99.1:22", &net.TCPAddr{IP: net.ParseIP("10.11.99.1"), Port: 22}, otherKey); err == nil {
		t.Fatal("changed host key was accepted")
	}
}

type fakeNode struct {
	mode    os.FileMode
	content string
	target  string
}

type fakeRemote struct {
	nodes  map[string]fakeNode
	closed bool
}

func (f *fakeRemote) Lstat(name string) (os.FileInfo, error) {
	node, ok := f.nodes[name]
	if !ok {
		return nil, os.ErrNotExist
	}
	return fakeInfo{name: path.Base(name), node: node}, nil
}

func (f *fakeRemote) ReadDir(name string) ([]os.FileInfo, error) {
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
