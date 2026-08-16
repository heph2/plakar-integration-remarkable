# reMarkable integration

This importer backs up a reMarkable tablet over SSH. It is designed for the
reMarkable 1 and uses the tablet's SFTP subsystem through the system OpenSSH
client. The backup run is read-only: it does not install software, stop
services, or write to the device.

The snapshot preserves the raw, proprietary Xochitl data needed for recovery:

- `/home/root/.local/share/remarkable/xochitl`
- `/home/root/.config/remarkable/xochitl.conf`

All files under the document directory are copied opaquely, including unknown
sidecars added by future Xochitl versions. The configuration file is included
because it was requested for disaster recovery; it normally contains the
tablet's root password in plaintext. Protect access to the resulting snapshots.

## Prepare the tablet

reMarkable 1 exposes SSH without Developer Mode. Connect it by USB and use
`root@10.11.99.1`. The device-specific password and available IP addresses are
shown under **Settings > Help/About > Copyright and licenses > GPLv3
Compliance** (the exact menu name depends on the OS version).

For unattended backups, install a dedicated SSH key instead of putting the
password in shell history:

```sh
ssh-keygen -t rsa -b 3072 -f ~/.ssh/id_rsa_remarkable
ssh root@10.11.99.1 'mkdir -p -m 700 /home/root/.ssh'
cat ~/.ssh/id_rsa_remarkable.pub | \
  ssh root@10.11.99.1 'tee -a /home/root/.ssh/authorized_keys >/dev/null && chmod 600 /home/root/.ssh/authorized_keys'
ssh-add ~/.ssh/id_rsa_remarkable
```

The explicit installation commands avoid an `ssh-copy-id` path bug present in
OpenSSH versions older than 9.4 when used with Dropbear. Installing the public
key is an explicit one-time device change, and possession of the private key
grants root access to the tablet; store it accordingly.

Pin the host key while directly connected over a trusted USB cable. Review the
fingerprint before accepting it; do not use `insecure_ignore_host_key` for
routine backups. By default the importer reads `~/.ssh/known_hosts`.

Confirm that SFTP is available on the installed tablet OS:

```sh
sftp root@10.11.99.1
```

## Build and install

The `ssh` executable must be available in `PATH`.

```sh
make package install
```

Nix-wrapped Plakar installations may point their default data directory into
the read-only Nix store. Install and run with a writable data directory:

```sh
PLAKAR_DATA="${XDG_DATA_HOME:-$HOME/.local/share}/plakar"
plakar -datadir "$PLAKAR_DATA" pkg add -u ./remarkable_v1.1.0_linux_amd64.ptar
plakar -datadir "$PLAKAR_DATA" at /path/to/repository backup remarkable://10.11.99.1
```

## Back up

With the dedicated key loaded in `SSH_AUTH_SOCK`:

```sh
plakar at /path/to/repository backup remarkable://10.11.99.1
```

Explicit key and known-hosts paths can instead be supplied as connector
options:

```sh
plakar at /path/to/repository backup \
  -o private_key=~/.ssh/id_rsa_remarkable \
  -o known_hosts=~/.ssh/known_hosts \
  remarkable://10.11.99.1
```

The importer invokes OpenSSH with `BatchMode=yes`, so password prompts are not
supported. Use an SSH agent, `private_key`, or an identity configured in
`~/.ssh/config`. Host aliases and other OpenSSH settings are honored.

## Consistency

The importer is deliberately read-only: it never stops services or changes the
tablet. reMarkable's Xochitl documentation says Xochitl should not be running
while its document store is accessed. For a consistent snapshot, stop Xochitl
in a separate SSH session immediately before the backup and always start it
again afterward:

```sh
(
  set -e
  trap "ssh root@10.11.99.1 'systemctl start xochitl'" EXIT
  ssh root@10.11.99.1 'systemctl stop xochitl'
  plakar at /path/to/repository backup remarkable://10.11.99.1
)
```

A backup taken while Xochitl is running is best-effort and may combine files
from different document states. Keep the tablet awake, powered, and connected
until the command completes.

## Configuration

| Option | Default | Description |
| --- | --- | --- |
| `location` | required | `remarkable://[user@]host[:port]`; paths are intentionally rejected |
| `username` | `root` | SSH user, unless present in the location |
| `private_key` | OpenSSH configuration | Identity file passed to `ssh -i` |
| `ssh_auth_sock` | `$SSH_AUTH_SOCK` | SSH agent socket override |
| `known_hosts` | `~/.ssh/known_hosts` | Pinned OpenSSH host keys |
| `insecure_ignore_host_key` | `false` | Disable host verification; testing only |

Host-key pinning remains enabled by default. Any legacy algorithm overrides
needed by older firmware can be configured normally in `~/.ssh/config`.

## References

- [reMarkable Xochitl documentation](https://developer.remarkable.com/documentation/xochitl)
- [reMarkable SSH access guide](https://remarkable.guide/guide/access/ssh.html)
- [reMarkable backup guide](https://remarkable.guide/guide/access/backup.html)
- [Plakar Go Kloset SDK](https://github.com/PlakarKorp/go-kloset-sdk)
