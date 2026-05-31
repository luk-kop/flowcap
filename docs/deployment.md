# Deployment

## Systemd Service

Create a dedicated system user (no home directory, no login shell):

```bash
useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin flowcap
```

Install the binary:

```bash
sudo cp bin/flowcap /usr/local/bin/
sudo chmod 755 /usr/local/bin/flowcap
```

Check the embedded version metadata:

```bash
/usr/local/bin/flowcap --version
```

Create log files with correct ownership:

```bash
sudo touch /var/log/flowcap.log /var/log/flowcap-stats.log
sudo chown flowcap:flowcap /var/log/flowcap.log /var/log/flowcap-stats.log
```

Create an environment file `/etc/default/flowcap`:

```bash
INTERFACE=eth0
FLOWCAP_OPTS=-json -metrics-addr 127.0.0.1:9090 -stats-file /var/log/flowcap-stats.log
```

Create a service unit file `/etc/systemd/system/flowcap.service`:

```ini
[Unit]
Description=flowcap - eBPF network flow capture
After=network.target

[Service]
Type=simple
User=flowcap
Group=flowcap
EnvironmentFile=/etc/default/flowcap
ExecStart=/usr/local/bin/flowcap $FLOWCAP_OPTS $INTERFACE
Restart=on-failure
RestartSec=5
StandardOutput=append:/var/log/flowcap.log
StandardError=journal
SyslogIdentifier=flowcap
AmbientCapabilities=CAP_BPF CAP_PERFMON CAP_NET_ADMIN
CapabilityBoundingSet=CAP_BPF CAP_PERFMON CAP_NET_ADMIN
NoNewPrivileges=true
CPUQuota=10%
MemoryMax=128M

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now flowcap
```

To change configuration, edit `/etc/default/flowcap` and restart:

```bash
sudo systemctl restart flowcap
```

View logs:

```bash
# Flow output
tail -f /var/log/flowcap.log

# Service logs
journalctl -u flowcap -f
```

On startup, flowcap logs the embedded `version`, `revision`, and `build_date` values along with the selected interface and runtime options. This helps confirm which build is running under systemd after upgrades.

## Troubleshooting Capabilities

Flowcap calls `rlimit.RemoveMemlock()` during startup before loading eBPF objects. On the supported Linux 6.6+ kernels this should normally be handled by cgroup-based BPF memory accounting and the service capabilities above are sufficient.

If startup fails with a memlock or `RLIMIT_MEMLOCK` error on a custom kernel or host with unusual BPF memory accounting settings, test whether adding `CAP_SYS_RESOURCE` resolves it:

```ini
AmbientCapabilities=CAP_BPF CAP_PERFMON CAP_NET_ADMIN CAP_SYS_RESOURCE
CapabilityBoundingSet=CAP_BPF CAP_PERFMON CAP_NET_ADMIN CAP_SYS_RESOURCE
```

Do not add `CAP_SYS_RESOURCE` by default unless the host requires it; it is broader than the normal Flowcap runtime capability set.

## Log Rotation

Create `/etc/logrotate.d/flowcap` to prevent log files from growing indefinitely:

```text
/var/log/flowcap.log /var/log/flowcap-stats.log {
    daily
    maxsize 100M
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
```

`copytruncate` is used because flowcap holds open file descriptors - it copies the log and truncates the original without requiring a process restart.
