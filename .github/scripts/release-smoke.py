"""Exercise installed/release CLIs. Run inside scripts/test-network.sh on Linux.

Requires Python 3.11+, OpenSSL, lo and dlep-test from the network harness.
No host networking changes or persistent credentials are made here.
"""

import argparse
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import tempfile
import time
import tomllib


class Smoke:
    def __init__(self, binaries, root, version):
        self.binaries = binaries
        self.root = root
        self.version = version
        self.env = dict(os.environ, TOKIO_WORKER_THREADS="2", NO_COLOR="1")
        for key in ("DLEP_LOG", "DLEP_ROUTER_CONFIG", "DLEP_MODEM_CONFIG"):
            self.env.pop(key, None)
        self.checked = 0
        self.children = []

    def command(self, role, unified):
        return [str(self.binaries / "dlep"), role] if unified else [str(self.binaries / f"dlep-{role}")]

    def run(self, command, expected=0, env=None):
        result = subprocess.run(command, env=self.env | (env or {}), capture_output=True, text=True, timeout=15)
        assert result.returncode == expected, (command, result.returncode, result.stdout, result.stderr)
        self.checked += 1
        return result

    def certificates(self):
        self.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                  "-nodes", "-keyout", str(self.root / "ca.key"), "-out", str(self.root / "ca.pem"),
                  "-days", "1", "-subj", "/CN=DLEP smoke CA", "-addext", "basicConstraints=critical,CA:TRUE"])
        extensions = self.root / "extensions.cnf"
        extensions.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
                              "extendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=IP:127.0.0.1,IP:::1\n")
        for role in ("modem", "router"):
            self.run(["openssl", "req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                      "-keyout", str(self.root / f"{role}.key"), "-out", str(self.root / f"{role}.csr"),
                      "-subj", f"/CN=DLEP smoke {role}"])
            self.run(["openssl", "x509", "-req", "-in", str(self.root / f"{role}.csr"),
                      "-CA", str(self.root / "ca.pem"), "-CAkey", str(self.root / "ca.key"), "-CAcreateserial",
                      "-out", str(self.root / f"{role}.pem"), "-days", "1", "-extfile", str(extensions)])

    def tls_flags(self, role):
        return ["--ca-bundle", str(self.root / "ca.pem"), "--cert", str(self.root / f"{role}.pem"),
                "--key", str(self.root / f"{role}.key")]

    def config(self, name, ip="127.0.0.1", discovery_port=0, mutual=False):
        path = self.root / f"{name}.toml"
        path.write_text(f'''[network]
bind_addr = "{ip}"
tcp_port = 0
discovery_port = {discovery_port}
interface = "missing-dlep"
use_tls = true
[tls]
cert = "missing-cert.pem"
key = "missing-key.pem"
ca_bundle = "missing-ca.pem"
require_client_cert = {str(mutual).lower()}
[timers]
heartbeat_interval_ms = 1000
discovery_interval_ms = 1000
termination_timeout_ms = 1000
''')
        return path

    def cli_checks(self):
        launcher = [str(self.binaries / "dlep")]
        for flag in ("--help", "-h"):
            result = self.run(launcher + [flag])
            assert "router" in result.stdout and "modem" in result.stdout
        for flag in ("--version", "-V"):
            assert self.version in self.run(launcher + [flag]).stdout
        self.run(launcher, expected=2)
        self.run(launcher + ["unknown-role"], expected=2)
        for unified in (False, True):
            for role in ("router", "modem"):
                command = self.command(role, unified)
                for flag in ("--help", "-h"):
                    help_text = self.run(command + [flag]).stdout
                    for option in ("--config", "--interface", "--log-level", "--no-tls", "--cert",
                                   "--key", "--ca-bundle", "--check-config", "--help", "--version"):
                        assert option in help_text, (role, option)
                    assert ("--peer" in help_text) == (role == "router")
                for flag in ("--version", "-V"):
                    assert self.version in self.run(command + [flag]).stdout
                path = self.config(f"check-{role}-{unified}", mutual=True)
                common = ["--interface", "lo", "--check-config"]
                # All TLS paths in the file are deliberately wrong: CLI overrides must win.
                result = self.run(command + ["--config", str(path)] + common + self.tls_flags(role))
                assert "configuration OK" in result.stdout
                for flag in ("--config", "-c"):
                    self.run(command + [flag, str(path), "--no-tls"] + common,
                             env={f"DLEP_{role.upper()}_CONFIG": "missing-config.toml"})
                self.run(command + ["--no-tls"] + common, env={f"DLEP_{role.upper()}_CONFIG": str(path)})
                for level in ("trace", "debug", "info", "warn", "error"):
                    result = self.run(command + ["--no-tls", "--check-config", "--log-level", level],
                                      env={"DLEP_LOG": "[broken"})
                    assert "invalid log level" not in result.stderr
                result = self.run(command + ["--no-tls", "--check-config"], env={"DLEP_LOG": "[broken"})
                assert "invalid log level" in result.stderr
                for flag in ("--config", "--interface", "--log-level", "--cert", "--key", "--ca-bundle"):
                    self.run(command + [flag], expected=2)
                self.run(command + ["--unknown-flag"], expected=2)
                self.run(command + ["--config", "missing-config.toml", "--check-config"], expected=1)
                self.run(command + ["--config", str(path), "--no-tls", "--check-config"], expected=1)
                self.run(command + ["--config", str(path)] + common, expected=1)
                if role == "router":
                    self.run(command + ["--peer", "127.0.0.1:854", "--peer", "[::1]:854", "--no-tls", "--check-config"])
                    self.run(command + ["--peer", "invalid", "--check-config"], expected=2)
                else:
                    self.run(command + ["--peer", "127.0.0.1:854"], expected=2)
                print(f"PASS CLI flags: {'dlep ' if unified else 'dlep-'}{role}", flush=True)

    def start(self, name, command):
        log = self.root / f"{name}.log"
        with log.open("w") as output:
            child = subprocess.Popen(command, env=self.env, stdout=output, stderr=subprocess.STDOUT)
        entry = (child, log)
        self.children.append(entry)
        return entry

    def wait_log(self, entry, pattern, count=1):
        child, log = entry
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            text = log.read_text()
            matches = re.findall(pattern, text)
            assert child.poll() is None, (child.args, child.returncode, text)
            if len(matches) >= count:
                return matches[-1]
            time.sleep(0.02)
        raise AssertionError(("log timeout", pattern, log.read_text()))

    def stop(self, entry, sig=signal.SIGTERM):
        child, log = entry
        assert child.poll() is None, log.read_text()
        child.send_signal(sig)
        assert child.wait(timeout=8) == 0, log.read_text()
        assert "shutdown requested" in log.read_text(), log.read_text()

    def session(self, name, unified, ip, tls, discovery=False, peers=1):
        # Only discovery scenarios need a fixed UDP port; they run sequentially
        # inside a fresh network namespace. TCP always uses modem-assigned ports.
        port = 49854 if discovery else 0
        modems = []
        addresses = []
        for index in range(peers):
            path = self.config(f"{name}-modem-{index}", ip, port, mutual=tls)
            command = self.command("modem", unified) + ["--config", str(path), "--interface", "lo", "--log-level", "info"]
            command += self.tls_flags("modem") if tls else ["--no-tls"]
            modem = self.start(f"{name}-modem-{index}", command)
            addresses.append(self.wait_log(modem, r"modem listening on (\S+)"))
            modems.append(modem)
        path = self.config(f"{name}-router", ip, port)
        command = self.command("router", unified) + ["-c", str(path), "--interface", "lo", "--log-level", "info"]
        command += self.tls_flags("router") if tls else ["--no-tls"]
        if not discovery:
            for address in addresses:
                command += ["--peer", address]
        router = self.start(f"{name}-router", command)
        self.wait_log(router, r"session up", peers)
        text = router[1].read_text()
        for address in addresses:
            assert address in text, text
        assert f"tls={str(tls).lower()}" in text, text
        if discovery:
            assert "mode=Discovery" in text, text
        # Keep heartbeats active for more than two intervals.
        time.sleep(2.2)
        assert "session down" not in router[1].read_text(), router[1].read_text()
        self.stop(router, signal.SIGINT)
        for modem in modems:
            self.stop(modem)
            assert "session task error" not in modem[1].read_text(), modem[1].read_text()
        print(f"PASS session: {name}", flush=True)

    def cleanup(self):
        for child, log in self.children:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", type=Path, default=Path("target/release"))
    parser.add_argument("--version", default=tomllib.loads(Path("Cargo.toml").read_text())["workspace"]["package"]["version"])
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="dlep-release-smoke-") as directory:
        root = Path(directory)
        smoke = Smoke(args.bin_dir.resolve(), root, args.version)
        try:
            smoke.certificates()
            smoke.cli_checks()
            smoke.session("standalone-ipv4-plaintext-two-peers", False, "127.0.0.1", False, peers=2)
            smoke.session("launcher-ipv6-mutual-tls", True, "::1", True)
            smoke.session("standalone-ipv4-discovery-mutual-tls", False, "127.0.0.1", True, discovery=True)
            smoke.session("launcher-ipv4-discovery-plaintext", True, "127.0.0.1", False, discovery=True)
            print(json.dumps({"cli_and_certificate_checks": smoke.checked, "session_scenarios": 4, "version": args.version}))
        except BaseException:
            for child, log in smoke.children:
                print(f"--- {log.name}: {child.args}\n{log.read_text()}", flush=True)
            raise
        finally:
            smoke.cleanup()


if __name__ == "__main__":
    main()
