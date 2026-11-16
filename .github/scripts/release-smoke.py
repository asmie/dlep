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
        for key in ("DLEP_LOG", "DLEP_LOG_FORMAT", "DLEP_ROUTER_CONFIG", "DLEP_MODEM_CONFIG"):
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
        dns_extensions = self.root / "dns-extensions.cnf"
        dns_extensions.write_text(extensions.read_text().replace("IP:127.0.0.1,IP:::1", "DNS:localhost"))
        self.run(["openssl", "x509", "-req", "-in", str(self.root / "modem.csr"),
                  "-CA", str(self.root / "ca.pem"), "-CAkey", str(self.root / "ca.key"), "-CAcreateserial",
                  "-out", str(self.root / "dns-modem.pem"), "-days", "1", "-extfile", str(dns_extensions)])
        scoped_extensions = self.root / "scoped-extensions.cnf"
        scoped_extensions.write_text(extensions.read_text().replace("IP:127.0.0.1,IP:::1", "IP:fe80::1"))
        self.run(["openssl", "x509", "-req", "-in", str(self.root / "modem.csr"),
                  "-CA", str(self.root / "ca.pem"), "-CAkey", str(self.root / "ca.key"), "-CAcreateserial",
                  "-out", str(self.root / "scoped-modem.pem"), "-days", "1", "-extfile", str(scoped_extensions)])

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
                    for option in ("--config", "--interface", "--log-level", "--log-format", "--no-tls", "--cert",
                                   "--key", "--ca-bundle", "--bind-addr", "--discovery-port",
                                   "--check-config", "--dual-stack-discovery", "--generate-completions", "--help", "--version"):
                        assert option in help_text, (role, option)
                    assert ("--peer" in help_text) == (role == "router")
                    assert ("--tcp-port" in help_text) == (role == "modem")
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
                for log_format in ("text", "json"):
                    result = self.run(command + ["--no-tls", "--check-config", "--log-format", log_format],
                                      env={"DLEP_LOG_FORMAT": "invalid"})
                    assert result.stdout == "configuration OK\n"
                self.run(command + ["--log-format", "invalid"], expected=2)
                self.run(command + ["--log-format"], expected=2)
                self.run(command + ["--no-tls", "--check-config"], expected=2,
                         env={"DLEP_LOG_FORMAT": "invalid"})
                result = self.run(command + ["--dual-stack-discovery", "--no-tls", "--check-config"], expected=1)
                assert "explicit interface" in result.stderr
                self.run(command + ["--dual-stack-discovery", "--interface", "dlep-test", "--no-tls", "--check-config"])
                dual = self.config(f"dual-check-{role}-{unified}")
                dual.write_text(dual.read_text().replace("[network]\n", "[network]\ndiscovery_dual_stack=true\n"))
                self.run(command + ["-c", str(dual), "--interface", "dlep-test", "--bind-addr", "::", "--no-tls", "--check-config"])
                for flag in ("--config", "--interface", "--log-level", "--cert", "--key", "--ca-bundle",
                             "--bind-addr", "--discovery-port"):
                    self.run(command + [flag], expected=2)
                for value in ("hostname.invalid", "[::1]", "fe80::1%lo", "127.0.0.1:854"):
                    self.run(command + ["--bind-addr", value, "--check-config"], expected=2)
                for value in ("-1", "65536", "not-a-port"):
                    self.run(command + ["--discovery-port", value, "--check-config"], expected=2)
                wrong_bind = self.config(f"wrong-bind-{role}-{unified}", ip="192.0.2.123")
                self.run(command + ["-c", str(wrong_bind), "--no-tls"] + common, expected=1)
                self.run(command + ["-c", str(wrong_bind), "--no-tls", "--bind-addr", "127.0.0.1",
                                    "--discovery-port", "65535"] + common)
                if role == "modem":
                    offer = self.config(f"offer-check-{unified}")
                    base = offer.read_text()
                    offer.write_text(base + "\n[discovery]\noffer_retries=2\noffer_retry_interval_ms=1000\n")
                    self.run(command + ["--config", str(offer), "--no-tls"] + common)
                    for retries, interval in ((6, 1000), (1, 999)):
                        offer.write_text(base + f"\n[discovery]\noffer_retries={retries}\noffer_retry_interval_ms={interval}\n")
                        for check in ([], ["--check-config"]):
                            result = self.run(command + ["--config", str(offer), "--no-tls"] + check, expected=1)
                            assert "discovery.offer_" in result.stderr
                    self.run(command + ["--tcp-port"], expected=2)
                    for value in ("-1", "65536", "not-a-port"):
                        self.run(command + ["--tcp-port", value, "--check-config"], expected=2)
                else:
                    self.run(command + ["--tcp-port", "854"], expected=2)
                self.run(command + ["--unknown-flag"], expected=2)
                self.run(command + ["--config", "missing-config.toml", "--check-config"], expected=1)
                self.run(command + ["--config", str(path), "--no-tls", "--check-config"], expected=1)
                self.run(command + ["--config", str(path)] + common, expected=1)
                unregistered = self.config(f"unregistered-extension-{role}-{unified}", ip="192.0.2.123")
                unregistered.write_text(unregistered.read_text() + "\n[extensions.not_installed]\nenabled=true\n")
                for check in ([], ["--check-config"]):
                    result = self.run(command + ["--config", str(unregistered), "--no-tls"] + check, expected=1)
                    assert 'extension "not_installed"' in result.stderr
                    assert "no registered factory" in result.stderr
                if role == "router":
                    self.run(command + ["--peer", "127.0.0.1:854", "--peer", "[::1]:854", "--no-tls", "--check-config"])
                    self.run(command + ["--peer", "does-not-exist.invalid:854", "--no-tls", "--check-config"])
                    for peer in ("[fe80::1%dlep-missing]:854", "[fe80::1%3]:854"):
                        self.run(command + ["--peer", peer, "--no-tls", "--check-config"])
                    scoped = self.config(f"scoped-check-{unified}")
                    scoped.write_text("mode='static'\nstatic_peers=['[fe80::1%dlep-missing]:854']\n" + scoped.read_text())
                    self.run(command + ["--config", str(scoped), "--no-tls"] + common)
                    for peer in ("[::1%lo]:854", "[fe80::1%]:854", "[fe80::1%4294967296]:854"):
                        self.run(command + ["--peer", peer, "--check-config"], expected=2)
                    named = self.config(f"named-check-{unified}")
                    named.write_text("mode='static'\nstatic_peers=['does-not-exist.invalid:854']\n" + named.read_text())
                    self.run(command + ["--config", str(named)] + common + self.tls_flags(role))
                    for value in ("localhost", "localhost:65536", "https://localhost:854", "bad name:854"):
                        self.run(command + ["--peer", value, "--check-config"], expected=2)
                    self.run(command + ["--peer", "invalid", "--check-config"], expected=2)
                else:
                    self.run(command + ["--peer", "127.0.0.1:854"], expected=2)
                print(f"PASS CLI flags: {'dlep ' if unified else 'dlep-'}{role}", flush=True)

    def completion_checks(self):
        launcher = [str(self.binaries / "dlep")]
        commands = [launcher] + [self.command(role, unified)
                                for unified in (False, True) for role in ("router", "modem")]
        shells = {"bash", "elvish", "fish", "powershell", "zsh"}
        # Completion scripts must work before configuration, tracing, or socket setup.
        env = {"DLEP_ROUTER_CONFIG": "missing-router.toml", "DLEP_MODEM_CONFIG": "missing-modem.toml",
               "DLEP_LOG": "[broken"}
        scripts = {}
        for command in commands:
            self.run(command + ["--generate-completions"], expected=2)
            self.run(command + ["--generate-completions", "unknown-shell"], expected=2)
            for shell in sorted(shells):
                result = self.run(command + [f"--generate-completions={shell}"], env=env)
                assert result.stdout and not result.stderr, (command, shell, result)
                assert "generate-completions" in result.stdout, (command, shell)
                scripts[tuple(command), shell] = result.stdout
                if command[0] == launcher[0] and len(command) > 1:
                    assert result.stdout == scripts[tuple(launcher), shell], (command, shell)
                elif command != launcher:
                    assert ("tcp-port" in result.stdout) == command[0].endswith("dlep-modem")
                    assert ("--peer" in result.stdout or "-l peer " in result.stdout) == command[0].endswith("dlep-router"), (command, shell)
        self.run(launcher + ["--generate-completions", "bash", "router"], expected=2)
        self.run(launcher + ["router", "--generate-completions", "bash", "--unknown-flag"], expected=2)

        invoke = r'''
source "$1"
shift
COMP_WORDS=("$@")
COMP_CWORD=$((${#COMP_WORDS[@]} - 1))
COMP_LINE="${COMP_WORDS[*]}"
COMP_POINT=${#COMP_LINE}
binding=$(complete -p "${COMP_WORDS[0]}")
[[ $binding =~ -F\ ([^[:space:]]+) ]] || exit 1
"${BASH_REMATCH[1]}" "${COMP_WORDS[0]}" "${COMP_WORDS[COMP_CWORD]}" "${COMP_WORDS[COMP_CWORD-1]}"
printf '%s\n' "${COMPREPLY[@]}"
'''
        for command in commands[:3]:
            binary = Path(command[0]).name
            script = self.root / f"{binary}.bash"
            script.write_text(scripts[tuple(command), "bash"])
            self.run(["bash", "-n", str(script)])

            def complete(*words):
                return set(self.run(["bash", "--noprofile", "--norc", "-c", invoke, "completion-check",
                                     str(script), binary, *words]).stdout.splitlines())

            if binary == "dlep":
                assert {"router", "modem"} <= complete("")
                for role in ("router", "modem"):
                    options = complete(role, "--")
                    assert "--dual-stack-discovery" in options
                    assert ("--peer" in options) == (role == "router")
                    assert ("--tcp-port" in options) == (role == "modem")
                    assert shells == complete(role, "--generate-completions", "")
                    assert {"text", "json"} == complete(role, "--log-format", "")
            else:
                options = complete("--")
                assert "--dual-stack-discovery" in options
                assert "--config" in options
                assert ("--peer" in options) == (binary == "dlep-router")
                assert {"text", "json"} == complete("--log-format", "")
                assert ("--tcp-port" in options) == (binary == "dlep-modem")
            assert shells == complete("--generate-completions", "")
        print("PASS shell completions: five generators, launcher/standalone names and Bash behavior", flush=True)

    def start(self, name, command, env=None):
        log = self.root / f"{name}.log"
        with log.open("w") as output:
            child = subprocess.Popen(command, env=self.env | (env or {}), stdout=output, stderr=subprocess.STDOUT)
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

    def session(self, name, unified, ip, tls, discovery=False, peers=1, dual=False):
        # Only discovery scenarios need a fixed UDP port; they run sequentially
        # inside a fresh network namespace. TCP always uses modem-assigned ports.
        port = 49854 if discovery else 0
        interface = "dlep-test" if dual else "lo"
        modems = []
        addresses = []
        for index in range(peers):
            path = self.config(f"{name}-modem-{index}", "192.0.2.123", 1, mutual=tls)
            path.write_text(path.read_text().replace("tcp_port = 0", "tcp_port = 1"))
            if discovery:
                path.write_text(path.read_text() + "\n[discovery]\noffer_retries=2\n")
            modem_ip = ("192.0.2.1", "fe80::1")[index] if dual else ip
            command = self.command("modem", unified) + ["--config", str(path), "--interface", interface, "--log-level", "info",
                "--bind-addr", modem_ip, "--tcp-port", "0", "--discovery-port", str(port)]
            command += self.tls_flags("modem") if tls else ["--no-tls"]
            modem = self.start(f"{name}-modem-{index}", command)
            addresses.append(self.wait_log(modem, r"modem listening on (\S+)"))
            assert not addresses[-1].endswith(":1"), addresses[-1]
            modems.append(modem)
        path = self.config(f"{name}-router", "192.0.2.123", 1)
        command = self.command("router", unified) + ["-c", str(path), "--interface", interface, "--log-level", "info",
            "--bind-addr", ip, "--discovery-port", str(port)]
        command += self.tls_flags("router") if tls else ["--no-tls"]
        if dual:
            command += ["--dual-stack-discovery"]
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
        assert len(re.findall(r"session up", router[1].read_text())) == peers
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

    def json_session(self, unified):
        name = f"json-logging-{unified}"
        description = 'radio "quoted"\nsecond line'
        path = self.config(f"{name}-modem", mutual=True)
        path.write_text(f"peer_description={json.dumps(description)}\n" + path.read_text())
        modem_flags = [] if unified else ["--log-format", "json"]
        modem = self.start(f"{name}-modem", self.command("modem", unified) + modem_flags +
                           ["--config", str(path), "--interface", "lo"] + self.tls_flags("modem"),
                           env={"DLEP_LOG_FORMAT": "json" if unified else "text"})

        def wait_event(entry, prefix):
            child, log = entry
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                assert child.poll() is None, (child.args, child.returncode, log.read_text())
                # Ignore the trailing partial record if a concurrent write is in progress.
                for line in log.read_text().splitlines(keepends=True):
                    if line.endswith("\n"):
                        event = json.loads(line)
                        if event["fields"].get("message", "").startswith(prefix):
                            return event
                time.sleep(0.02)
            raise AssertionError(("JSON log timeout", prefix, log.read_text()))

        listening = wait_event(modem, "modem listening on ")
        address = listening["fields"]["message"].removeprefix("modem listening on ")
        startup = wait_event(modem, "starting dlep-modem")
        assert startup["fields"]["peer"] == description, startup
        assert startup["fields"]["tls"] is True, startup
        assert startup["fields"]["port"] == 0, startup
        path = self.config(f"{name}-router")
        router_flags = ["--log-format", "json"] if unified else []
        router = self.start(f"{name}-router", self.command("router", unified) + router_flags +
                            ["--config", str(path), "--interface", "lo", "--peer", address] + self.tls_flags("router"),
                            env={"DLEP_LOG_FORMAT": "text" if unified else "json"})
        connected = wait_event(router, "session up")
        assert connected["fields"]["addr"] == address, connected
        assert connected["fields"]["tls"] is True, connected
        self.stop(router)
        self.stop(modem)
        for child, log in (router, modem):
            text = log.read_text()
            assert "\x1b" not in text, text
            events = [json.loads(line) for line in text.splitlines()]
            assert any(event["fields"].get("message") == "shutdown requested" for event in events), events
            for event in events:
                assert event["level"] in {"INFO", "WARN", "ERROR"}, event
                assert isinstance(event["timestamp"], str) and isinstance(event["target"], str), event
                assert isinstance(event["fields"], dict), event
        print(f"PASS session: {name} (JSON fields, escaping, CLI/environment precedence, TLS, SIGTERM)", flush=True)

    def identity_session(self, unified, scoped=False):
        kind = "scoped" if scoped else "dns"
        name = f"{kind}-reconnect-{unified}"
        interface = "dlep-test" if scoped else "lo"
        ip = "fe80::1" if scoped else "127.0.0.1"
        modem_flags = ["--interface", interface, "--bind-addr", ip, "--discovery-port", "0"]
        modem_flags += self.tls_flags("modem")
        cert_index = modem_flags.index("--cert")
        modem_flags[cert_index + 1] = str(self.root / f"{kind}-modem.pem")
        command = self.command("modem", unified) + modem_flags
        modem = self.start(f"{name}-modem", command + ["--tcp-port", "0"])
        address = self.wait_log(modem, r"modem listening on (\S+)")
        port = address.rsplit(":", 1)[1]
        path = self.config(f"{name}-router")
        flags = ["--config", str(path), "--interface", interface, "--bind-addr", ip] + self.tls_flags("router")
        peer = f"[fe80::1%dlep-test]:{port}" if scoped else f"localhost:{port}"
        peers = [peer, address] if scoped else [peer]
        if unified:
            path.write_text(f"mode='static'\nstatic_peers={peers!r}\n" + path.read_text())
        else:
            for peer in peers:
                flags += ["--peer", peer]
        router = self.start(f"{name}-router", self.command("router", unified) + flags)
        self.wait_log(router, r"session up")
        assert address in router[1].read_text()
        assert "tls=true" in router[1].read_text()
        if scoped:
            time.sleep(2.2)
            assert len(re.findall(r"session up", router[1].read_text())) == 1
        self.stop(modem)
        replacement = self.start(f"{name}-replacement", command + ["--tcp-port", port])
        self.wait_log(replacement, r"modem listening on (\S+)")
        self.wait_log(router, r"session up", count=2)
        if scoped:
            time.sleep(2.2)
            assert len(re.findall(r"session up", router[1].read_text())) == 2
        self.stop(router, signal.SIGINT)
        self.stop(replacement)
        print(f"PASS session: {name} ({'named zone plus numeric alias' if scoped else 'DNS-only certificate'}, {'config' if unified else 'CLI'} peer, reconnect)", flush=True)


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
            smoke.completion_checks()
            smoke.session("standalone-ipv4-plaintext-two-peers", False, "127.0.0.1", False, peers=2)
            smoke.session("launcher-ipv6-mutual-tls", True, "::1", True)
            smoke.session("standalone-ipv4-discovery-mutual-tls", False, "127.0.0.1", True, discovery=True)
            smoke.session("launcher-ipv4-discovery-plaintext", True, "127.0.0.1", False, discovery=True)
            smoke.identity_session(False)
            smoke.identity_session(True)
            smoke.identity_session(False, scoped=True)
            smoke.identity_session(True, scoped=True)
            smoke.session("launcher-dual-discovery-two-families", True, "0.0.0.0", False, discovery=True, peers=2, dual=True)
            smoke.json_session(False)
            smoke.json_session(True)
            print(json.dumps({"cli_and_certificate_checks": smoke.checked, "session_scenarios": 11, "version": args.version}))
        except BaseException:
            for child, log in smoke.children:
                print(f"--- {log.name}: {child.args}\n{log.read_text()}", flush=True)
            raise
        finally:
            smoke.cleanup()


if __name__ == "__main__":
    main()
