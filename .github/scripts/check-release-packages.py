"""Check archived sources without borrowing files from the repository.

Run after `cargo package --workspace --allow-dirty --locked` and
`cargo fetch --locked`. The fetch includes development dependencies that package
verification may not download; all checks below intentionally run offline.
This reconstructs an isolated workspace from the archives and patches ONLY the
unpublished DLEP dependencies to those extracted copies. Third-party versions use Cargo.lock.
Cargo's preceding package verification checks the normalized registry packages;
this additionally compiles every packaged test and installs all three commands.
"""

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import tomllib


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--install-root", type=Path, default=Path("target/release-install"))
    parser.add_argument("--run-tests", action="store_true", help="needs the network-test namespace")
    args = parser.parse_args()
    repo = Path.cwd()
    install = args.install_root.resolve()
    metadata = json.loads(subprocess.check_output(["cargo", "metadata", "--no-deps", "--locked", "--offline", "--format-version", "1"]))
    members = [p for p in metadata["packages"] if p["id"] in metadata["workspace_members"]]
    version = tomllib.loads((repo / "Cargo.toml").read_text())["workspace"]["package"]["version"]
    with tempfile.TemporaryDirectory(prefix="dlep-package-check-") as directory:
        root = Path(directory)
        names = []
        for package in members:
            assert package["version"] == version, package["name"]
            name = f'{package["name"]}-{version}'
            names.append(name)
            with tarfile.open(repo / "target/package" / f"{name}.crate") as archive:
                assert all(n.startswith(name + "/") for n in archive.getnames())
                archive.extractall(root, filter="data")
            for required in ("LICENSE", "README.md", "Cargo.toml", "Cargo.lock"):
                assert (root / name / required).is_file(), (name, required)
            # Cargo must flatten symlinks; the extracted package stands alone.
            assert not any(p.is_symlink() for p in (root / name).rglob("*")), name
        manifest = '[workspace]\nresolver = "3"\nmembers = ' + json.dumps(names) + '\n\n[patch.crates-io]\n'
        for package, name in zip(members, names):
            manifest += f'{package["name"]} = {{ path = "{name}" }}\n'
        (root / "Cargo.toml").write_text(manifest)
        shutil.copyfile(repo / "Cargo.lock", root / "Cargo.lock")
        env = dict(os.environ, CARGO_TARGET_DIR=str(repo / "target/package-check"))
        command = ["cargo", "test", "--workspace", "--all-features", "--offline", "--locked"]
        if not args.run_tests:
            command.append("--no-run")
        subprocess.run(command, cwd=root, env=env, check=True)
        # Installation resolves the local patches for versions not on crates.io
        # yet; it never uploads or modifies the user's normal Cargo bin directory.
        for name in ("dlep", "dlep-router", "dlep-modem"):
            # Adapt only unpublished sources to the extracted local patches;
            # keep the verified third-party resolution for installation too.
            shutil.copyfile(root / "Cargo.lock", root / f"{name}-{version}" / "Cargo.lock")
            subprocess.run(["cargo", "install", "--path", str(root / f"{name}-{version}"),
                            "--root", str(install), "--offline", "--locked", "--force"], cwd=root, env=env, check=True)
        for name in ("dlep", "dlep-router", "dlep-modem"):
            result = subprocess.check_output([str(install / "bin" / name), "--version"], text=True)
            assert result.strip() == f"{name} {version}", result
        print(f"Verified {len(members)} self-contained archives; installed dlep, dlep-router and dlep-modem {version} into {install}")


if __name__ == "__main__":
    main()
