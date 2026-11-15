"""Archive verification must not silently skip a test or feature-gated target."""
import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location(
    "release_packages", Path(__file__).with_name("check-release-packages.py"))
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


def package(root):
    return {"name": "dlep-example", "manifest_path": f"{root}/Cargo.toml", "targets": [
        {"name": "example", "kind": ["lib"], "src_path": f"{root}/src/lib.rs"},
        {"name": "regression", "kind": ["test"], "src_path": f"{root}/tests/regression.rs",
         "required-features": ["network"]},
    ]}


class ArchiveInventoryTests(unittest.TestCase):
    def test_relocated_normalized_targets_match(self):
        source, archived = package("/checkout/crates/example"), package("/tmp/example-0.2.0")
        archived["targets"].reverse()
        checker.check_target_inventory(source, archived)

    def test_missing_added_or_changed_targets_fail(self):
        source = package("/checkout/crates/example")
        archived = package("/tmp/example-0.2.0")
        missing = copy.deepcopy(archived)
        missing["targets"].pop()
        extra = copy.deepcopy(archived)
        extra["targets"].append({"name": "stale", "kind": ["test"],
                                 "src_path": "/tmp/example-0.2.0/tests/stale.rs"})
        gated = copy.deepcopy(archived)
        gated["targets"][1]["required-features"] = ["different"]
        relocated = copy.deepcopy(archived)
        relocated["targets"][1]["src_path"] = "/tmp/example-0.2.0/tests/other.rs"
        for candidate in [missing, extra, gated, relocated]:
            with self.subTest(candidate=candidate), self.assertRaises(AssertionError):
                checker.check_target_inventory(source, candidate)


if __name__ == "__main__":
    unittest.main()
