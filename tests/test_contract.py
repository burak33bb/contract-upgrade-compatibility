import ast
import importlib.util
import sys
import unittest
from pathlib import Path
from types import ModuleType


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "contracts" / "contract_upgrade_compatibility.py"


def _load_contract_module():
    class DynArray(list):
        @classmethod
        def __class_getitem__(cls, _item):
            return cls

    def identity_decorator(function):
        return function

    class Public:
        write = staticmethod(identity_decorator)
        view = staticmethod(identity_decorator)

    fake = ModuleType("genlayer")
    fake.DynArray = DynArray
    fake.gl = type("GL", (), {"Contract": object, "public": Public()})
    sys.modules["genlayer"] = fake
    spec = importlib.util.spec_from_file_location("upgrade_contract_under_test", CONTRACT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BASELINE = '''
from genlayer import *
class ExampleVault(gl.Contract):
    owner: str
    total: int

    @gl.public.view
    def get_total(self) -> int:
        return self.total

    @gl.public.write
    def deposit(self, amount: int) -> None:
        self.total += amount
'''


class UpgradeCompatibilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contract = _load_contract_module()
        cls.source = CONTRACT.read_text(encoding="utf-8")

    def test_python_syntax_and_consensus_path(self):
        ast.parse(self.source)
        self.assertIn("gl.nondet.web.get", self.source)
        self.assertIn("gl.nondet.exec_prompt", self.source)
        self.assertIn("gl.vm.run_nondet_unsafe", self.source)
        self.assertIn("leader_result.calldata", self.source)
        self.assertIn("self.reports.append", self.source)

    def test_extracts_contract_storage_and_public_signatures(self):
        interface = self.contract._extract_interface(BASELINE)
        self.assertEqual(interface["contract_class"], "ExampleVault")
        self.assertEqual(interface["storage_order"], ["owner", "total"])
        self.assertEqual(set(interface["public_methods"]), {"get_total", "deposit"})

    def test_flags_removed_storage_and_changed_public_signature(self):
        candidate = BASELINE.replace("    owner: str\n", "").replace(
            "def deposit(self, amount: int)", "def deposit(self, amount: str)"
        )
        diff = self.contract._compare_interfaces(
            self.contract._extract_interface(BASELINE),
            self.contract._extract_interface(candidate),
        )
        self.assertEqual(diff["removed_storage_fields"], ["owner"])
        self.assertEqual(diff["changed_public_methods"], ["deposit"])
        self.assertEqual(
            self.contract._aggregate_status(diff, "LOW"), self.contract.BREAKING_RISK
        )

    def test_storage_order_change_is_conservative(self):
        candidate = BASELINE.replace("    owner: str\n    total: int", "    total: int\n    owner: str")
        diff = self.contract._compare_interfaces(
            self.contract._extract_interface(BASELINE),
            self.contract._extract_interface(candidate),
        )
        self.assertTrue(diff["storage_order_changed"])
        self.assertEqual(
            self.contract._aggregate_status(diff, "LOW"), self.contract.BREAKING_RISK
        )

    def test_additions_and_semantic_uncertainty_require_review(self):
        candidate = BASELINE.replace("    total: int", "    total: int\n    paused: bool")
        diff = self.contract._compare_interfaces(
            self.contract._extract_interface(BASELINE),
            self.contract._extract_interface(candidate),
        )
        self.assertEqual(
            self.contract._aggregate_status(diff, "LOW"), self.contract.REVIEW_REQUIRED
        )
        unchanged = self.contract._compare_interfaces(
            self.contract._extract_interface(BASELINE),
            self.contract._extract_interface(BASELINE),
        )
        self.assertEqual(
            self.contract._aggregate_status(unchanged, "UNRESOLVED"),
            self.contract.REVIEW_REQUIRED,
        )

    def test_no_breaking_change_is_not_reported_as_safe(self):
        unchanged = self.contract._compare_interfaces(
            self.contract._extract_interface(BASELINE),
            self.contract._extract_interface(BASELINE),
        )
        status = self.contract._aggregate_status(unchanged, "LOW")
        self.assertEqual(status, "NO_BREAKING_CHANGE_IDENTIFIED")
        self.assertNotEqual(status, "SAFE")

    def test_source_urls_must_be_public_raw_github(self):
        validate = self.contract._validate_source_url
        commit = "a" * 40
        self.assertEqual(
            validate(f"https://raw.githubusercontent.com/acme/vault/{commit}/contracts/vault.py"),
            f"https://raw.githubusercontent.com/acme/vault/{commit}/contracts/vault.py",
        )
        for url in [
            "http://raw.githubusercontent.com/acme/vault/" + commit + "/vault.py",
            "https://github.com/acme/vault/blob/main/vault.py",
            "https://raw.githubusercontent.com.evil.invalid/a/b/c.py",
            "https://raw.githubusercontent.com/acme/vault/main/contracts/vault.py",
        ]:
            with self.subTest(url=url), self.assertRaises(ValueError):
                validate(url)

    def test_report_validators_reject_extra_semantic_fields(self):
        validate = self.contract._validate_semantic_assessment
        good = {"semantic_risk": "LOW", "findings": ["No material behavior change identified."], "summary": "Reviewed."}
        validate(good)
        with self.assertRaises(ValueError):
            validate(dict(good, extra="not allowed"))


if __name__ == "__main__":
    unittest.main()
