#!/usr/bin/env python3
"""Contract tests with inert, temporary fixtures; never run attack behavior."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

TOOLS = Path(__file__).with_name("benchmark_tools.py")
spec = importlib.util.spec_from_file_location("benchmark_tools", TOOLS)
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)


def fixture(root):
    (root / "artifacts").mkdir(exist_ok=True)
    graph = {
        "schema_version": "1.1", "case_id": "fixture-linux", "title": "测试夹具",
        "source": {"kind": "report", "normalized_file": "source.md"},
        "scope": "仅测试数据契约", "platform": "linux", "target_platform": "linux",
        "attack_reference": {"source": "fixture", "version": "test-only"},
        "status": "generated", "initial_conditions": [],
        "nodes": [], "edges": [],
        "execution_status": {"scripts_generated": True, "attack_executed": False,
                             "host_evidence_collected": False}}
    for n in (1, 2):
        graph["nodes"].append({
            "id": f"N0{n}", "operation": f"测试行为 {n}", "source_status": "reported",
            "source_refs": [{"file": "source.md", "line_start": n, "quote": "测试引用"}],
            "attack_techniques": [{"id": "T1105", "name": "Ingress Tool Transfer"}],
            "implementation": {"mode": "native", "operation": "测试行为",
                "attack_techniques": [{"id": "T1105", "name": "Ingress Tool Transfer"}],
                "entrypoint": f"run.sh:step_N0{n}", "depends_on": ["N01"] if n == 2 else [],
                "evidence_checks": [f"E0{n}"]}})
    graph["edges"] = [{"source": "N01", "target": "N02", "kind": "inferred_dependency",
                       "basis": "测试关系", "source_refs": [{"file": "source.md"}]}]
    graph["evaluation"] = {"status": "draft", "qa_checks": [
        {"question": f"问题{n}？", "node_ids": [f"N0{n}"], "verifier_id": f"E0{n}"}
        for n in (1, 2)]}
    qa = [{"question": f"问题{n}？", "answer": None, "match_rule": "对象正确"} for n in (1, 2)]
    bg = {name: "调查主机 {{hostname}}" for name in ["L1", "L2", "L3"]}
    for name, obj in [("attack_graph.json", graph), ("qa.json", qa), ("backgrounds.json", bg)]:
        (root / name).write_text(json.dumps(obj, ensure_ascii=False), encoding="utf-8")
    (root / "run.sh").write_text('#!/usr/bin/env bash\nstep_N01() { :; }\nstep_N02() { :; }\nexit 99\n', encoding="utf-8")
    # Importing or executing this verifier would fail: validation must only parse.
    (root / "artifacts/verify.py").write_text('raise RuntimeError("Must not execute verifier")\n', encoding="utf-8")
    (root / "artifacts/tools.py").write_text(TOOLS.read_text(encoding="utf-8"), encoding="utf-8")
    (root / "README.md").write_text('Package-Revision: 1\n仅测试，不是可运行场景。\n', encoding="utf-8")
    report = {"schema_version": "1.0", "scenario_id": "fixture-linux", "package_revision": "1",
              "run_id": "test-run", "verified_at": "2026-09-29T12:00:00+08:00",
              "verification_scope": "live_endpoint", "passed": True,
              "bindings": {"path": "/tmp/合成数据", "hostname": "测试主机"},
              "checks": [{"id": f"E0{n}", "passed": True, "observed_answer": "仅测试：目标 /tmp/合成数据",
                          "evidence": [{"location": "/tmp/合成数据", "observation": "仅测试观测"}]}
                         for n in (1, 2)]}
    return graph, qa, bg, report


class Contracts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="endpointir-skill-test-")
        self.root = Path(self.temp.name)
        self.graph, self.qa, self.bg, self.report = fixture(self.root)

    def tearDown(self):
        self.temp.cleanup()

    def write(self, name, data):
        (self.root / name).write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")

    def final(self, report=None):
        self.write("verification.json", self.report if report is None else report)
        tool.finalize(self.root, self.root / "verification.json")

    def test_draft_does_not_execute_code(self):
        tool.validate(self.root)
        with self.assertRaises(tool.ContractError):
            tool.validate(self.root, True)

    def test_finalize_binds_actual_values_and_keeps_question_set(self):
        self.final()
        graph, qa, bg, _ = tool.validate(self.root, True)
        self.assertEqual([q["question"] for q in qa], ["问题1？", "问题2？"])
        self.assertEqual(qa[0]["answer"], "仅测试：目标 /tmp/合成数据")
        self.assertEqual(bg["L1"], "调查主机 测试主机")
        self.assertEqual(graph["verification"]["verification_scope"], "live_endpoint")

    def test_failed_missing_empty_and_stale_report_leave_files_intact(self):
        variants = []
        for change in [lambda r: r.update(passed=False),
                       lambda r: r.update(package_revision="other"),
                       lambda r: r.update(scenario_id="other"),
                       lambda r: r["checks"].pop(),
                       lambda r: r["checks"][0].update(evidence=[]),
                       lambda r: r["checks"][0].update(passed=False),
                       lambda r: r["checks"].append(copy.deepcopy(r["checks"][0])),
                       lambda r: r["bindings"].pop("hostname"),
                       lambda r: r.update(verified_at="no-time"),
                       lambda r: r.update(verification_scope="unknown")]:
            r = copy.deepcopy(self.report)
            change(r)
            variants.append(r)
        before = {n: (self.root / n).read_bytes() for n in
                  ("qa.json", "backgrounds.json", "attack_graph.json")}
        for variant in variants:
            with self.subTest(report=variant):
                with self.assertRaises(tool.ContractError):
                    self.final(variant)
                self.assertEqual(before, {n: (self.root / n).read_bytes() for n in before})

    def test_duplicate_nodes_cycle_and_omitted_qa_rejected(self):
        for change in [lambda g: g["nodes"].append(copy.deepcopy(g["nodes"][0])),
                       lambda g: g["nodes"][0]["implementation"].update(depends_on=["N02"]),
                       lambda g: g["nodes"][1]["implementation"].update(mode="omitted", reason="无证据")]:
            g = copy.deepcopy(self.graph)
            change(g)
            self.write("attack_graph.json", g)
            with self.assertRaises(tool.ContractError):
                tool.validate(self.root)

    def test_mismatched_verifier_and_missing_level_rejected(self):
        self.graph["evaluation"]["qa_checks"][0]["verifier_id"] = "E02"
        self.write("attack_graph.json", self.graph)
        with self.assertRaises(tool.ContractError):
            tool.validate(self.root)
        fixture(self.root)
        self.bg.pop("L3")
        self.write("backgrounds.json", self.bg)
        with self.assertRaises(tool.ContractError):
            tool.validate(self.root)

    def test_reordered_questions_keep_evidence_mapping(self):
        self.qa.reverse()
        self.write("qa.json", self.qa)
        self.report["checks"][0]["observed_answer"] = "first fact"
        self.report["checks"][1]["observed_answer"] = "second fact"
        self.final()
        _, qa, _, _ = tool.validate(self.root, True)
        self.assertEqual([q["answer"] for q in qa], ["second fact", "first fact"])

    def test_verified_content_changes_rejected(self):
        self.final()
        qa = tool.load(self.root / "qa.json", list)
        qa[0]["answer"] = "unsupported replacement"
        self.write("qa.json", qa)
        with self.assertRaises(tool.ContractError):
            tool.validate(self.root, True)

    def test_external_symlink_cannot_be_validated_or_overwritten(self):
        with tempfile.TemporaryDirectory() as outside:
            target = Path(outside) / "outside.py"
            target.write_text("pass\n", encoding="utf-8")
            (self.root / "artifacts/verify.py").unlink()
            (self.root / "artifacts/verify.py").symlink_to(target)
            with self.assertRaises(tool.ContractError):
                tool.validate(self.root)
            with self.assertRaises(tool.ContractError):
                tool.replace_files(self.root, {"artifacts/verify.py": "changed"})
            self.assertEqual(target.read_text(), "pass\n")

    def test_output_paths_cannot_escape_package(self):
        with tempfile.TemporaryDirectory() as outside:
            target = Path(outside) / "output.txt"
            target.write_text("original", encoding="utf-8")
            (self.root / "external").symlink_to(outside, target_is_directory=True)
            for name in (str(target), "../escape.txt", "external/output.txt"):
                with self.subTest(name=name):
                    with self.assertRaises(tool.ContractError):
                        tool.replace_files(self.root, {name: "changed"})
            self.assertEqual(target.read_text(), "original")
            self.assertFalse(list(self.root.glob(".endpointir-*")))

    def test_revision_change_rejects_verified_state(self):
        self.final()
        (self.root / "README.md").write_text("Package-Revision: 2\n", encoding="utf-8")
        with self.assertRaises(tool.ContractError):
            tool.validate(self.root, True)

    def test_malformed_placeholder_and_injection_are_literal(self):
        with self.assertRaises(tool.ContractError):
            tool.interpolate("x {{bad", {})
        with self.assertRaises(tool.ContractError):
            tool.interpolate("x }}", {})
        self.assertEqual(tool.interpolate("{{x}}", {"x": "$(touch /no-such-file)"}),
                         "$(touch /no-such-file)")

    def test_root_script_attachments_rejected(self):
        (self.root / "extra.py").write_text("pass\n", encoding="utf-8")
        with self.assertRaises(tool.ContractError):
            tool.validate(self.root)
        (self.root / "extra.py").unlink()
        (self.root / "extra.sh").write_text(":\n", encoding="utf-8")
        with self.assertRaises(tool.ContractError):
            tool.validate(self.root)

    def test_python_syntax_error_rejected_without_import(self):
        (self.root / "artifacts/verify.py").write_text("def broken(:\n", encoding="utf-8")
        with self.assertRaises(SyntaxError):
            tool.validate(self.root)


if __name__ == "__main__":
    unittest.main(verbosity=2)
