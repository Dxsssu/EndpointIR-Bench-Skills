#!/usr/bin/env python3
"""Portable scenario validation and finalization (Python 3.10+, Bash).

Never executes the scenario or its verifier. A verification report is trusted
operator input: structural checks cannot authenticate real endpoint observations.
"""
from __future__ import annotations

import argparse
import ast
import copy
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path


class ContractError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise ContractError(message)


def nonempty(value):
    return isinstance(value, str) and bool(value.strip())


def load(path, expected_type=dict):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, f"Duplicate JSON key: {key}")
            result[key] = value
        return result
    data = json.loads(path.read_text(encoding="utf-8-sig"), object_pairs_hook=pairs)
    require(isinstance(data, expected_type), f"Unexpected JSON type: {path}")
    return data


def safe_file(root, relative):
    p = Path(relative)
    require(not p.is_absolute() and ".." not in p.parts, f"Unsafe package path: {relative}")
    candidate = root / p
    require(candidate.resolve().is_relative_to(root.resolve()), f"Escaping symlink: {relative}")
    require(candidate.is_file(), f"Missing file: {relative}")
    return candidate


def ids(items, where):
    require(isinstance(items, list), f"{where}: expected list")
    result = {}
    for item in items:
        require(isinstance(item, dict), f"{where}: expected object")
        ident = item.get("id")
        require(isinstance(ident, str) and re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", ident),
                f"{where}: invalid id {ident!r}")
        require(ident not in result, f"{where}: duplicate id {ident}")
        result[ident] = item
    return result


def string_list(value, where, allow_empty=True):
    require(isinstance(value, list), f"{where}: expected list")
    require(all(nonempty(x) for x in value), f"{where}: expected nonempty strings")
    require(len(set(value)) == len(value), f"{where}: duplicate values")
    require(allow_empty or bool(value), f"{where}: empty list")
    return value


def dag(node_ids, edges, where):
    adjacent = {node: [] for node in node_ids}
    degrees = {node: 0 for node in node_ids}
    seen = set()
    for source, target in edges:
        require(source in degrees and target in degrees, f"{where}: unknown endpoint")
        if (source, target) in seen:
            continue
        seen.add((source, target))
        adjacent[source].append(target)
        degrees[target] += 1
    queue = sorted(node for node, degree in degrees.items() if degree == 0)
    order = []
    while queue:
        node = queue.pop(0)
        order.append(node)
        for target in adjacent[node]:
            degrees[target] -= 1
            if degrees[target] == 0:
                queue.append(target)
    require(len(order) == len(node_ids), f"{where}: cycle detected")
    return order


def techniques(items, where):
    require(isinstance(items, list), f"{where}: expected technique list")
    for item in items:
        require(isinstance(item, dict), f"{where}: invalid technique")
        require(re.fullmatch(r"T\d{4}(?:\.\d{3})?", str(item.get("id", ""))),
                f"{where}: invalid ATT&CK ID")
        require(nonempty(item.get("name")), f"{where}: missing ATT&CK name")


def revision(root):
    text = safe_file(root, "README.md").read_text(encoding="utf-8")
    found = re.findall(r"^Package-Revision:\s*([A-Za-z0-9._-]+)\s*$", text, re.M)
    require(len(found) == 1, "README needs exactly one Package-Revision: value")
    return found[0]


def content_digest(qa, backgrounds):
    data = json.dumps([qa, backgrounds], ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def validate(root, require_verified=False):
    root = root.resolve()
    required = ["attack_graph.json", "run.sh", "artifacts/verify.py",
                "qa.json", "backgrounds.json", "artifacts/tools.py", "README.md"]
    for name in required:
        safe_file(root, name)
    require(not (root / "attack_graph.mmd").exists(), "Attack graph output must be JSON only")
    require(sorted(p.name for p in root.glob("*.sh")) == ["run.sh"], "Root needs only run.sh")
    require(not list(root.glob("*.py")), "Python attachments belong in artifacts/")
    graph = load(root / "attack_graph.json")
    qa = load(root / "qa.json", list)
    backgrounds = load(root / "backgrounds.json")
    rev = revision(root)
    case = graph.get("case_id")
    require(isinstance(case, str) and re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", case), "Invalid case_id")
    require(graph.get("schema_version") == "1.1", "Graph schema_version must be 1.1")
    require(graph.get("target_platform") == "linux", "Target must be linux")
    require(nonempty(graph.get("scope")) and nonempty(graph.get("platform")), "Missing scope/source platform")
    source = graph.get("source", {})
    require(isinstance(source, dict) and source.get("kind") in
            {"report", "emulation_plan", "sample_observation", "mixed"}, "Invalid source kind")
    ref = graph.get("attack_reference", {})
    require(isinstance(ref, dict) and nonempty(ref.get("source")) and nonempty(ref.get("version")),
            "ATT&CK source/version required")
    nodes = ids(graph.get("nodes"), "nodes")
    require(nodes, "Graph has no nodes")
    dependency_edges, active_checks = [], set()
    active = set()
    for node_id, node in nodes.items():
        require(nonempty(node.get("operation")), f"{node_id}: missing operation")
        require(node.get("source_status") in {"observed", "reported", "inferred", "unknown"},
                f"{node_id}: invalid source_status")
        require(isinstance(node.get("source_refs"), list) and node["source_refs"], f"{node_id}: missing source refs")
        techniques(node.get("attack_techniques"), node_id)
        imp = node.get("implementation")
        require(isinstance(imp, dict), f"{node_id}: missing implementation")
        require(imp.get("mode") in {"native", "equivalent", "omitted"}, f"{node_id}: invalid mode")
        if imp["mode"] == "omitted":
            require(nonempty(imp.get("reason")), f"{node_id}: omission reason required")
            continue
        active.add(node_id)
        require(nonempty(imp.get("operation")), f"{node_id}: actual operation required")
        techniques(imp.get("attack_techniques"), f"{node_id} implementation")
        if not node["attack_techniques"] or not imp["attack_techniques"]:
            require(isinstance(node.get("unknowns"), list) and node["unknowns"], f"{node_id}: explain unmapped technique")
        if imp["mode"] == "equivalent":
            require(nonempty(imp.get("reason")), f"{node_id}: replacement reason required")
            string_list(imp.get("preserved_semantics"), f"{node_id}: preserved_semantics", False)
            string_list(imp.get("changed_semantics"), f"{node_id}: changed_semantics", False)
        entry = imp.get("entrypoint", "")
        require(isinstance(entry, str) and ":" in entry, f"{node_id}: entrypoint must be file:function")
        file, function = entry.split(":", 1)
        require(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", function), f"{node_id}: invalid function name")
        script = safe_file(root, file).read_text(encoding="utf-8")
        require(re.search(r"\b" + re.escape(function) + r"\b", script), f"{node_id}: function not found")
        for dependency in string_list(imp.get("depends_on"), f"{node_id}: depends_on"):
            dependency_edges.append((dependency, node_id))
        active_checks.update(string_list(imp.get("evidence_checks"), f"{node_id}: evidence_checks", False))
    require(active, "No executable behavior")
    require(all(a in active and b in active for a, b in dependency_edges), "Dependency on omitted/unknown node")
    dag(active, dependency_edges, "execution dependencies")
    edges = graph.get("edges")
    require(isinstance(edges, list), "edges must be list")
    graph_edges = []
    for edge in edges:
        require(isinstance(edge, dict), "Invalid edge")
        require(edge.get("kind") in {"reported_execution", "reported_order", "inferred_dependency"}, "Invalid edge kind")
        require(nonempty(edge.get("basis")) and isinstance(edge.get("source_refs"), list)
                and edge["source_refs"], "Edge basis/source required")
        graph_edges.append((edge.get("source"), edge.get("target")))
    dag(nodes, graph_edges, "source graph")
    dag(nodes, graph_edges + dependency_edges, "source and implementation ordering")
    require(qa, "No QA checkpoints")
    evaluation = graph.get("evaluation")
    require(isinstance(evaluation, dict), "Graph needs evaluation metadata")
    links = evaluation.get("qa_checks")
    require(isinstance(links, list) and len(links) == len(qa), "QA/check mapping count differs")
    by_question = {}
    for link in links:
        require(isinstance(link, dict) and nonempty(link.get("question")), "Invalid QA mapping")
        require(link["question"] not in by_question, "Duplicate mapped question")
        by_question[link["question"]] = link
    used_verifiers, questions = set(), set()
    for item in qa:
        require(isinstance(item, dict) and set(item) == {"question", "answer", "match_rule"},
                "Each QA must contain only question, answer, match_rule")
        for field in ("question", "match_rule"):
            require(nonempty(item.get(field)), f"QA: missing {field}")
        question = item["question"]
        require(question not in questions, "Duplicate QA question")
        questions.add(question)
        require(question in by_question, "Question not linked to graph")
        link = by_question[question]
        node_ids = string_list(link.get("node_ids"), "QA mapping: node_ids", False)
        require(set(node_ids) <= active, "QA references omitted/unknown node")
        possible = {x for n in node_ids for x in nodes[n]["implementation"]["evidence_checks"]}
        verifier = link.get("verifier_id")
        require(nonempty(verifier) and verifier in possible, "QA verifier not linked to its nodes")
        require(verifier not in used_verifiers, "Use one independent check per atomic QA")
        used_verifiers.add(verifier)
    state = evaluation.get("status")
    require(state in {"draft", "verified"}, "Invalid evaluation state")
    require(not require_verified or state == "verified", "Runtime verification has not finalized this package")
    require(set(backgrounds) == {"L1", "L2", "L3"}, "Need exactly L1, L2, L3")
    for name, text in backgrounds.items():
        require(nonempty(text), f"{name}: missing background text")
        if state == "verified":
            require("{{" not in text and "}}" not in text, f"{name}: unresolved text")
    if state == "verified":
        stamp = graph.get("verification")
        require(isinstance(stamp, dict), "Missing graph verification record")
        require(stamp.get("package_revision") == rev, "Verified package revision is stale")
        require(evaluation.get("content_sha256") == content_digest(qa, backgrounds),
                "QA/backgrounds changed since finalization")
        for item in qa:
            require(nonempty(item["answer"]) and "{{" not in item["answer"] and "}}" not in item["answer"],
                    "Missing actual answer")
    else:
        require(all(x["answer"] is None for x in qa), "Draft QA must not claim actual answers")
    # Syntax checks do not import Python modules or execute shell commands.
    for path in root.rglob("*.py"):
        safe_file(root, str(path.relative_to(root)))
        ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    env = os.environ.copy()
    env.pop("BASH_ENV", None)
    env.pop("ENV", None)
    for path in root.rglob("*.sh"):
        safe_file(root, str(path.relative_to(root)))
        result = subprocess.run(["bash", "-n", str(path)], capture_output=True, text=True,
                                encoding="utf-8", timeout=20, env=env)
        require(result.returncode == 0, f"Bash syntax error {path.name}: {result.stderr.strip()}")
    return graph, qa, backgrounds, active_checks


def evidence(value, where):
    require(isinstance(value, list) and value, f"{where}: no evidence")
    for item in value:
        require(isinstance(item, dict) and nonempty(item.get("location")) and nonempty(item.get("observation")),
                f"{where}: evidence needs location and observation")


def replace_files(root, updates):
    """Stage everything before replacing; roll back on an ordinary write failure.

    Each rename is atomic; the verification stamp detects interruption between
    files. Keep consumers stopped during finalization (not a multi-file DB).
    """
    staged, previous, replaced = {}, {}, []
    try:
        for name, content in updates.items():
            relative = Path(name)
            require(not relative.is_absolute() and ".." not in relative.parts,
                    f"Unsafe output path: {name}")
            target = root / relative
            require(target.resolve().is_relative_to(root.resolve()),
                    f"Output escapes package through symlink: {name}")
            require(not target.is_symlink(), f"Refusing symlink output: {name}")
            previous[name] = target.read_bytes() if target.exists() else None
            with tempfile.NamedTemporaryFile(dir=root, prefix=".endpointir-", delete=False) as f:
                staged[name] = Path(f.name)
                f.write(content.encode("utf-8"))
                f.flush()
                os.fsync(f.fileno())
        for name, path in staged.items():
            os.replace(path, root / name)
            replaced.append(name)
    except Exception:
        for name in reversed(replaced):
            target = root / name
            if previous[name] is None:
                target.unlink(missing_ok=True)
            else:
                target.write_bytes(previous[name])
        raise
    finally:
        for path in staged.values():
            path.unlink(missing_ok=True)


def interpolate(template, bindings):
    pattern = re.compile(r"\{\{([A-Za-z_][A-Za-z0-9_]*)\}\}")
    def substitute(match):
        key = match.group(1)
        require(key in bindings, f"Missing runtime binding: {key}")
        value = bindings[key]
        require(type(value) in {str, int, float}, f"Invalid runtime binding: {key}")
        require(str(value).strip(), f"Empty runtime binding: {key}")
        return str(value)
    result = pattern.sub(substitute, template)
    require("{{" not in result and "}}" not in result, "Unresolved/malformed runtime placeholder")
    return result


def finalize(root, report_path):
    graph, qa, backgrounds, active_checks = validate(root)
    graph, qa, backgrounds = copy.deepcopy((graph, qa, backgrounds))
    report = load(report_path)
    require(report.get("schema_version") == "1.0", "Invalid verification schema")
    require(report.get("scenario_id") == graph["case_id"], "Verification scenario mismatch")
    require(report.get("package_revision") == revision(root), "Verification revision mismatch")
    require(report.get("passed") is True, "Verification did not pass")
    if graph["evaluation"]["status"] == "verified":
        require(report.get("run_id") == graph["verification"].get("run_id"),
                "New run requires draft answers and refreshed background bindings")
    for field in ("run_id", "verified_at"):
        require(nonempty(report.get(field)), f"Missing {field}")
    try:
        timestamp = datetime.fromisoformat(report["verified_at"].replace("Z", "+00:00"))
        require(timestamp.tzinfo is not None, "verified_at must include timezone")
    except ValueError as exc:
        raise ContractError("Invalid verified_at timestamp") from exc
    require(report.get("verification_scope") in {"live_endpoint", "restored_image"}, "Invalid verification scope")
    checks = ids(report.get("checks"), "verification checks")
    require(active_checks <= set(checks), "Verification missing graph evidence checks")
    for check_id, check in checks.items():
        require(check.get("passed") is True, f"{check_id}: failed verification")
        evidence(check.get("evidence"), check_id)
    bindings = report.get("bindings")
    require(isinstance(bindings, dict), "Missing runtime bindings")
    links = {x["question"]: x for x in graph["evaluation"]["qa_checks"]}
    for item in qa:
        check = checks[links[item["question"]]["verifier_id"]]
        answer = check.get("observed_answer")
        require(nonempty(answer) and "{{" not in answer and "}}" not in answer, "Actual answer missing")
        item["answer"] = answer
    backgrounds = {name: interpolate(text, bindings) for name, text in backgrounds.items()}
    graph["verification"] = {key: report[key] for key in
                             ("package_revision", "run_id", "verified_at", "verification_scope")}
    graph["evaluation"]["status"] = "verified"
    graph["evaluation"]["content_sha256"] = content_digest(qa, backgrounds)
    graph["status"] = "runtime_verified"
    graph["execution_status"] = {"scripts_generated": True, "attack_executed": True,
                                 "host_evidence_collected": True}
    updates = {name: json.dumps(value, ensure_ascii=False, indent=2) + "\n"
               for name, value in [("attack_graph.json", graph), ("qa.json", qa),
                                    ("backgrounds.json", backgrounds)]}
    replace_files(root, updates)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["validate", "finalize"])
    parser.add_argument("package", type=Path)
    parser.add_argument("--require-verified", action="store_true")
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    root = args.package.resolve()
    try:
        require(root.is_dir(), "Package directory missing")
        if args.command == "validate":
            graph, qa, _, _ = validate(root, args.require_verified)
            print(json.dumps({"valid": True, "scenario_id": graph["case_id"],
                              "qa_status": graph["evaluation"]["status"], "scenario_executed_by_this_tool": False}, ensure_ascii=False))
        else:
            require(args.report is not None, "finalize needs --report")
            finalize(root, args.report)
            validate(root, True)
            print("Finalized QA/backgrounds from the supplied verification report; no scenario executed.")
    except (ContractError, OSError, ValueError, TypeError, KeyError, SyntaxError, subprocess.SubprocessError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
