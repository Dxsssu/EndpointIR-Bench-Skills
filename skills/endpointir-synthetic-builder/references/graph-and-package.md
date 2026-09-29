# 合成图与输出契约

## 目录

```text
benchmark/synthetic-<id>/
  attack_graph.json
  run.sh
  backgrounds.json
  qa.json
  README.md
  image.tar                 # 仅实际生成后保存；也可在 README 记录外部位置
  artifacts/
    verify.py
    tools.py                # 本 Skill 的 scripts/benchmark_tools.py
    payloads/               # 自带运行附件，按需
    results/                # 实际运行后报告，按需
```

攻击图只提供 JSON，不输出 Mermaid/SVG。根目录唯一脚本为 run.sh，其他脚本全部在 artifacts 下，不新增伪造的来源文件。所有路径以场景根目录为基准。README 标注 `Package-Revision: 1`，修改行为或题目含义后递增；纯路径整理不要求重新执行。

## 图结构

沿用 EndpointIR 的 case_id、source、scope、platform、nodes、edges、implementation、evaluation 等结构，新增 synthetic/designed 语义，不能将自主设计标为来源报告或已观测攻击。

```json
{
  "schema_version": "1.1",
  "case_id": "synthetic-example-linux",
  "title": "合成业务任务调查场景",
  "source": {"kind": "synthetic", "basis": "agent_internal_attack_knowledge"},
  "status": "generated",
  "scope": "明确描述本次行为范围、假定起点和未模拟部分",
  "platform": "linux",
  "target_platform": "linux",
  "attack_reference": {
    "source": "model_knowledge",
    "version": "unspecified",
    "verification_status": "knowledge_based"
  },
  "design": {
    "objective": "本场景需要完成的有限目标",
    "chain_family": "业务作业处理",
    "environment": "具备 Bash/Python 的隔离 Linux 容器",
    "seed": 42
  },
  "initial_conditions": ["测试文件由准备阶段生成，不计入攻击步骤"],
  "nodes": [],
  "edges": [],
  "edge_semantics": {
    "designed_dependency": "为目标设计的输入输出或执行前置依赖",
    "designed_order": "执行安排中的先后，不自动构成因果关系"
  },
  "execution_status": {"scripts_generated": true, "attack_executed": false, "host_evidence_collected": false},
  "evaluation": {"status": "draft", "qa_checks": []}
}
```

`version: unspecified` 表示没有外部核对过的 ATT&CK 版本，并非官方版本名。source 不填编造的 URL、报告名或引用。置信度基于模型记忆，不能称为官方认证或实际观测。

## 节点

```json
{
  "id": "N01",
  "operation": "执行合成业务处理脚本",
  "source_status": "designed",
  "design_basis": "为后续收集阶段建立真实进程和文件处理关系",
  "attack_techniques": [{"id": "T1059.004", "name": "Unix Shell"}],
  "tactics": [{"id": "TA0002", "name": "Execution", "basis": "通过 shell 执行受控程序"}],
  "mapping_confidence": "high",
  "preconditions": ["自带的良性脚本已可用"],
  "inputs": ["合成业务配置"],
  "outputs": ["后续步骤消费的处理产物"],
  "expected_evidence": [{"description": "实际执行记录及处理产物", "availability_condition": "实际进程/服务日志可保留", "validation_status": "not_executed"}],
  "unknowns": [],
  "implementation": {
    "mode": "native",
    "operation": "通过 shell 运行自带的有限业务处理程序",
    "attack_techniques": [{"id": "T1059.004", "name": "Unix Shell"}],
    "entrypoint": "run.sh:step_N01",
    "depends_on": [],
    "evidence_checks": ["E01"]
  }
}
```

- 节点 ID 唯一；source_status 始终 designed，执行是否成功由 execution_status 与 verification 表示。
- mapping_confidence 为 high/medium/low。低置信度不填技术 ID，attack_techniques 为空并在 unknowns 说明；有疑问时不要硬填子技术。
- tactics 描述本节点实际角色，每项带语义依据。未知可空；多 tactic 不能变成多个操作。Linux 不支持的标签不要作为实际实现映射。
- implementation.mode 为 native/equivalent/omitted。native 表示机制直接实现，仍是合成场景。equivalent 必须有 reason、preserved_semantics、changed_semantics；omitted 必须有 reason，不出已发生的事实题。
- 设计意图在外层，实际 Linux 机制在 implementation，替代时重新映射技术。不能用外层意图计算实测覆盖。
- 每个可执行节点提供实际函数入口、显式 depends_on、至少一个独立 evidence_checks ID。实际代码显式调用，不 eval 图。

## 边与 QA 关联

```json
{
  "source": "N01",
  "target": "N02",
  "kind": "designed_dependency",
  "basis": "N02 消费 N01 生成的配置，配置不存在则不能执行"
}
```

两类边都是自主设计，没有 source_refs。依赖与安排不能产生环，只有 designed_dependency 用作明确执行前提；implementation.depends_on 与依赖边一致。

QA 的内部关联仅放在 evaluation：

```json
{
  "status": "draft",
  "qa_checks": [
    {"question": "哪个脚本被实际执行？", "node_ids": ["N01"], "verifier_id": "E01"}
  ]
}
```

question 与 qa.json 完全一致，按问题文本关联，不按数组顺序。详细 QA、背景和报告结构见 [qa-and-backgrounds.md](qa-and-backgrounds.md)。

## 验证

`artifacts/tools.py validate <场景目录>` 验证图结构、合成来源声明、执行依赖、脚本路径、QA 格式和代码语法，不运行场景，也不能凭语法验证 ATT&CK 知识正确性。

独立 verifier 必须读取端点证据。工具 finalize 只接收有实际执行依据的报告，填入 answer、背景运行值和图的 verification。不能为通过工具编造报告。执行前 expected_evidence 是设计预期，实际观测保留在报告中。
