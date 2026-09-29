# 攻击图与场景文件契约

## 每个场景的目录

```text
benchmark/<scenario-id>/
  attack_graph.json      # 攻击图只保留 JSON
  run.sh                 # 场景根目录唯一脚本，加载 artifacts 下附件
  backgrounds.json       # L1/L2/L3 正文
  qa.json                # 每项仅 question、answer、match_rule
  README.md              # 运行及镜像使用说明
  image.tar              # 实际生成后保存，或在 README 记录外部位置
  artifacts/
    verify.py            # 独立证据验证器
    tools.py             # 校验及执行后定稿工具
    payloads/            # 按需提供的运行附件
    source/              # 按需保存的来源副本
    results/             # 实际验证报告与运行记录
```

调查镜像可保存在同目录或外部镜像存储，README 写明实际位置；没有生成时明确“待用户在 Linux 实验环境保存”。不要创建假的 image 文件或凭空写入镜像路径。评估端保留完整构建目录；Agent 只接收镜像与当次等级的正文字符串，不能直接读取 `backgrounds.json`（里面还有其他等级）和 `qa.json`。

文件为 UTF-8，JSON 用 `ensure_ascii=False`。场景 ID 使用稳定的小写字母、数字和连字符。来源 ID 与场景 ID 分开，跨来源同一事件的派生场景保留 parent/source 信息。不能通过改名把同源变体宣称为独立事件。

脚本均以 `run.sh` 所在目录定位 `artifacts/`，不依赖调用者当前目录。工具的 package 参数仍指场景根目录，例如 `python3 artifacts/tools.py validate .`。移动来源副本时同步修改图内引用。仅迁移路径且不改变行为和证据条件时可保留原修订版及实测结果。

## 图顶层

图顶层使用 `case_id/source/scope/platform/initial_conditions/nodes/edges/edge_semantics/execution_status`，新增实现字段。以下是结构，不是已执行的数据：

```json
{
  "schema_version": "1.1",
  "case_id": "example-linux",
  "title": "场景名称",
  "source": {
    "kind": "report",
    "normalized_file": "artifacts/source/report.md",
    "url": "",
    "manifest_id": "source-id"
  },
  "status": "generated",
  "scope": "已选择的连贯行为范围",
  "platform": "原始材料的平台",
  "target_platform": "linux",
  "attack_reference": {"source": "atomic_red_team", "version": "实际查到的提交或版本"},
  "initial_conditions": [],
  "nodes": [],
  "edges": [],
  "edge_semantics": {
    "reported_execution": "来源明确的执行或载荷依赖",
    "reported_order": "来源叙述顺序，不自动构成因果依赖",
    "inferred_dependency": "为构建而推断的依赖"
  },
  "excluded_reported_actions": [],
  "execution_status": {
    "scripts_generated": true,
    "attack_executed": false,
    "host_evidence_collected": false
  }
}
```

`source.kind` 为 `report/emulation_plan/sample_observation/mixed`。多个来源用 `source.materials` 数组追加，不丢失出处。日期、版本、运行状态必须真实；仅提供源文件的事实不能标为已实测。

QA 与背景使用 [qa-and-backgrounds.md](qa-and-backgrounds.md) 的简化格式；构建侧关联保存在图顶层 `evaluation`，验证记录保存在 `verification`。

## 节点

```json
{
  "id": "N01",
  "operation": "原始来源中的具体行为",
  "attack_techniques": [
    {"id": "T1105", "name": "Ingress Tool Transfer", "mapping_basis": "已核对的来源及行为含义"}
  ],
  "source_status": "reported",
  "source_refs": [{"file": "artifacts/source/report.md", "line_start": 12, "line_end": 15, "quote": "真实原文"}],
  "preconditions": [],
  "inputs": [],
  "outputs": [],
  "expected_evidence": [
    {"description": "文件或事件记录", "availability_condition": "需要的采集设置", "validation_status": "not_executed"}
  ],
  "unknowns": [],
  "executor": "bash",
  "atomic_test_id": null,
  "implementation": {
    "mode": "equivalent",
    "operation": "Linux 上实际实现的行为",
    "attack_techniques": [{"id": "T1105", "name": "Ingress Tool Transfer"}],
    "entrypoint": "run.sh:step_N01",
    "depends_on": [],
    "reason": "原始下载载荷已不可获取",
    "preserved_semantics": ["网络获取脚本并落盘"],
    "changed_semantics": ["使用隔离接收端和本地编写的脚本"],
    "evidence_checks": ["E01"]
  }
}
```

- `id` 采用 `N01` 等唯一字母数字标识。`operation` 为单项可解释行为，不把整条攻击链压成一个节点。
- `source_status` 为 `observed/reported/inferred/unknown`；observed 需有实际样本观测/执行证据，不是 LLM 自称观察过。
- `source_refs` 可用相对文件+行号、PDF 页码+原句、URL+章节，或样本观测记录 ID。推断节点仍给出推断依据。
- `implementation.mode` 为 `native/equivalent/omitted`。执行节点要有实现入口、观测项；省略节点要有原因，不能生成其已发生的 QA。
- 每个实现的 `depends_on` 表示真正的执行前提，与报告叙述顺序分离。所有执行依赖构成 DAG。重复行为用独立事件节点或有界循环说明，不制造自环。
- `attack_techniques` 保留源平台映射；`implementation.attack_techniques` 核对 Linux 对应技术。模拟 Windows Run Key 为 Linux 用户定时任务时，不得沿用注册表技术作为 Linux 实测标签。
- ATT&CK 映射不能确定时保留空列表并写入 `unknowns`，不能填造假的 ID。有效映射以官方技术元数据或本地已核实资料为准。
- JSON 中的命令描述不是执行源。运行器采用已审阅的显式代码，不通过 `eval` 执行图或来源文本。

## 边语义

每条边包含 `source/target/kind/basis/source_refs`。kind 使用 `reported_execution/reported_order/inferred_dependency`。其他项目已有语义先显式记录并扩展工具，不能静默折叠成因果关系。

只交付 `attack_graph.json`，不生成 `.mmd`、SVG 或其他派生图。分支和各类边保留在 JSON 中；孤立分支只表示关系未知，不声称并行，多个入边不自动构成 AND。

## 静态验收

`artifacts/tools.py validate` 检查字段、ID、边与执行依赖 DAG、QA 引用、L1–L3、Python/Bash 语法及草稿/验证状态；不会执行任何场景代码。Agent 另核对 ATT&CK 映射语义、替代的忠实度、是否泄漏答案，以及验证器是否确实读取独立证据。
