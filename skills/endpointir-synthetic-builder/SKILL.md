---
name: endpointir-synthetic-builder
description: "不依赖报告、数据集或外部 ATT&CK 数据，基于 Agent 内置知识自主设计多步 Linux 终端溯源 Benchmark，生成攻击图 JSON、自包含脚本、L1–L3 背景与三字段隐藏 QA。用于从零合成场景、扩大 ATT&CK 行为覆盖和批量设计互补攻击链；给定报告的忠实转换使用 endpointir-benchmark-builder。"
---

# EndpointIR Synthetic Builder

自主构造有因果关系、可执行、可留下调查证据的合成场景。所有事件均标明 synthetic，不冒充真实攻击报告。最终测评仍只有调查环境镜像、L1–L3 背景、隐藏 QA；图和脚本是构建材料。


配套校验与定稿工具需要 Python 3.10+ 和 Bash，仅使用 Python 标准库；可在 macOS/Linux 上生成和校验，场景行为只在 Linux 实验环境执行。
## 输入与默认范围

- 不要求用户提供任何报告、样本、Playbook 或 ATT&CK 数据，不下载或检索这些资料。使用自己的 ATT&CK 知识设计程序，合成业务文件、测试账户和本地服务由附件生成。
- 可以检查当前 Linux 能力和已有 benchmark 的设计摘要以避免重复；这些是环境/去重信息，不是必须输入。没有旧场景也能独立工作。
- 输出到当前项目 `benchmark/synthetic-<scenario-id>/`，不覆盖已存在场景。未指定数量时先生成一个连贯的多步场景；只有用户要求批量时才构建场景组。
- 默认 Linux、Bash、Python 3.10+ 标准库，优先使用容器可完成的行为；需要 systemd、cron、audit 或多主机时明确声明环境条件，不能假定普通容器具备这些能力。
- 生成请求只生成与静态检查。用户明确要求在已指定的隔离 Linux 环境运行时，按既有授权执行、验证并保存可恢复镜像。

## 工作流程

1. 阅读 [design-and-coverage.md](references/design-and-coverage.md)，先选择业务环境、攻击目标、起点和行为链，再选择技术标签。默认尝试设计 10–16 个有意义的操作，涉及至少 5 类 tactic；这是设计目标，环境不支持时保留连贯性并报告缺口，不用重复命令凑数。
2. 阅读 [graph-and-package.md](references/graph-and-package.md)，先写 `attack_graph.json`。明确输入输出、前置条件、执行依赖、ATT&CK 知识置信度和每步所需证据。只输出 JSON 图。
3. 阅读 [linux-runtime.md](references/linux-runtime.md)，生成根目录唯一脚本 `run.sh`，其余脚本、载荷和验证附件全部放在 `artifacts/`。只有真实执行可观察的操作才能进入执行链；平台不支持的机制写明 omitted 或修改设计。
4. 阅读 [qa-and-backgrounds.md](references/qa-and-backgrounds.md)，设计原子事实问题及语义判定规则。`qa.json` 每项只有 question、answer、match_rule；执行前 answer 为 null，执行后根据独立验证结果定稿。`backgrounds.json` 只有 L1/L2/L3 正文。
5. 将本 Skill 的 `scripts/benchmark_tools.py` 复制为 `artifacts/tools.py`，运行结构检查和无副作用的 plan。它不依赖其他 Skill、不下载数据，也不会替你执行场景。

```bash
python3 benchmark/synthetic-<id>/artifacts/tools.py validate benchmark/synthetic-<id>
bash benchmark/synthetic-<id>/run.sh plan
```

用户要求执行时，先 check，再 execute、独立 verify。验证报告存放在评估端 `artifacts/results/`。基于报告 finalize 后，保存镜像并从恢复的镜像再次验证；缺失必要证据不能标为成功。

```bash
python3 artifacts/tools.py finalize . --report artifacts/results/verification.json
python3 artifacts/tools.py validate . --require-verified
```

## 输出与覆盖结论

- README 简述场景、运行依赖、替代差异、镜像保存/恢复方法和覆盖情况，不另生成大量清单文件。
- 分别报告设计涉及、脚本实现、实测有证据支持的技术。仅基于内置知识的映射始终标为 knowledge_based，不能写成已核对官方版本或宣称“完整覆盖 ATT&CK”。
- 同一 ID 重复执行只算一个技术；父技术与其子技术的关系单独解释，子技术数量和父技术族数量分开。跨场景统计并集，不累计重复项。不能用多个 tactic 标签扩大一个动作的贡献。
- 被测 Agent 只得到恢复的环境和所选等级背景，输出自由调查报告。图、QA、验证器、构建脚本和验证结果留在评估端。调查镜像保留自然业务产物及日志，移除构建/评分材料。
- 汇报生成、Linux 实测、镜像恢复验证分别处于什么状态。创建 Skill 本身不代表已经生成或运行场景，也不代表评测过调查 Agent。
