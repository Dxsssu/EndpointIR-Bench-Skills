# EndpointIR Skills

用于构建 Linux 终端溯源 Agent Benchmark 的两个独立 Codex Skill。

| Skill | 输入与用途 |
|---|---|
| [endpointir-benchmark-builder](skills/endpointir-benchmark-builder/SKILL.md) | 将用户提供的溯源报告、攻击仿真计划或样本行为记录转成可调查场景 |
| [endpointir-synthetic-builder](skills/endpointir-synthetic-builder/SKILL.md) | 从 Agent 内置 ATT&CK 知识设计多步合成场景，无需外部数据集 |

两个 Skill 可以分别安装，不互相依赖，也不依赖原始 EndpointIR 项目目录。

## 安装

下载本仓库并进入仓库根目录，将需要的 Skill 目录复制到 Codex 的 skills 目录。例如默认位置：

```bash
mkdir -p "${CODEX_HOME:-$HOME/.codex}/skills"
cp -R skills/endpointir-benchmark-builder "${CODEX_HOME:-$HOME/.codex}/skills/"
cp -R skills/endpointir-synthetic-builder "${CODEX_HOME:-$HOME/.codex}/skills/"
```

若已安装同名 Skill，先备份或比较已有修改，再更新目录；避免递归复制留下旧版本附件。

示例请求：

> 使用 $endpointir-benchmark-builder 将我提供的报告转成一个 Linux 溯源场景。

> 使用 $endpointir-synthetic-builder 自主生成 3 个互补的 Linux 溯源场景，扩大 ATT&CK 多步行为覆盖。

## 依赖与执行边界

- 校验和定稿工具使用 Python 3.10+ 标准库以及 Bash，无 pip 依赖。
- macOS/Linux 可生成和静态校验；场景行为只在隔离 Linux 靶机执行。Windows 控制端请使用带 Bash/Python 的 WSL 环境。
- Docker/虚拟机平台并非 Skill 的安装依赖；只有运行和保存调查环境时才需要选定平台。
- 第一种 Skill 需要用户材料，ATT&CK 映射可使用本地元数据或按需官方资料；第二种使用内置知识，明确记录 knowledge_based，不冒充已核对的官方版本。
- 仿真使用受控程序和合成数据。环境准备、真实执行、独立验证和镜像恢复是不同阶段；静态检查不证明行为真实发生。

## 输出格式

```text
benchmark/<scenario-id>/
  attack_graph.json
  run.sh
  backgrounds.json
  qa.json
  README.md
  image.tar                # 实际生成后保存，或记录外部镜像位置
  artifacts/               # 验证器、工具、载荷、来源副本及实际运行结果
```

攻击图只提供 JSON；根目录只有一个脚本 run.sh。背景只含 L1/L2/L3 正文；QA 每项只含 question、answer、match_rule。QA、图和验证结果保留在评估侧，不提供给被测 Agent。

## 开发验证

从仓库根目录执行，测试只使用临时惰性夹具，不执行攻击仿真：

```bash
python3 -B skills/endpointir-benchmark-builder/scripts/test_benchmark_tools.py
python3 -B skills/endpointir-synthetic-builder/scripts/test_benchmark_tools.py
```

CI 配置在 Ubuntu/macOS 上使用 Python 3.10 和 3.12 运行同一套测试。两个 Skill 的工具副本各自自包含，共用逻辑修改应同步修复并分别运行测试。

本次发布前检查（2026-09-29）：移除了原项目的专用路径提示，补齐最低版本说明及写入路径越界检查；macOS/Python 3.12 和隔离 Debian/Python 3.12 均通过 27 项测试。测试在含中文与空格的新路径中运行。Python 3.10 已通过语法兼容检查，完整运行测试留给 CI，尚未声称执行过该版本。相对引用与发布文件清单检查通过，打包排除了 Python 缓存。

## 发布内容与许可

本仓库只包含 Skill 指令、规格及校验工具，不包含原始报告、恶意样本、用户数据、调查镜像或实测证据。`.gitignore` 排除运行产物和本地缓存。

发布者尚未指定开源许可证，因此本包未擅自添加 LICENSE。正式开放复用前请选择适用的许可证；未来加入第三方代码、报告或数据时，应分别保留其许可和来源说明。
