# 隐藏 QA 与 L1–L3

## 最终文件格式

`qa.json` 是数组，每项严格只包含三个字段：

```json
[
  {
    "question": "主机获取了哪个脚本，保存在哪里？",
    "answer": "脚本由实际观测到的地址获取，并保存到实际落盘路径。",
    "match_rule": "正确识别传输来源与落盘路径；允许等价措辞。仅指出文件存在不足以确定来源。"
  }
]
```

不写 id、node_ids、expected_answer、verifier_id、evidence_requirements、evidence 或验证状态到 QA。
一题对应一个可判定事实，包含必要属性但不捆绑多个独立攻击阶段。必要证据要求直接写进
`match_rule`。问题必须唯一，标准答案只描述镜像中可调查的实际行为，不以原报告或预期配置代替实测。

`backgrounds.json` 严格是三个等级到正文的映射：

```json
{
  "L1": "主机 lab-host 出现异常脚本活动，涉及 /var/tmp/example/update.sh。请核实并还原相关过程。",
  "L2": "主机 lab-host 出现异常脚本活动，请调查其来源和后续操作。",
  "L3": "主机 lab-host 被报告存在异常活动，请调查是否发生安全事件并还原过程。"
}
```

不写 template、revealed_fact_ids、text 包装或其他元数据。不同场景据实际告警编写正文。
L1 给具体实体、窄时间窗或调查起点，L2 给局部告警，L3 给粗粒度异常。三者同镜像同 QA，
只减少初始提示。给被测 Agent 的输入仅为选定等级的字符串，不能把整个 JSON 或隐藏 QA 交给它。

## 构建侧关联与执行后定稿

为保留自动验证能力，在已有 `attack_graph.json` 中记录构建侧关联，不额外增加交付文件：

```json
{
  "evaluation": {
    "status": "draft",
    "qa_checks": [
      {
        "question": "主机获取了哪个脚本，保存在哪里？",
        "node_ids": ["N01"],
        "verifier_id": "E01"
      }
    ]
  }
}
```

按完整 question 匹配，而不是按数组位置匹配；问题调整时同步更新关联。一个 QA 对应一个
独立验证项。关联必须指向实际实现的节点，不能给省略行为出题。

执行前 `answer` 为 null，图中 `evaluation.status` 为 draft。背景直接写字符串，尚未知的
运行值可临时写成 `{{hostname}}` 等占位符；不另设 template 字段。验证器根据脚本配置和
真实端点证据检查事实，不能读取 QA、攻击图或运行器成功标志来回显答案。

验证报告保留在评估侧，使用以下契约：

```json
{
  "schema_version": "1.0",
  "scenario_id": "example-linux",
  "package_revision": "1",
  "run_id": "实际运行标识",
  "verified_at": "实际带时区 ISO-8601 时间",
  "verification_scope": "restored_image",
  "passed": true,
  "bindings": {"hostname": "lab-host"},
  "checks": [
    {
      "id": "E01",
      "passed": true,
      "observed_answer": "依据实际观测构造的完整答案",
      "evidence": [{"location": "实际文件或日志位置", "observation": "实际观测内容"}]
    }
  ]
}
```

`verification_scope` 为 live_endpoint 或 restored_image；只有后者证明在恢复的交付镜像中
检查通过。缺题、失败、空证据、场景/修订版不匹配或未绑定变量都应阻止定稿，不得删题缩小分母。

```bash
python3 artifacts/tools.py finalize . --report /controller/results/verification.json
python3 artifacts/tools.py validate . --require-verified
```

定稿把 observed_answer 写入对应 answer，填入背景中的运行值；验证时间、run_id、revision、
scope 仅记在攻击图 verification 中。evaluation.status 改为 verified，工具保存两份简化文件
内容的摘要，检测定稿后的意外改动。摘要不是对真实执行的证明，证据依据仍是独立验证报告。

README 写 `Package-Revision: <version>`，验证器内嵌同一版本。修改脚本、题意或评分标准后
递增版本，清空答案，恢复背景中的运行占位符，将图状态重置 draft，移除旧 verification 和
content_sha256，再执行验证。同一镜像恢复复核不改版本。仅删除冗余输出字段且不改变场景、
问题、答案、判定标准时可沿用原验证报告，不必重新执行场景。
新一轮运行定稿前也应恢复 draft 和所需背景占位符，避免沿用上次实体与时间。

## LLM 裁判规则

后续评分时向独立裁判提供 QA、判定要求、必要的参考证据和调查报告，不给被测 Agent 提供这些材料。裁判先将报告拆成去重的原子事实，再语义匹配，不比较字符相似度，不按文风给等级分。

- TP：正确匹配的标准事实，每个只算一次。
- FP：任务范围内错误的确定性事实；正确事实旁的错误陈述也计入。
- FN：标准事实没有被正确恢复，包含遗漏和错误回答。
- 候选猜测不算 TP，明确不确定项不当成确定性错误事实。
- QA 未覆盖的陈述先查证，不能因不在标准答案里就当作 FP；新增有效事实经统一修订后重评所有结果。
- 输出原文、匹配问题、正确/不正确判断及理由；不得补写报告未表达的信息。

Precision = TP/(TP+FP)，Recall = TP/(TP+FN)，F1 为二者调和平均。无事实输出时三者记 0。证据支持可另做分析，不暗中改变事实匹配口径。裁判版本与规则统一并经人工抽查；此 skill 不调用在线裁判或虚构 Precision/Recall 数值。
