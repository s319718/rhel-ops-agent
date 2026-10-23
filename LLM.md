# LLM 模型接入说明

## 模型在哪里

项目仓库不包含模型权重。有两种使用方式：

- 直接调用阿里云 DashScope 的 Qwen API，不需要下载权重。
- 在运行机器上用 Ollama 管理本地 `qwen2.5:7b-instruct`。

本地 Ollama 模型目录：

```text
/usr/share/ollama/.ollama/models
```

本机接口：

```text
http://127.0.0.1:11434
```

## 推荐模型

| 模型 | 用途 | 要求 |
|---|---|---|
| `qwen-plus` | 直接调用 DashScope 的默认推荐 | 阿里云 API Key |
| `qwen2.5:7b-instruct` | 本机离线推荐 | Ollama，约 8K 上下文 |
| Qwen2.5 14B/32B | 更复杂多意图，资源要求更高 | 足够内存或 GPU |
| DeepSeek V2/V3 | 推理和复杂中文任务 | 需确认所用服务支持工具调用 |
| Llama 3 / GLM 4 | 可选替代 | 需使用支持 Function Calling 的版本 |

不建议使用不能稳定返回 `tool_calls` 的旧模型或纯聊天模型。

## 方式一：直接调用 Qwen API

先在阿里云百炼 / DashScope 创建 API Key：

```bash
cd rhel-ops-agent
sudo bash scripts/setup-qwen-api.sh
sudo rhel-agent llm-test
```

脚本会隐藏读取 API Key，并写入 `/etc/rhel-ops-agent/agent.env`：

```text
RHEL_OPS_LLM_ENABLED=1
RHEL_OPS_LLM_MODE=hybrid
RHEL_OPS_LLM_PROVIDER=qwen
RHEL_OPS_LLM_BASE_URL=https://dashscope.aliyuncs.com/compatible-mode/v1
RHEL_OPS_LLM_MODEL=qwen-plus
```

API Key 不写入代码、不返回 Web、不进入日志，文件权限为 `0600`。

## 方式二：RHEL 本机 Ollama

```bash
cd rhel-ops-agent
sudo RHEL_OPS_INSTALL_OLLAMA=1 bash scripts/setup-ollama.sh
```

脚本执行内容：

1. 检查 `ollama`。
2. 在显式确认下运行 Ollama 官方安装脚本。
3. 启动 Ollama 服务。
4. 拉取 `qwen2.5:7b-instruct`。
5. 更新 `/etc/rhel-ops-agent/agent.env`。
6. 重启 `rhel-ops-agent.service`。

手工拉取：

```bash
ollama pull qwen2.5:7b-instruct
ollama list
```

## 配置

```bash
RHEL_OPS_LLM_ENABLED=1
RHEL_OPS_LLM_MODE=hybrid
RHEL_OPS_LLM_PROVIDER=qwen
RHEL_OPS_LLM_BASE_URL=https://dashscope.aliyuncs.com/compatible-mode/v1
RHEL_OPS_LLM_MODEL=qwen-plus
RHEL_OPS_LLM_API_KEY=sk-***
RHEL_OPS_LLM_TIMEOUT=20
RHEL_OPS_LLM_CONFIDENCE=0.55
RHEL_OPS_LLM_STRUCTURED_OUTPUT=1
RHEL_OPS_LLM_MAX_ACTIONS=6
```

`RHEL_OPS_LLM_MODE`：

- `off`：关闭。
- `hybrid`：规则优先，未命中或缺少参数时调用模型。
- `always`：本地硬拦截后优先使用模型，失败回退规则。

## OpenAI 兼容服务

```bash
RHEL_OPS_LLM_ENABLED=1
RHEL_OPS_LLM_MODE=hybrid
RHEL_OPS_LLM_PROVIDER=openai-compatible
RHEL_OPS_LLM_BASE_URL=https://your-provider.example/v1
RHEL_OPS_LLM_MODEL=your-tool-calling-model
RHEL_OPS_LLM_API_KEY=your-secret
```

客户端请求地址为：

```text
<BASE_URL>/chat/completions
```

远程地址必须使用 HTTPS。明文 HTTP 只允许 `localhost`、`127.0.0.1` 或 `::1`。

## Function Calling 协议

模型只允许调用一个函数：

```json
{
  "name": "submit_operations",
  "arguments": {
    "language": "zh",
    "confidence": 0.93,
    "rationale": "用户要求修改系统语言",
    "operations": [
      {
        "action_id": "set_locale_zh",
        "parameters": {}
      }
    ]
  }
}
```

客户端处理顺序：

1. 优先读取原生 `tool_calls`。
2. 其次接受完整 JSON 内容。
3. 拒绝包含解释文字的自由文本。
4. 校验动作 ID、参数名、参数格式、置信度、动作数量。
5. 通过 `RuleEngine` 重新生成计划。
6. 高风险操作继续要求确认语。

模型没有 Shell、文件写入、网络命令或自定义二进制工具。

## 上下文设计

为兼容 7B 模型的 8K 上下文，请求不会把所有参数 schema 原样塞入提示：

- 工具枚举包含全部 101 个动作 ID。
- 系统根据用户输入本地检索最多 24 个相关动作。
- 只展开相关动作的参数说明。
- 内置 20 条中英文 few-shot 示例。
- 不发送系统日志、命令历史、密码、Token 或 API Key。

## 验证

```bash
sudo rhel-agent rules
sudo rhel-agent "机器有点卡，帮我看看谁占 CPU 高"
```

Web：

```text
http://127.0.0.1:8765/api/llm/status
```

计划成功由 LLM 解析时会显示：

```text
LLM 理解 + 本地安全校验
```

## 故障排查

### 显示“未启用”

检查 `/etc/rhel-ops-agent/agent.env` 是否包含 `RHEL_OPS_LLM_ENABLED=1`，然后：

```bash
sudo systemctl restart rhel-ops-agent
sudo rhel-agent rules
```

### 模型服务不可用

```bash
curl http://127.0.0.1:11434/api/tags
systemctl status ollama
ollama list
```

### 模型返回格式错误

Agent 会拒绝结果并回退规则引擎。检查模型是否支持工具调用；必要时更换为 Qwen2.5-Instruct。

### 工具调用被拒绝

确认模型名称正确、服务支持 OpenAI tools 或 Ollama tools，并且没有强制关闭结构化输出。
