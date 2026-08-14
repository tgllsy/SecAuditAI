# SecAuditAI - 自动化代码审计与漏洞验证工具

SecAuditAI 是一个集成了 **CodeQL** 静态分析和 **LLM (大语言模型)** 智能验证的自动化代码审计工具。它旨在帮助安全研究人员和开发人员高效地发现和验证代码中的安全漏洞，显著降低误报率。

## 项目定位

SecAuditAI 是一个独立的 Go 开源工具，面向需要把 CodeQL 扫描结果交给 LLM 做二次分析的开发者和安全研究人员。项目由 `tgllsy` 维护，欢迎通过 Issue 和 Pull Request 反馈问题、补充规则或改进文档。

> 反编译功能会先处理归档中的依赖库，可能占用较多磁盘空间和模型 Token。对 Java 项目，优先使用 Maven/Gradle 构建后的源码进行分析。

## 🚀 功能特点

- **自动化静态分析**: 利用 GitHub CodeQL 强大的查询能力，对源代码进行深度的污点追踪和数据流分析。
- **AI 智能验证**: 集成大语言模型（如 DeepSeek, GPT 等），对 CodeQL 的扫描结果进行二次验证，准确判断漏洞的真实性。
- **多模型轮询**: 支持配置多个 AI 模型，自动轮询调用，提高系统可用性和容错能力。
- **误报过滤**: 通过 AI 分析代码上下文、过滤机制和防御措施，自动剔除无效的误报。
- **Payload 生成**: 针对确认的漏洞，尝试自动生成验证 Payload (PoC)，辅助复现。
- **多语言支持**: 支持 Java, Python, Go, JavaScript 等多种主流编程语言（取决于 CodeQL 和规则集的支持）。
- **可视化报告**: 生成包含代码高亮、漏洞详情、AI 分析过程和验证结果的 HTML 报表。

## 🛠️ 环境配置

在运行本工具之前，请确保您的环境满足以下要求：

### 1. 基础环境
- **Operating System**: Windows, Linux, or macOS
- **Go**: Version 1.24 或更高版本

### 2. 依赖工具
- **CodeQL CLI**: 必须安装并配置到系统环境变量 `PATH` 中。
  - [下载地址](https://github.com/github/codeql-cli-binaries/releases)
- **CodeQL Rulesets**: 需要下载对应的 CodeQL 查询包（Standard Libraries）。
  - [CodeQL Repo](https://github.com/github/codeql)

### 3. AI 模型配置
- 需要一个兼容 OpenAI API 格式的 LLM 服务接口（如 DeepSeek API, OpenAI API 等）。

## 📦 安装与编译

### 1. 克隆项目
```bash
git clone https://github.com/tgllsy/SecAuditAI.git
cd SecAuditAI
```

### 2. 安装依赖
```bash
go mod tidy
```

### 3. 编译项目
```bash
go build -o SecAuditAI.exe -ldflags="-s -w" -trimpath .
```

## ⚙️ 配置文件

在运行之前，请确保项目根目录下存在 `config.yaml` 配置文件。你可以参考以下模板进行配置：

### 完整配置示例

```yaml
# 工具配置
tool:
  name: "Automated Code Audit Tool"
  version: "1.0.4"

# CodeQL配置
codeql:
  cli_path: "codeql"  # CodeQL CLI路径
  database_dir: "./codeql-dbs"  # 数据库存储目录
  repo_path: "/codeql/codeql-repo" # CodeQL 规则库根目录
  threads: "0" # 使用的线程数，0表示使用所有可用核心
  ram: "24000" # 使用的内存大小(MB)，留空表示自动管理
  languages:
    java:
      ruleset: "java/ql/src/codeql-suites/java-security-extended.qls"
      additional_rulesets:
        - "java/ql/src/codeql-suites/java-code-quality.qls"
    python:
      ruleset: "python/ql/src/codeql-suites/python-security-extended.qls"
      additional_rulesets:
        - "python/ql/src/codeql-suites/python-code-quality.qls"
    go:
      ruleset: "go/ql/src/codeql-suites/go-security-extended.qls"
      additional_rulesets:
        - "go/ql/src/codeql-suites/go-code-quality.qls"
    javascript:
      ruleset: "javascript/ql/src/codeql-suites/javascript-security-extended.qls"
      additional_rulesets:
        - "javascript/ql/src/codeql-suites/javascript-code-quality.qls"

# AI配置
ai:

  # 多模型配置（新格式，支持轮询）
  models:
    - provider: "https://api.siliconflow.cn/v1"  # AI提供商 API 地址
      api_key: "your-api-key-1"  # API密钥
      model: "deepseek-ai/DeepSeek-V3"  # 模型名称
    - provider: "https://api.openai.com/v1"  # 另一个AI提供商 API 地址
      api_key: "your-api-key-2"  # 另一个API密钥
      model: "gpt-4o"  # 另一个模型名称
  
  temperature: 0.7  # 生成温度
  max_tokens: 3000  # 最大令牌数

# 报告配置
report:
  output_dir: "./reports"  # 报告输出目录
  formats: ["json", "html"]  # 支持的报告格式
  include_payload: true  # 是否包含Payload
```

## 🖥️ 使用说明

### 基本用法

```bash
./SecAuditAI.exe audit --target <源代码目录> --language <语言>
```

### 常用参数

| 参数 | 简写 | 描述 | 默认值 |
|------|------|------|--------|
| `--target` | `-t` | **(必填)** 目标源代码目录的绝对路径 | - |
| `--language` | `-l` | 源代码语言 | `java` |
| `--output` | `-o` | 报告输出目录 | `./reports` |
| `--config` | `-c` | 配置文件路径 | `config.yaml` |
| `--concurrency` | `-n` | AI 验证的并发线程数 | `5` |
| `--ruleset` | `-r` | 自定义规则集路径 (可选) | - |

### 示例

1. **审计 Java 项目**：
   ```bash
   ./SecAuditAI.exe audit -t "C:\Users\username\Downloads\Hello-Java-Sec-master" -l java
   ```

2. **指定输出目录**：
   ```bash
   ./SecAuditAI.exe audit -t "C:\projects\app" -l python -o "C:\reports\my-app"
   ```

3. **使用自定义配置文件**：
   ```bash
   ./SecAuditAI.exe audit -t "C:\projects\app" -l go -c "D:\configs\custom-config.yaml"
   ```

4. **调整并发数**：
   ```bash
   ./SecAuditAI.exe audit -t "C:\projects\app" -l javascript -n 10
   ```

### 工作流程

1. **配置加载**：加载指定的配置文件
2. **规则集选择**：根据语言选择合适的 CodeQL 规则集
3. **数据库创建**：为目标代码创建 CodeQL 数据库
4. **静态分析**：使用 CodeQL 执行规则分析
5. **结果解析**：解析 CodeQL 生成的 SARIF 结果
6. **AI 验证**：使用大语言模型对漏洞进行智能验证（支持多模型轮询）
7. **报告生成**：生成 HTML 和 JSON 格式的报告

## 📂 代码结构

```
SecAuditAI/
├── cmd/
│   └── audit/          # audit 命令的核心逻辑
├── internal/
│   ├── ai/             # AI 客户端与验证逻辑（支持多模型轮询）
│   ├── codeql/         # CodeQL 操作封装 (建库、分析、解析 SARIF)
│   ├── config/         # 配置加载与管理（支持多模型配置）
│   ├── report/         # 报告生成 (HTML/JSON)
│   └── utils/          # 通用工具函数
├── rules/              # 自定义规则集目录
│   └── java/           # Java 自定义规则
├── codeql-dbs/         # CodeQL 数据库存储目录（自动创建）
├── reports/            # 默认报告输出目录（自动创建）
├── config.yaml         # 配置文件
├── main.go             # 程序入口
├── go.mod              # Go 依赖定义
├── go.sum              # Go 依赖校验和
└── README.md           # 项目文档
```

## 🔧 核心组件说明

### 1. 命令行接口 (cmd/audit/)
- **audit.go**: 实现了 `audit` 命令的主要逻辑，协调整个审计流程
- **参数解析**: 处理命令行参数，支持多种配置选项

### 2. AI 模块 (internal/ai/)
- **client.go**: AI 客户端实现，支持多模型轮询
- **payload.go**: Payload 生成逻辑
- **validator.go**: 漏洞验证逻辑

### 3. CodeQL 模块 (internal/codeql/)
- **database.go**: CodeQL 数据库创建
- **scanner.go**: CodeQL 分析执行
- **result.go**: SARIF 结果解析

### 4. 配置模块 (internal/config/)
- **config.go**: 配置结构体定义和加载逻辑

## 🆕 新增与重要变更

- 支持 `.jar/.war/.apk` 自动反编译：当 `-t` 指向归档文件时，自动使用 Jadx 反编译到 `./out/decompiled/<项目名>_<时间戳>`，随后进行 CodeQL 分析
- 支持 CodeQL 无构建模式：命令行可通过 `--buildless/-b` 开启，无构建时自动使用 `--build-mode=none`
- 新增配置项：
  - `decompiler.jadx_path`：Jadx 可执行文件路径或其目录（程序会在该目录及 `bin` 子目录中自动定位 `jadx(.bat/.exe)`）
  - `codeql.maven_paths` 与 `codeql.gradle_paths`：用于 CodeQL 构建 Java 项目时定位 Maven/Gradle
  - `jdk.versions` 与 `jdk.default`：多版本 JDK 配置与默认版本
- 输出目录统一为 `./out` 下：
  - CodeQL 数据库：`./out/codeql-dbs/<项目名>_<时间戳>`
  - 报告目录：`./out/reports/<项目名>_<时间戳>`
- 项目名约定：取 `-t` 路径最后一级目录名，或归档文件名（去扩展名），用于命名数据库与报告目录

### 归档分析示例

```powershell
.\SecAuditAI.exe audit -t "C:\Users\username\Downloads\app.apk" -l java
```

### 配置片段示例（新增/变更）

```yaml
codeql:
  database_dir: "./out/codeql-dbs"
  maven_paths:
    - "D:/Service/scoop/apps/maven/current/bin"
  gradle_paths:
    - "D:/Service/gradle-8.8/bin"

jdk:
  versions:
    jdk8: "C:/Program Files/Java/jdk1.8.0_202/bin/"
    jdk11: "D:/Service/jdk-11.0.28/bin/"
    jdk17: "D:/Service/jdk-17.0.12/bin/"
    jdk21: "D:/Service/jdk-21.0.9/bin/"
  default: "jdk8"

decompiler:
  # 可填到具体可执行文件路径，或其目录（程序会在该目录及其 bin 子目录中自动定位可执行文件）
  jadx_path: "D:/Service/jadx/bin"
```

### 安全提示

- 请勿将真实的 `api_key` 提交到仓库，建议使用环境变量或本地未提交的配置文件
- 工具不会记录或输出敏感密钥到日志
- **支持多模型配置**: 支持配置多个 AI 模型，自动轮询

### 5. 报告模块 (internal/report/)
- **generator.go**: 报告生成核心逻辑
- **exporter.go**: 报告导出（JSON/HTML）

## 📋 版本更新日志

### 当前版本

当前代码版本为 `1.0.4`。提交功能变更前，请先运行仓库中的测试和静态检查。

### v1.0.1 (2025-12-12)
- ✨ 新增多模型轮询支持，提高系统可用性
- ✨ 优化配置文件结构，支持更灵活的配置
- ✨ 增强目录自动创建功能，避免手动创建目录
- 🐛 修复了数据库创建目录不存在的问题
- 📚 更新了详细的配置示例和使用说明

### v1.0.0 (2025-12-11)
- 🚀 初始版本发布
- ✨ 集成 CodeQL 静态分析
- ✨ 集成 LLM 智能验证
- ✨ 支持多语言审计
- ✨ 生成可视化 HTML/JSON 报告

## 🤝 贡献指南

欢迎提交 Issue 和 Pull Request 来改进本项目！

1. **代码规范**: 请遵循 Go 语言编码规范，使用 `gofmt` 格式化代码。
2. **注释**: 提交的代码请包含清晰的中文注释。
3. **测试**: 修改核心逻辑后，请确保通过本地测试。
4. **文档**: 如有功能变更，请同步更新 README.md。

### 本地检查

```bash
go test ./...
go vet ./...
```

## 📝 许可证

MIT License
