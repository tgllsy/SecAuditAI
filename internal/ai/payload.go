// Package ai 实现了AI客户端与验证逻辑，用于与大语言模型交互
package ai

import (
	"context"
	"fmt"

	"github.com/secauditai/secauditai/internal/codeql" // 引入codeql包，使用漏洞定义
)

// GeneratePayload 为确认存在的漏洞生成验证用的Payload
// 调用大语言模型生成安全无害的概念验证(PoC)，用于验证漏洞的存在
// 参数：
//   ctx - 上下文，用于控制请求的生命周期
//   vuln - 漏洞信息，包含规则ID、描述、位置等
//   snippet - 漏洞相关的代码片段（建议传入完整的代码上下文）
//   routeInfo - API路由信息（如果有）
// 返回：
//   string - 生成的Payload内容，包含验证步骤和预期结果
//   error - 如果生成失败则返回错误信息

func (c *Client) GeneratePayload(ctx context.Context, vuln codeql.Vulnerability, snippet string, routeInfo string) (string, error) {
	// 构建提示词，指导AI生成合适的Payload
	prompt := fmt.Sprintf(`你是一名高级渗透测试工程师。请为以下确认存在的漏洞生成一个用于验证的概念验证（PoC）Payload。
	
漏洞信息：
- 规则ID： %s
- 漏洞描述： %s
- 文件路径： %s
- 行号： %d
- API路由： %s

代码片段：
%s

生成要求：
1. Payload 必须是安全且无害的（例如，只打印特定的字符串、执行 calc.exe 或 sleep，不要执行破坏性操作）。
2. 提供具体的 Payload 字符串。
3. 如果是 Web 漏洞，请尽量提供 curl 命令或 HTTP 请求包，能在 Burp Suite 中使用。如果提供了API路由，请务必在构造请求时使用正确的路径。
4. 详细说明如何使用该 Payload 进行验证。

输出格式：
请使用 Markdown 格式输出，包含以下部分：
### 验证 Payload
`+"```text"+`
[具体的 Payload 内容]
`+"```"+`

### 验证步骤
1. [步骤1]
2. [步骤2]
...

### 预期结果
[描述漏洞存在时的预期表现]`,
		vuln.RuleID, vuln.Message, vuln.Location.File, vuln.Location.Line, routeInfo, snippet)

	// 调用SendPrompt方法发送提示词并获取响应
	return c.SendPrompt(ctx, prompt)
}
