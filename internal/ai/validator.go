// Package ai 实现了AI客户端与验证逻辑，用于与大语言模型交互
package ai

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/secauditai/secauditai/internal/codeql" // 引入codeql包，使用漏洞定义
	"github.com/secauditai/secauditai/internal/utils"  // 引入utils包，使用代码片段读取功能
)

// ValidationResult 表示漏洞验证的结果结构体
// 包含了AI对漏洞的分析结果和相关信息

type ValidationResult struct {
	IsReal              bool   `json:"is_real"`                        // 漏洞是否真实存在
	Reason              string `json:"reason"`                         // AI的分析理由
	CodeSnippet         string `json:"code_snippet"`                   // 相关代码片段
	VulnerableParameter string `json:"vulnerable_parameter,omitempty"` // 触发漏洞的参数名称
	RouteInfo           string `json:"route_info,omitempty"`           // API路由信息
	FullCodeContext     string `json:"full_code_context,omitempty"`    // 完整的代码上下文（包含Source和Sink）
}

// ValidateVulnerability 使用AI验证漏洞是否真实存在
// 调用大语言模型分析漏洞信息和代码片段，判断是否存在真实的安全问题
// 参数：
//   ctx - 上下文，用于控制请求的生命周期
//   vuln - 漏洞信息，包含规则ID、描述、位置等
//   basePath - 源代码的基础路径，用于构建完整的文件路径
// 返回：
//   *ValidationResult - 验证结果，包含漏洞是否真实、分析理由等
//   error - 如果验证失败则返回错误信息

func (c *Client) ValidateVulnerability(ctx context.Context, vuln codeql.Vulnerability, basePath string) (*ValidationResult, error) {
	// 读取代码片段（如果尚未提供）
	snippet := vuln.CodeSnippet
	if snippet == "" {
		// 构建完整文件路径，处理路径分隔符和清理路径
		relPath := filepath.Clean(vuln.Location.File)
		// SARIF通常包含相对路径或URI，确保正确拼接基础路径
		fullPath := filepath.Join(basePath, relPath)

		// 读取代码片段，包含20行上下文
		s, err := utils.ReadCodeSnippet(fullPath, vuln.Location.Line, 20)
		if err != nil {
			return nil, fmt.Errorf("读取代码片段失败: %w", err)
		}
		snippet = s
	}

	// 构建完整的数据流代码上下文
	var fullCodeContext string

	if len(vuln.FlowSteps) > 0 {
		// 策略 A: 如果有详细的数据流步骤，构建完整的追踪上下文
		var sb strings.Builder
		sb.WriteString("数据流追踪 (Data Flow Trace):\n")

		// 用于去重的简单机制：记录上一次读取的文件和行号
		lastFile := ""
		lastLine := -1

		for i, step := range vuln.FlowSteps {
			// 如果与上一步在同一文件且行号相近（5行以内），则跳过，避免重复展示
			if step.File == lastFile && step.Line >= lastLine-5 && step.Line <= lastLine+5 {
				continue
			}

			relPath := filepath.Clean(step.File)
			fullPath := filepath.Join(basePath, relPath)

			// 读取代码片段，上下文行数设为 4
			s, err := utils.ReadCodeSnippet(fullPath, step.Line, 4)
			if err == nil {
				stepName := fmt.Sprintf("Step %d", i+1)
				if i == 0 {
					stepName = "Source (输入源)"
				} else if i == len(vuln.FlowSteps)-1 {
					stepName = "Sink (漏洞点)"
				}

				sb.WriteString(fmt.Sprintf("\n--- %s: %s:%d ---\n%s\n", stepName, step.File, step.Line, s))

				lastFile = step.File
				lastLine = step.Line
			}
		}
		fullCodeContext = sb.String()
	} else if vuln.Source != nil {
		// 策略 B: 只有 Source 和 Sink 信息（旧逻辑兼容）
		var sourceSnippet string
		// 判断是否需要读取：如果Source和Sink不在同一个文件，或者在同一个文件但距离较远（超过20行）
		shouldRead := false
		if vuln.Source.File != vuln.Location.File {
			shouldRead = true
		} else {
			diff := vuln.Source.Line - vuln.Location.Line
			if diff < 0 {
				diff = -diff
			}
			if diff > 20 {
				shouldRead = true
			}
		}

		if shouldRead {
			relPath := filepath.Clean(vuln.Source.File)
			fullPath := filepath.Join(basePath, relPath)
			s, err := utils.ReadCodeSnippet(fullPath, vuln.Source.Line, 10)
			if err == nil {
				sourceSnippet = fmt.Sprintf("Source 代码片段 (输入源 %s:%d):\n%s", vuln.Source.File, vuln.Source.Line, s)
			}
		}

		if sourceSnippet != "" {
			fullCodeContext = fmt.Sprintf("%s\n\n----------------------------------------\n\nSink 代码片段 (漏洞点 %s:%d):\n%s", sourceSnippet, vuln.Location.File, vuln.Location.Line, snippet)
		} else {
			fullCodeContext = fmt.Sprintf("代码片段 (漏洞点 %s:%d):\n%s", vuln.Location.File, vuln.Location.Line, snippet)
		}
	} else {
		// 策略 C: 只有 Sink 信息
		fullCodeContext = fmt.Sprintf("代码片段 (漏洞点 %s:%d):\n%s", vuln.Location.File, vuln.Location.Line, snippet)
	}

	// 尝试提取API路由信息（针对Web项目）
	var routeInfo string
	// 优先从Source位置提取路由（通常Controller层是Source）
	if vuln.Source != nil {
		relPath := filepath.Clean(vuln.Source.File)
		fullPath := filepath.Join(basePath, relPath)
		routeInfo = utils.ExtractRouteInfo(fullPath, vuln.Source.Line)
	}
	// 如果没有Source或未提取到，尝试从Sink位置提取（有时Controller直接调用Sink）
	if routeInfo == "" {
		relPath := filepath.Clean(vuln.Location.File)
		fullPath := filepath.Join(basePath, relPath)
		routeInfo = utils.ExtractRouteInfo(fullPath, vuln.Location.Line)
	}

	// 检查缓存
	// 使用 RuleID + 完整代码上下文 作为缓存Key
	cacheKey := fmt.Sprintf("%s|%s", vuln.RuleID, fullCodeContext)
	if cached, ok := c.cache.Load(cacheKey); ok {
		return cached.(*ValidationResult), nil
	}

	// 根据文件类型构建不同的提示词
	fileExt := filepath.Ext(vuln.Location.File)
	isMyBatis := false
	if fileExt == ".xml" {
		// 检查是否为MyBatis文件
		isMyBatis = strings.Contains(strings.ToLower(vuln.Location.File), "mapper") || strings.Contains(strings.ToLower(snippet), "mybatis")
	}

	// 确定分析重点
	analysisFocus := "分析数据流向，判断是否存在用户可控的输入进入了危险函数（Source 到 Sink）。"
	if isMyBatis {
		analysisFocus = "如果是MyBatis XML文件，请重点检查${}语法使用，这是SQL注入的常见来源，应使用#{}替代。"
	}

	// 构建提示词，指导AI进行漏洞分析
	prompt := fmt.Sprintf(`你是一名资深的安全代码审计专家。请根据以下信息分析代码中是否存在真实的安全漏洞。

漏洞信息：
- 规则ID： %s
- 漏洞描述： %s
- 文件路径： %s
- 行号： %d
- API路由： %s

代码片段（包含上下文）：
%s

分析要求：
1. %s
2. 分析数据流向，判断是否存在用户可控的输入进入了危险函数（Source 到 Sink）。请特别注意 Source 处（如果有）是否对输入进行了校验、过滤或清理。
3. 检查代码中是否存在有效的过滤、转义或验证机制。
4. 考虑代码的上下文环境，排除误报情况（如测试代码、死代码等）。
5. 如果存在漏洞，请准确识别触发漏洞的参数名称。如果提供了API路由信息，请尝试构造一个简单的PoC（概念验证）请求。

输出要求：
请务必严格按照以下格式输出结果（不要包含其他无关的寒暄），确保使用 Markdown 格式：

判定结果：[是/否]
触发参数：[参数名/无]
风险等级：[高/中/低/无]
分析理由：
[详细的分析说明，解释为什么判定为是或否，指出具体的漏洞点或防御措施。
如果涉及代码分析，请使用 Markdown 代码块。
请确保段落之间有空行，以便正确渲染。]`,
		vuln.RuleID, vuln.Message, vuln.Location.File, vuln.Location.Line, routeInfo, fullCodeContext, analysisFocus)

	// 调用AI客户端发送提示词
	response, err := c.SendPrompt(ctx, prompt)
	if err != nil {
		return nil, err
	}

	// 解析AI响应，判断漏洞是否真实存在
	isReal := strings.Contains(response, "判定结果：是") || strings.Contains(response, "判定结果：[是]")

	// 提取触发漏洞的参数名称
	var vulnerableParam string
	lines := strings.Split(response, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "触发参数：") {
			vulnerableParam = strings.TrimSpace(strings.TrimPrefix(line, "触发参数："))
			vulnerableParam = strings.Trim(vulnerableParam, "[]") // 移除括号
			break
		}
	}

	// 构建并返回验证结果
	result := &ValidationResult{
		IsReal:              isReal,
		Reason:              response,
		CodeSnippet:         snippet,
		VulnerableParameter: vulnerableParam,
		RouteInfo:           routeInfo,
		FullCodeContext:     fullCodeContext,
	}

	// 存入缓存
	c.cache.Store(cacheKey, result)

	return result, nil
}
