// Package report 实现了报告生成功能，支持生成JSON和HTML格式的审计报告
package report

import (
	"github.com/secauditai/secauditai/internal/ai"         // 引入AI包，使用验证结果类型
	"github.com/secauditai/secauditai/internal/codeql"     // 引入codeql包，使用漏洞类型
)

// AuditResult 表示单个漏洞的审计结果结构体
// 包含漏洞信息、AI验证结果和生成的Payload

type AuditResult struct {
	Vulnerability codeql.Vulnerability `json:"vulnerability"` // 漏洞基本信息
	Validation    *ai.ValidationResult `json:"validation,omitempty"` // AI验证结果（可选）
	Payload       string               `json:"payload,omitempty"`   // 生成的验证Payload（可选）
}

// Report 表示完整的审计报告结构体
// 包含源代码语言和所有漏洞的审计结果列表

type Report struct {
	Language string        `json:"language"` // 源代码语言（如java、python、go等）
	Results  []AuditResult `json:"results"`  // 所有漏洞的审计结果列表
}

// GenerateReport 生成审计报告
// 注意：当前实现比较简单，实际使用中建议直接在主流程中构建Report对象
// 参数：
//   vulns - 漏洞列表
//   validations - 验证结果映射表（键为漏洞唯一标识）
//   payloads - Payload映射表（键为漏洞唯一标识）
// 返回：
//   *Report - 生成的审计报告指针

func GenerateReport(vulns []codeql.Vulnerability, validations map[string]*ai.ValidationResult, payloads map[string]string) *Report {
	var results []AuditResult // 审计结果列表

	// 遍历所有漏洞，构建审计结果
	for _, v := range vulns {
		// 创建审计结果对象
		res := AuditResult{
			Vulnerability: v, // 设置漏洞基本信息
		}
		// 注意：当前实现未使用validations和payloads参数
		// 在实际应用中，应根据漏洞的唯一标识（如文件路径+行号+规则ID）从映射表中获取对应的数据
		// 例如：key := fmt.Sprintf("%s:%d:%s", v.Location.File, v.Location.Line, v.RuleID)
		// res.Validation = validations[key]
		// res.Payload = payloads[key]
		
		results = append(results, res) // 添加到结果列表
	}

	// 创建并返回Report对象
	return &Report{Results: results}
}

// 注意：更好的实现方式是直接在主流程中构建Report结构体，
// 这样可以更灵活地处理审计结果，而不需要依赖映射表来关联数据。
