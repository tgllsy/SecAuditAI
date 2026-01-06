// Package verify 实现了 verify 命令的核心逻辑，用于直接验证 SARIF 文件
package verify

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/secauditai/secauditai/internal/ai"     // AI客户端模块
	"github.com/secauditai/secauditai/internal/codeql" // CodeQL操作模块
	"github.com/secauditai/secauditai/internal/config" // 配置管理模块
	"github.com/secauditai/secauditai/internal/report" // 报告生成模块
	"github.com/fatih/color"                           // 终端颜色输出
	"github.com/spf13/cobra"                           // 命令行框架
)

// 命令行参数变量定义
var (
	sarifFile   string // SARIF 文件路径
	sourceDir   string // 源代码根目录
	outputDir   string // 报告输出目录
	configFile  string // 配置文件路径
	language    string // 源代码语言
	concurrency int    // AI 验证并发数
)

// Cmd 定义了 verify 命令，用于直接验证 SARIF 结果
var Cmd = &cobra.Command{
	Use:   "verify",
	Short: "直接验证 SARIF 结果",
	Long:  `跳过 CodeQL 扫描，直接读取现有的 SARIF 文件进行 AI 智能验证，并生成报告。`,
	Run:   runVerify,
}

// init 初始化命令行参数绑定
func init() {
	// 绑定命令行参数
	Cmd.Flags().StringVarP(&sarifFile, "sarif", "s", "", "SARIF 文件路径 (必填)")
	Cmd.MarkFlagRequired("sarif")
	Cmd.Flags().StringVarP(&sourceDir, "source", "t", "", "源代码根目录 (必填)")
	Cmd.MarkFlagRequired("source")
	Cmd.Flags().StringVarP(&outputDir, "output", "o", "", "报告输出目录")
	Cmd.Flags().StringVarP(&configFile, "config", "c", "config.yaml", "配置文件路径")
	Cmd.Flags().StringVarP(&language, "language", "l", "unknown", "源代码语言 (用于报告展示)")
	Cmd.Flags().IntVarP(&concurrency, "concurrency", "n", 5, "AI 验证并发数")
}

// runVerify 是 verify 命令的主要执行逻辑
func runVerify(cmd *cobra.Command, args []string) {
	// 初始化颜色输出函数
	info := color.New(color.FgCyan).PrintfFunc()               // 信息输出颜色
	success := color.New(color.FgGreen).PrintfFunc()           // 成功输出颜色
	warn := color.New(color.FgYellow).PrintfFunc()             // 警告输出颜色
	danger := color.New(color.FgRed).PrintfFunc()              // 错误输出颜色
	title := color.New(color.FgWhite, color.Bold).PrintfFunc() // 标题输出颜色

	// 1. 加载配置文件
	info("📄 正在加载配置文件: %s...\n", configFile)
	cfg, err := config.LoadConfig(configFile)
	if err != nil {
		log.Fatalf("无法加载配置文件: %v", err)
	}

	// 处理报告输出目录
	if outputDir == "" {
		if cfg.Report.OutputDir == "" {
			outputDir = "./reports"
		} else {
			outputDir = cfg.Report.OutputDir
		}
	}

	// 2. 解析 SARIF 文件
	info("📊 正在读取并解析 SARIF 文件: %s...\n", sarifFile)
	vulns, err := codeql.ParseSarif(sarifFile)
	if err != nil {
		log.Fatalf("解析 SARIF 文件失败: %v", err)
	}

	// 检查是否发现漏洞
	if len(vulns) > 0 {
		warn("⚠️  文件中包含 %d 个潜在漏洞。\n", len(vulns))
	} else {
		success("✅ SARIF 文件中未发现漏洞。\n")
		return
	}

	// 3. 准备输出目录
	timestamp := time.Now().Format("20060102_150405")
	projectName := filepath.Base(sourceDir)
	currentReportDir := filepath.Join(outputDir, fmt.Sprintf("verify_%s_%s", timestamp, projectName))

	if err := os.MkdirAll(currentReportDir, 0755); err != nil {
		log.Fatalf("创建报告输出目录失败: %v", err)
	}

	// 4. AI 验证
	info("🤖 正在启动 AI 验证（并发数：%d）...\n", concurrency)

	// 准备AI模型配置
	var aiModels []struct {
		APIKey  string
		Model   string
		BaseURL string
	}

	for _, modelConfig := range cfg.AI.Models {
		aiModels = append(aiModels, struct {
			APIKey  string
			Model   string
			BaseURL string
		}{
			APIKey:  modelConfig.APIKey,
			Model:   modelConfig.Model,
			BaseURL: modelConfig.Provider,
		})
	}

	aiClient := ai.NewClient(aiModels)
	ctx := context.Background()

	var auditResults []report.AuditResult
	var mutex sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)
	var processedCount int

	for i, v := range vulns {
		wg.Add(1)
		go func(index int, vuln codeql.Vulnerability) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			// 验证漏洞
			valResult, err := aiClient.ValidateVulnerability(ctx, vuln, sourceDir)

			// 生成 Payload
			var payload string
			var payloadErr error
			if err == nil && valResult != nil && valResult.IsReal && cfg.Report.IncludePayload {
				// 使用完整的代码上下文和路由信息生成更准确的Payload
				payload, payloadErr = aiClient.GeneratePayload(ctx, vuln, valResult.FullCodeContext, valResult.RouteInfo)
			}

			mutex.Lock()
			defer mutex.Unlock()
			processedCount++

			// 输出进度
			fmt.Println("---------------------------------------------------------")
			title("[%d/%d] 正在检查 %s\n", processedCount, len(vulns), vuln.RuleID)
			fmt.Printf("文件: %s:%d\n", vuln.Location.File, vuln.Location.Line)

			if err != nil {
				warn("❌ AI 验证失败: %v\n", err)
			} else {
				if valResult.IsReal {
					danger("🔴 [高危] AI 确认漏洞真实存在\n")
				} else {
					success("🟢 [安全] AI 判定为误报或低风险\n")
				}
				if valResult.CodeSnippet != "" {
					vuln.CodeSnippet = valResult.CodeSnippet
				}
			}

			if valResult != nil && valResult.IsReal && cfg.Report.IncludePayload {
				info("💣 正在生成 Payload...\n")
				if payloadErr != nil {
					warn("❌ Payload 生成失败: %v\n", payloadErr)
				} else {
					success("✅ Payload 生成成功。\n")
				}
			}

			auditResults = append(auditResults, report.AuditResult{
				Vulnerability: vuln,
				Validation:    valResult,
				Payload:       payload,
			})
		}(i, v)
	}
	wg.Wait()

	// 5. 生成报告
	info("📄 正在导出报告...\n")
	rep := &report.Report{
		Language: language,
		Results:  auditResults,
	}

	for _, format := range cfg.Report.Formats {
		if format == "json" {
			if err := rep.ExportJSON(currentReportDir); err != nil {
				log.Printf("导出 JSON 失败: %v", err)
			}
		} else if format == "html" {
			if err := rep.ExportHTML(currentReportDir); err != nil {
				log.Printf("导出 HTML 失败: %v", err)
			}
		}
	}

	success("✨ 验证完成！报告已保存至: %s\n", currentReportDir)
}
