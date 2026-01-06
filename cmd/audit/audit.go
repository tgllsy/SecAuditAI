// Package audit 实现了审计命令的核心逻辑
package audit

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/secauditai/secauditai/internal/ai"     // AI客户端模块
	"github.com/secauditai/secauditai/internal/codeql" // CodeQL操作模块
	"github.com/secauditai/secauditai/internal/config" // 配置管理模块
	"github.com/secauditai/secauditai/internal/decompiler"

	// 反编译模块
	"github.com/secauditai/secauditai/internal/report" // 报告生成模块
	"github.com/secauditai/secauditai/internal/utils"  // 通用工具函数
	"github.com/fatih/color"                           // 终端颜色输出
	"github.com/spf13/cobra"                           // 命令行框架
)

// 命令行参数变量定义
var (
	targetDir     string // 目标源代码目录
	outputDir     string // 报告输出目录
	configFile    string // 配置文件路径
	language      string // 源代码语言
	rulesetPath   string // 规则集路径
	concurrency   int    // AI 验证并发数
	buildModeNone bool   // 是否使用CodeQL无构建模式(--build-mode=none)
)

// Cmd 定义了 audit 命令，用于执行自动化代码审计
var Cmd = &cobra.Command{
	Use:   "audit",
	Short: "执行自动化代码审计",
	Long:  `执行自动化代码审计，包括CodeQL静态分析和AI智能验证，生成详细的漏洞报告。`,
	Run:   runAudit,
}

// init 初始化命令行参数绑定
func init() {
	// 绑定命令行参数，设置短选项、默认值和描述
	Cmd.Flags().StringVarP(&targetDir, "target", "t", "", "目标源代码目录 (必填)")
	Cmd.MarkFlagRequired("target") // 标记为必填参数
	Cmd.Flags().StringVarP(&outputDir, "output", "o", "", "报告输出目录")
	Cmd.Flags().StringVarP(&configFile, "config", "c", "config.yaml", "配置文件路径")
	Cmd.Flags().StringVarP(&language, "language", "l", "java", "源代码语言")
	Cmd.Flags().StringVarP(&rulesetPath, "ruleset", "r", "", "规则集路径 (可选)")
	Cmd.Flags().IntVarP(&concurrency, "concurrency", "n", 5, "AI 验证并发数")
	Cmd.Flags().BoolVarP(&buildModeNone, "buildless", "b", false, "使用CodeQL无构建模式(--build-mode=none)")
}

// runAudit 是 audit 命令的主要执行逻辑，协调整个审计流程
// 参数：
//
//	cmd - cobra命令对象
//	args - 命令行参数数组
func runAudit(cmd *cobra.Command, args []string) {
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

	// 处理报告输出目录的优先级：
	// 1. 如果命令行指定了outputDir，则使用命令行的值
	// 2. 如果命令行没有指定，则使用配置文件中的值
	// 3. 如果配置文件也没有指定，则使用默认值"./reports"
	if outputDir == "" { // 检查是否使用了默认值（空字符串）
		if cfg.Report.OutputDir == "" {
			outputDir = "./reports"
		} else {
			outputDir = cfg.Report.OutputDir
		}
	}

	// 确保报告输出目录存在
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		log.Fatalf("创建报告输出目录失败: %v", err)
	}

	// 1.5 检查并处理反编译
	// 如果 targetDir 是一个文件（如 .jar, .war, .apk），则先进行反编译
	fileInfo, err := os.Stat(targetDir)
	if err == nil && !fileInfo.IsDir() {
		// 使用配置中的Jadx路径
		dc := decompiler.NewDecompiler(cfg.Decompiler.JadxPath)
		if dc.IsArchive(targetDir) {
			title("🔓 检测到归档文件，准备反编译...\n")

			// 准备反编译输出目录
			filename := filepath.Base(targetDir)
			projectName := strings.TrimSuffix(filename, filepath.Ext(filename))
			timestamp := time.Now().Format("20060102_150405")
			// 使用绝对路径，确保后续操作正确
			absOutDir, _ := filepath.Abs("./out/decompiled")
			decompiledDir := filepath.Join(absOutDir, fmt.Sprintf("%s_%s", projectName, timestamp))

			// 执行反编译
			if err := dc.Decompile(targetDir, decompiledDir); err != nil {
				log.Fatalf("反编译失败: %v", err)
			}

			success("✅ 反编译完成，源码已保存至: %s\n", decompiledDir)

			// 更新 targetDir 为反编译后的目录
			targetDir = decompiledDir

			// 强制开启 buildless 模式，因为反编译代码通常无法直接构建
			if !buildModeNone {
				buildModeNone = true
				warn("⚠️  针对反编译代码，已自动启用 --buildless 模式。\n")
			}
		}
	}

	// 2. 确定规则集路径
	var allRulesetPaths []string

	if rulesetPath != "" {
		// 如果命令行指定了规则集，则使用命令行参数
		allRulesetPaths = append(allRulesetPaths, rulesetPath)
	} else {
		// 根据语言选择规则集
		if langConfig, ok := cfg.CodeQL.Languages[language]; ok {
			// 添加主规则集
			var mainRulesetPath string
			if cfg.CodeQL.RepoPath != "" {
				mainRulesetPath = filepath.Join(cfg.CodeQL.RepoPath, langConfig.Ruleset)
			} else {
				mainRulesetPath = langConfig.Ruleset
			}
			allRulesetPaths = append(allRulesetPaths, mainRulesetPath)

			// 添加所有额外规则集
			for _, additionalRuleset := range langConfig.AdditionalRulesets {
				var fullAdditionalPath string
				if cfg.CodeQL.RepoPath != "" && !filepath.IsAbs(additionalRuleset) && !strings.HasPrefix(additionalRuleset, "./") {
					// 如果是相对路径且不是以./开头，则认为是相对于repo_path的路径
					fullAdditionalPath = filepath.Join(cfg.CodeQL.RepoPath, additionalRuleset)
				} else {
					fullAdditionalPath = additionalRuleset
				}
				allRulesetPaths = append(allRulesetPaths, fullAdditionalPath)
			}
		} else {
			// 如果未找到明确配置，尝试使用默认值
			log.Printf("警告: 配置文件中未明确配置语言 '%s'，正在检查默认值...", language)
		}
	}

	// 检查是否获取到规则集
	if len(allRulesetPaths) == 0 {
		warn("⚠️  未指定语言 '%s' 的规则集，且配置文件中未找到.\n", language)
	}

	// 显示审计任务开始信息
	title("🚀 正在启动审计任务：%s...\n", targetDir)

	// 3. 生成带时间戳的路径，用于存储报告和数据库
	timestamp := time.Now().Format("20060102_150405")
	projectName := filepath.Base(targetDir) // 从目标目录获取项目名称

	currentReportDir := filepath.Join(outputDir, fmt.Sprintf("%s_%s", timestamp, projectName))             // 报告目录
	currentDbDir := filepath.Join(cfg.CodeQL.DatabaseDir, fmt.Sprintf("db_%s_%s", timestamp, projectName)) // 数据库目录

	// 4. CodeQL: 创建数据库
	info("📦 正在创建 CodeQL 数据库: %s...\n", currentDbDir)
	// 确保数据库目录的父目录存在
	if err := os.MkdirAll(cfg.CodeQL.DatabaseDir, 0755); err != nil {
		log.Fatalf("创建数据库父目录失败: %v", err)
	}

	// 检测Java版本并选择合适的JDK（仅针对Java项目）
	var jdkPath string
	if language == "java" {
		info("🔍 正在检测项目的Java版本...\n")
		javaVersion, err := utils.DetectJavaVersion(targetDir)
		if err != nil {
			warn("⚠️  Java版本检测失败: %v，使用默认JDK\n", err)
		} else {
			success("✅ 检测到Java版本: %s\n", javaVersion)

			// 选择合适的JDK
			jdkPath, err = utils.SelectJDK(cfg.JDK.Versions, javaVersion, cfg.JDK.Default)
			if err != nil {
				warn("⚠️  JDK选择失败: %v，使用系统默认Java\n", err)
			} else {
				success("✅ 选择的JDK: %s\n", jdkPath)
			}
		}
	}

	// 创建CodeQL数据库，传递JDK路径和配置
	if err := codeql.CreateDatabase(cfg, cfg.CodeQL.CLIPath, targetDir, currentDbDir, language, cfg.CodeQL.Threads, cfg.CodeQL.RAM, jdkPath, buildModeNone); err != nil {
		log.Fatalf("CodeQL 数据库创建失败: %v", err)
	}

	// 5. CodeQL: 执行分析
	sarifFile := filepath.Join(currentReportDir, "results.sarif") // SARIF结果文件路径
	// 创建报告输出目录
	if err := os.MkdirAll(currentReportDir, 0755); err != nil {
		log.Fatalf("创建输出目录失败: %v", err)
	}

	info("🔍 正在分析数据库...\n")
	if err := codeql.AnalyzeDatabase(cfg.CodeQL.CLIPath, currentDbDir, sarifFile, cfg.CodeQL.Threads, cfg.CodeQL.RAM, allRulesetPaths...); err != nil {
		log.Fatalf("CodeQL 分析失败: %v", err)
	}

	// 6. 解析SARIF分析结果
	info("📊 正在解析扫描结果...\n")
	vulns, err := codeql.ParseSarif(sarifFile)
	if err != nil {
		log.Fatalf("解析 SARIF 文件失败: %v", err)
	}

	// 检查是否发现漏洞
	if len(vulns) > 0 {
		warn("⚠️  发现 %d 个潜在漏洞。\n", len(vulns))
	} else {
		success("✅ 未发现漏洞。\n")
		return // 无漏洞，直接返回
	}

	// 7. AI 验证：对发现的漏洞进行智能验证
	info("🤖 正在启动 AI 验证（并发数：%d）...\n", concurrency)

	// 准备AI模型配置
	var aiModels []struct {
		APIKey  string
		Model   string
		BaseURL string
	}

	// 遍历配置文件中的AI模型
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

	// 创建AI客户端（支持多模型轮询）
	aiClient := ai.NewClient(aiModels)
	ctx := context.Background() // 创建上下文

	// 初始化并发控制和结果存储
	var auditResults []report.AuditResult   // 审计结果列表
	var mutex sync.Mutex                    // 互斥锁，保护共享资源
	var wg sync.WaitGroup                   // 等待组，用于等待所有并发任务完成
	sem := make(chan struct{}, concurrency) // 信号量，控制并发数
	var processedCount int                  // 已处理的漏洞数量

	// 遍历所有漏洞，并发进行AI验证
	for i, v := range vulns {
		wg.Add(1) // 增加等待组计数
		// 启动协程处理每个漏洞
		go func(index int, vuln codeql.Vulnerability) {
			defer wg.Done() // 协程结束时减少等待组计数

			sem <- struct{}{}        // 获取信号量，控制并发
			defer func() { <-sem }() // 协程结束时释放信号量

			// 调用AI客户端验证漏洞
			valResult, err := aiClient.ValidateVulnerability(ctx, vuln, targetDir)

			// 生成Payload（如果需要）
			var payload string
			var payloadErr error
			if err == nil && valResult != nil && valResult.IsReal && cfg.Report.IncludePayload {
				// 使用完整的代码上下文和路由信息生成更准确的Payload
				payload, payloadErr = aiClient.GeneratePayload(ctx, vuln, valResult.FullCodeContext, valResult.RouteInfo)
			}

			// 加锁保护共享资源
			mutex.Lock()
			defer mutex.Unlock()
			processedCount++ // 更新已处理数量

			// 输出验证结果
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
				// 如果可用，从验证结果中填充代码片段
				if valResult.CodeSnippet != "" {
					vuln.CodeSnippet = valResult.CodeSnippet
				}
			}

			// 输出Payload生成结果
			if valResult != nil && valResult.IsReal && cfg.Report.IncludePayload {
				info("💣 正在生成 Payload...\n")
				if payloadErr != nil {
					warn("❌ Payload 生成失败: %v\n", payloadErr)
				} else {
					success("✅ Payload 生成成功。\n")
				}
			}

			// 将结果添加到审计结果列表
			auditResults = append(auditResults, report.AuditResult{
				Vulnerability: vuln,      // 漏洞信息
				Validation:    valResult, // 验证结果
				Payload:       payload,   // 生成的Payload
			})
		}(i, v) // 传递索引和漏洞对象到协程
	}
	wg.Wait() // 等待所有协程完成

	// 8. 生成并导出报告
	info("📄 正在导出报告...\n")
	rep := &report.Report{
		Language: language,     // 源代码语言
		Results:  auditResults, // 审计结果
	}

	// 导出报告到不同格式
	for _, format := range cfg.Report.Formats {
		if format == "json" {
			// 导出JSON格式报告
			if err := rep.ExportJSON(currentReportDir); err != nil {
				log.Printf("导出 JSON 失败: %v", err)
			}
		} else if format == "html" {
			// 导出HTML格式报告
			if err := rep.ExportHTML(currentReportDir); err != nil {
				log.Printf("导出 HTML 失败: %v", err)
			}
		}
	}

	// 显示审计完成信息
	success("✨ 审计完成！报告已保存至: %s\n", currentReportDir)
}
