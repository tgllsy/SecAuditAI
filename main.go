// Package main 是程序的入口点，定义了命令行工具的基本结构
package main

import (
	"fmt"
	"os"

	// audit 包包含审计命令的核心逻辑
	"github.com/secauditai/secauditai/cmd/audit"
	"github.com/secauditai/secauditai/cmd/verify"

	// verify 包包含直接验证 SARIF 文件的命令

	// cobra 用于构建命令行界面
	"github.com/spf13/cobra"
)

// main 函数是程序的入口点，初始化并执行命令行工具
func main() {
	// 定义根命令
	var rootCmd = &cobra.Command{
		Use:   "secauditai",
		Short: "自动化代码审计工具",
		Long:  `SecAuditAI - 一个集成 CodeQL 和 AI 的自动化代码审计与漏洞验证工具。`,
		// 禁用自动生成completion命令
		CompletionOptions: cobra.CompletionOptions{
			DisableDefaultCmd: true,
		},
	}

	// 添加审计命令
	rootCmd.AddCommand(audit.Cmd)
	// 添加验证命令
	rootCmd.AddCommand(verify.Cmd)

	// 添加版本命令
	rootCmd.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "打印版本号",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("SecAuditAI 版本 1.0.4")
		},
	})

	// 执行命令并处理错误
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
