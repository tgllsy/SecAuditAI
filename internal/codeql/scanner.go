// Package codeql 实现了CodeQL操作封装，包括数据库创建、分析和结果解析
package codeql

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
)

// Vulnerability 是简化的漏洞内部表示结构体
// 包含漏洞的基本信息、位置、代码片段以及数据流的源和汇

type Vulnerability struct {
	RuleID      string     `json:"rule"`                 // 漏洞规则ID
	Message     string     `json:"message"`              // 漏洞描述信息
	Location    Location   `json:"location"`             // 漏洞位置
	CodeSnippet string     `json:"codeSnippet"`          // 漏洞相关代码片段
	Source      *Endpoint  `json:"source,omitempty"`     // 数据流的源点（用户输入等）
	Sink        *Endpoint  `json:"sink,omitempty"`       // 数据流的汇点（危险函数等）
	FlowSteps   []Endpoint `json:"flow_steps,omitempty"` // 数据流的所有步骤（包含Source、中间步骤、Sink）
}

// Endpoint 表示数据流中的端点（源或汇）
type Endpoint struct {
	File string `json:"file"` // 端点所在文件
	Line int    `json:"line"` // 端点所在行号
}

// Location 表示漏洞在代码中的具体位置

type Location struct {
	File   string `json:"file"`   // 漏洞所在文件
	Line   int    `json:"line"`   // 漏洞所在行号
	Column int    `json:"column"` // 漏洞所在列号
}

// SarifLog 是SARIF（静态分析结果交换格式）的顶层结构体
// 包含一个或多个分析运行结果

type SarifLog struct {
	Runs []SarifRun `json:"runs"` // 分析运行结果列表
}

// SarifRun 表示一次SARIF分析运行的结果

type SarifRun struct {
	Results []SarifResult `json:"results"` // 本次运行发现的结果列表
}

// SarifResult 表示SARIF分析中的一个结果（通常是一个漏洞）

type SarifResult struct {
	RuleID  string `json:"ruleId"` // 结果对应的规则ID
	Message struct {
		Text string `json:"text"` // 结果描述文本
	} `json:"message"`
	Locations []struct {
		PhysicalLocation SarifPhysicalLocation `json:"physicalLocation"` // 结果的物理位置
	} `json:"locations"`
	CodeFlows []SarifCodeFlow `json:"codeFlows"` // 数据流信息
}

// SarifCodeFlow 表示SARIF中的代码流信息

type SarifCodeFlow struct {
	ThreadFlows []SarifThreadFlow `json:"threadFlows"` // 线程流列表
}

// SarifThreadFlow 表示SARIF中的线程流

type SarifThreadFlow struct {
	Locations []SarifThreadFlowLocation `json:"locations"` // 线程流中的位置列表
}

// SarifThreadFlowLocation 表示线程流中的一个位置

type SarifThreadFlowLocation struct {
	Location struct {
		PhysicalLocation SarifPhysicalLocation `json:"physicalLocation"` // 物理位置
	} `json:"location"`
}

// SarifPhysicalLocation 表示SARIF中的物理位置信息

type SarifPhysicalLocation struct {
	ArtifactLocation struct {
		URI string `json:"uri"` // 文件URI
	} `json:"artifactLocation"`
	Region struct {
		StartLine   int `json:"startLine"`   // 起始行号
		StartColumn int `json:"startColumn"` // 起始列号
	} `json:"region"`
}

// AnalyzeDatabase 执行CodeQL数据库分析
// 调用CodeQL CLI工具，使用指定的规则集对数据库进行分析，生成SARIF格式的结果文件
// 参数：
//   cliPath - CodeQL CLI工具的路径
//   dbPath - 数据库路径
//   outputPath - 输出结果文件路径（SARIF格式）
//   threads - 使用的线程数，留空则使用默认值
//   ram - 使用的内存大小(MB)，留空则使用默认值
//   rulesetPaths - 规则集路径列表，支持多个规则集
// 返回：
//   error - 如果分析失败则返回错误信息

func AnalyzeDatabase(cliPath, dbPath, outputPath, threads, ram string, rulesetPaths ...string) error {
	// 构建CodeQL数据库分析命令参数
	args := []string{"database", "analyze", dbPath}

	// 添加所有规则集路径
	args = append(args, rulesetPaths...)

	// 添加格式和输出参数
	args = append(args, "--format=sarif-latest", "--output="+outputPath)

	// 添加可选参数：线程数
	if threads != "" {
		args = append(args, "--threads="+threads)
	}
	// 添加可选参数：内存大小
	if ram != "" {
		args = append(args, "--ram="+ram)
	}

	// 创建并执行命令
	cmd := exec.Command(cliPath, args...)

	// 将命令输出重定向到标准输出和错误输出，便于查看执行过程
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// 执行命令并处理错误
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("分析数据库失败: %w", err)
	}

	return nil
}

// ParseSarif 解析SARIF格式的分析结果文件
// 将SARIF格式的分析结果转换为内部的Vulnerability结构体列表
// 参数：
//   sarifPath - SARIF文件路径
// 返回：
//   []Vulnerability - 解析出的漏洞列表
//   error - 如果解析失败则返回错误信息

func ParseSarif(sarifPath string) ([]Vulnerability, error) {
	// 打开SARIF文件
	file, err := os.Open(sarifPath)
	if err != nil {
		return nil, fmt.Errorf("打开SARIF文件失败: %w", err)
	}
	defer file.Close() // 确保文件在函数结束时关闭

	// 解析SARIF文件为SarifLog结构体
	var log SarifLog
	if err := json.NewDecoder(file).Decode(&log); err != nil {
		return nil, fmt.Errorf("解析SARIF文件失败: %w", err)
	}

	// 初始化漏洞列表
	var vulns []Vulnerability
	// 遍历所有分析运行结果
	for _, run := range log.Runs {
		// 遍历每个分析结果
		for _, result := range run.Results {
			// 创建漏洞结构体
			vuln := Vulnerability{
				RuleID:  result.RuleID,
				Message: result.Message.Text,
			}

			// 提取漏洞位置
			if len(result.Locations) > 0 {
				loc := result.Locations[0].PhysicalLocation
				vuln.Location = Location{
					File:   loc.ArtifactLocation.URI,
					Line:   loc.Region.StartLine,
					Column: loc.Region.StartColumn,
				}
			}

			// 从CodeFlows中提取Source和Sink及完整路径
			if len(result.CodeFlows) > 0 && len(result.CodeFlows[0].ThreadFlows) > 0 {
				tf := result.CodeFlows[0].ThreadFlows[0]

				// 提取所有步骤
				for _, loc := range tf.Locations {
					pl := loc.Location.PhysicalLocation
					vuln.FlowSteps = append(vuln.FlowSteps, Endpoint{
						File: pl.ArtifactLocation.URI,
						Line: pl.Region.StartLine,
					})
				}

				if len(tf.Locations) > 0 {
					// Source通常是第一个位置
					srcLoc := tf.Locations[0].Location.PhysicalLocation
					vuln.Source = &Endpoint{
						File: srcLoc.ArtifactLocation.URI,
						Line: srcLoc.Region.StartLine,
					}

					// Sink通常是最后一个位置
					sinkLoc := tf.Locations[len(tf.Locations)-1].Location.PhysicalLocation
					vuln.Sink = &Endpoint{
						File: sinkLoc.ArtifactLocation.URI,
						Line: sinkLoc.Region.StartLine,
					}
				}
			}

			// 注意：代码片段提取需要读取源文件或解析SARIF中的'contextRegion'
			// 目前我们将其留空，由后续步骤处理
			vulns = append(vulns, vuln)
		}
	}

	return vulns, nil
}
