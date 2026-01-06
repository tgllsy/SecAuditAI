// Package report 实现了报告生成功能，支持生成JSON和HTML格式的审计报告
package report

import (
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"time"
)

// ReportStats 保存报告的统计信息结构体
// 包含漏洞总数、确认真实漏洞数、疑似误报数和报告生成日期

type ReportStats struct {
	TotalVulnerabilities  int     // 总检出漏洞数
	ConfirmedReal         int     // 确认真实漏洞数
	FalsePositives        int     // 疑似误报/低风险漏洞数
	ConfirmedRealPercent  float64 // 确认真实漏洞百分比
	FalsePositivesPercent float64 // 疑似误报百分比
	GeneratedDate         string  // 报告生成日期和时间
}

// CalculateStats 计算报告的统计信息
// 遍历所有审计结果，统计真实漏洞和疑似误报的数量
// 返回：
//   ReportStats - 包含统计信息的结构体

func (r *Report) CalculateStats() ReportStats {
	stats := ReportStats{
		TotalVulnerabilities: len(r.Results),                           // 总漏洞数为结果列表长度
		GeneratedDate:        time.Now().Format("2006-01-02 15:04:05"), // 生成当前时间
	}
	// 遍历结果，统计确认真实漏洞数
	for _, res := range r.Results {
		if res.Validation != nil && res.Validation.IsReal {
			stats.ConfirmedReal++
		}
	}
	// 计算疑似误报数
	stats.FalsePositives = stats.TotalVulnerabilities - stats.ConfirmedReal
	// 计算百分比
	if stats.TotalVulnerabilities > 0 {
		stats.ConfirmedRealPercent = float64(stats.ConfirmedReal) / float64(stats.TotalVulnerabilities) * 100
		stats.FalsePositivesPercent = float64(stats.FalsePositives) / float64(stats.TotalVulnerabilities) * 100
	}
	return stats
}

// ExportJSON 导出报告为JSON格式
// 将审计结果序列化为JSON格式，保存到指定目录
// 参数：
//   outputDir - 报告输出目录
// 返回：
//   error - 如果导出失败则返回错误信息

func (r *Report) ExportJSON(outputDir string) error {
	// 创建输出目录（如果不存在）
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return err
	}

	// 构建输出文件路径
	filePath := filepath.Join(outputDir, "audit_report.json")
	// 创建文件
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close() // 确保文件在函数结束时关闭

	// 创建JSON编码器，设置缩进格式
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ") // 使用两个空格缩进，便于阅读
	// 编码并写入文件
	return encoder.Encode(r)
}

// ExportHTML 导出报告为HTML格式
// 使用HTML模板生成包含统计信息、漏洞列表和AI分析的可视化报告
// 参数：
//   outputDir - 报告输出目录
// 返回：
//   error - 如果导出失败则返回错误信息

func (r *Report) ExportHTML(outputDir string) error {
	// 创建输出目录（如果不存在）
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return err
	}

	// 构建输出文件路径
	filePath := filepath.Join(outputDir, "audit_report.html")
	// 创建文件
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close() // 确保文件在函数结束时关闭

	// 解析HTML模板
	tmpl, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("解析HTML模板失败: %w", err)
	}

	// 构建模板数据
	data := struct {
		Stats    ReportStats   // 报告统计信息
		Language string        // 源代码语言
		Results  []AuditResult // 审计结果列表
	}{
		Stats:    r.CalculateStats(), // 计算统计信息
		Language: r.Language,         // 设置语言
		Results:  r.Results,          // 审计结果
	}

	// 执行模板并写入文件
	return tmpl.Execute(file, data)
}

// htmlTemplate 是HTML报告的模板
// 使用现代化设计和交互效果，包含统计面板、数据可视化和漏洞详情展示

const htmlTemplate = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>自动化代码审计报告</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap-icons/1.10.5/font/bootstrap-icons.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.7.0/styles/github-dark.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/dompurify@3.0.3/dist/purify.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.7.0/highlight.min.js"></script>
    <style>
        body { background-color: #f8f9fa; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
        .card { border: none; box-shadow: 0 2px 5px rgba(0,0,0,0.05); margin-bottom: 20px; }
        .vuln-header { cursor: pointer; transition: background-color 0.2s; }
        .vuln-header:hover { background-color: #f1f3f5; }
        .vuln-header-high { background-color: #fff5f5; border-left: 4px solid #dc3545; }
        .vuln-header-low { background-color: #f1fff5; border-left: 4px solid #28a745; }
        .badge-real { background-color: #dc3545; color: white; }
        .badge-safe { background-color: #28a745; color: white; }
        pre { background-color: #2d2d2d; color: #ccc; padding: 15px; border-radius: 5px; max-height: 400px; overflow: auto; white-space: pre-wrap; word-wrap: break-word; overflow-wrap: break-word; }
        .markdown-body { font-size: 0.95rem; line-height: 1.6; word-wrap: break-word; overflow-wrap: break-word; }
        .markdown-body h3 { font-size: 1.1rem; margin-top: 15px; font-weight: bold; }
        .markdown-body ul { padding-left: 20px; }
        .markdown-body code { background-color: #f0f0f0; padding: 2px 4px; border-radius: 3px; font-family: monospace; color: #d63384; }
        .markdown-body pre code { background-color: transparent; color: inherit; padding: 0; white-space: pre-wrap; word-wrap: break-word; overflow-wrap: break-word; }
        .markdown-body pre { background-color: #2d2d2d; color: #ccc; padding: 10px; border-radius: 5px; overflow-x: auto; white-space: pre-wrap; word-wrap: break-word; overflow-wrap: break-word; }
    </style>
</head>
<body>
    <nav class="navbar navbar-dark bg-dark mb-4">
        <div class="container">
            <span class="navbar-brand mb-0 h1">🛡️ 自动化代码审计报告</span>
            <span class="text-light">{{.Stats.GeneratedDate}}</span>
        </div>
    </nav>

    <div class="container">
        
        <div class="row mb-4">
            <div class="col-md-4">
                <div class="card text-center text-white bg-primary h-100">
                    <div class="card-body">
                        <h5 class="card-title">总检出漏洞</h5>
                        <p class="display-4">{{.Stats.TotalVulnerabilities}}</p>
                    </div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="card text-center text-white bg-danger h-100">
                    <div class="card-body">
                        <h5 class="card-title">确认真实漏洞</h5>
                        <p class="display-4">{{.Stats.ConfirmedReal}}</p>
                    </div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="card text-center text-white bg-success h-100">
                    <div class="card-body">
                        <h5 class="card-title">疑似误报/低风险</h5>
                        <p class="display-4">{{.Stats.FalsePositives}}</p>
                    </div>
                </div>
            </div>
        </div>

        
        <div class="mb-3">
            <div class="btn-group" role="group">
                <button type="button" class="btn btn-outline-primary active" onclick="filterVulns('all', this)">全部</button>
                <button type="button" class="btn btn-outline-danger" onclick="filterVulns('real', this)">真实漏洞</button>
                <button type="button" class="btn btn-outline-success" onclick="filterVulns('safe', this)">疑似误报</button>
            </div>
        </div>

        
        
        <div id="vuln-list">
            {{range $index, $result := .Results}}
            <div class="card vuln-card" data-type="{{if and .Validation .Validation.IsReal}}real{{else}}safe{{end}}">
                <div class="card-header vuln-header d-flex justify-content-between align-items-center {{if and .Validation .Validation.IsReal}}vuln-header-high{{else}}vuln-header-low{{end}}" data-bs-toggle="collapse" data-bs-target="#collapse-{{$index}}">
                    <div>
                        
                            {{if and .Validation .Validation.IsReal}}
                                <span class="badge badge-real me-2">真实漏洞</span>
                                <span class="badge bg-danger text-light me-2">高危</span>
                            {{else}}
                                <span class="badge badge-safe me-2">疑似误报</span>
                                <span class="badge bg-success text-light me-2">低危</span>
                            {{end}}
                        
                        <strong>{{.Vulnerability.RuleID}}</strong>
                        <span class="text-muted ms-2 small">{{.Vulnerability.Location.File}}:{{.Vulnerability.Location.Line}}</span>
                    </div>
                    <i class="bi bi-chevron-down"></i>
                </div>
                <div id="collapse-{{$index}}" class="collapse">
                    <div class="card-body">
                        <div>
                            <h6>原始漏洞信息</h6>
                            <p><strong>消息：</strong>{{.Vulnerability.Message}}</p>
                            {{if and .Validation .Validation.RouteInfo}}
                            <p><strong>API 路由：</strong><code class="text-primary">{{.Validation.RouteInfo}}</code></p>
                            {{end}}
                            
                            {{if or .Vulnerability.Source .Vulnerability.Sink}}
                            <h6>污点追踪 (Data Flow)</h6>
                            <div class="mb-3">
                                {{if .Vulnerability.Source}}
                                <div class="d-flex align-items-center mb-1">
                                    <span class="badge bg-info text-dark me-2" style="width: 60px;">Source</span>
                                    <small class="text-break">{{.Vulnerability.Source.File}}:{{.Vulnerability.Source.Line}}</small>
                                </div>
                                {{end}}
                                
                                {{if .Vulnerability.Sink}}
                                <div class="d-flex align-items-center">
                                    <span class="badge bg-danger me-2" style="width: 60px;">Sink</span>
                                    <small class="text-break">{{.Vulnerability.Sink.File}}:{{.Vulnerability.Sink.Line}}</small>
                                </div>
                                {{end}}
                            </div>
                            {{end}}

                            <h6>代码片段</h6>
                            <pre><code class="language-{{$.Language}}">{{if and .Validation .Validation.FullCodeContext}}{{.Validation.FullCodeContext}}{{else}}{{.Vulnerability.CodeSnippet}}{{end}}</code></pre>

                            {{if .Validation}}
                                <h6 class="mt-3">🤖 AI 智能分析</h6>
                                
                                <div class="mb-2">
                                    <span class="badge {{if .Validation.IsReal}}bg-danger{{else}}bg-success{{end}} text-light me-2">
                                        判定结果: {{if .Validation.IsReal}}真实漏洞{{else}}疑似误报{{end}}
                                    </span>
                                    <span class="badge bg-warning text-dark me-2">
                                        触发参数: {{if .Validation.VulnerableParameter}}{{.Validation.VulnerableParameter}}{{else}}无{{end}}
                                    </span>
                                    <span class="badge {{if .Validation.IsReal}}bg-danger{{else}}bg-success{{end}} text-light">
                                        风险等级: {{if .Validation.IsReal}}高危{{else}}低危{{end}}
                                    </span>
                                </div>
                                
                                <div class="alert {{if .Validation.IsReal}}alert-danger{{else}}alert-success{{end}} markdown-body-raw" style="display:none;">{{.Validation.Reason}}</div>
                                <div class="alert {{if .Validation.IsReal}}alert-danger{{else}}alert-success{{end}} markdown-body"></div>
                            {{end}}

                            {{if .Payload}}
                                <h6 class="mt-3">💣 验证 Payload (PoC)</h6>
                                <div class="bg-light p-3 rounded border markdown-body-raw" style="display:none;">{{.Payload}}</div>
                                <div class="bg-light p-3 rounded border markdown-body"></div>
                            {{end}}
                        </div>
                    </div>
                </div>
            </div>
            {{else}}
            <div class="alert alert-info" role="alert">
                未发现任何漏洞
            </div>
            {{end}}
        </div>
    </div>

    <script>
        // Filter vulnerabilities
        function filterVulns(type, btn) {
            const vulnCards = document.querySelectorAll('.vuln-card');
            vulnCards.forEach(card => {
                if (type === 'all' || card.dataset.type === type) {
                    card.style.display = 'block';
                } else {
                    card.style.display = 'none';
                }
            });
            
            // Update active button
            document.querySelectorAll('.btn-group button').forEach(b => b.classList.remove('active'));
            if (btn) {
                btn.classList.add('active');
            }
        }

        // Render Markdown content
        function renderMarkdown() {
            const rawElements = document.querySelectorAll('.markdown-body-raw');
            rawElements.forEach(element => {
                const content = element.textContent;
                const target = element.nextElementSibling;
                target.innerHTML = marked.parse(content);
            });
        }

        // Initialize the page when DOM is loaded
        document.addEventListener('DOMContentLoaded', function() {
            renderMarkdown();

            if (window.hljs) {
                document.querySelectorAll('pre code').forEach(function (block) {
                    hljs.highlightElement(block);
                });
            }
        });
    </script>
</body>
</html>`
