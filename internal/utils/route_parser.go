package utils

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// ExtractRouteInfo 尝试从源文件中提取API路由信息
// 目前主要支持 Java Spring Boot
// 参数:
//   filePath - 源代码文件路径
//   line - 触发点所在的行号（Source Line）
// 返回:
//   string - 提取到的路由信息，格式如 "GET /api/v1/user/login"
func ExtractRouteInfo(filePath string, line int) string {
	ext := strings.ToLower(filepath.Ext(filePath))
	if ext == ".java" {
		return extractSpringRoute(filePath, line)
	}
	// 未来可扩展支持 Go (Gin/Echo), Python (Flask/Django/FastAPI) 等
	return ""
}

// extractSpringRoute 提取Spring Boot路由信息
func extractSpringRoute(filePath string, targetLine int) string {
	file, err := os.Open(filePath)
	if err != nil {
		return ""
	}
	defer file.Close()

	var finalClassPath string
	var potentialClassPath string // 暂存最近遇到的 RequestMapping

	var methodPath string
	var httpMethod string

	// 正则表达式
	// 匹配 @RequestMapping("/common") 或 @RequestMapping(value = "/common")
	// 注意：这里只匹配 value，不做复杂的属性解析
	mappingValueRegex := regexp.MustCompile(`Mapping\s*\(\s*(?:value\s*=\s*)?["']([^"']+)["']`)
	// 匹配注解类型 @GetMapping, @PostMapping, @RequestMapping
	mappingTypeRegex := regexp.MustCompile(`@(Get|Post|Put|Delete|Patch|Request)Mapping`)

	scanner := bufio.NewScanner(file)
	currentLine := 0

	for scanner.Scan() {
		currentLine++
		text := strings.TrimSpace(scanner.Text())
		
		// 忽略注释行
		if strings.HasPrefix(text, "//") || strings.HasPrefix(text, "*") || strings.HasPrefix(text, "/*") {
			continue
		}

		// 1. 查找 Mapping 注解
		if strings.Contains(text, "Mapping") {
			matches := mappingValueRegex.FindStringSubmatch(text)
			typeMatches := mappingTypeRegex.FindStringSubmatch(text)
			
			if len(matches) > 1 && len(typeMatches) > 1 {
				path := matches[1]
				methodType := typeMatches[1] // Get, Post, Request...

				if methodType == "Request" {
					// 可能是类注解，也可能是方法注解
					potentialClassPath = path
				}
				
				// 检查是否是目标方法（Source Line）附近的注解
				// 我们假设注解在方法定义的上方，且距离不远（例如 10 行内）
				// targetLine 通常是方法体内的某一行，或者方法定义行
				if targetLine >= currentLine && targetLine-currentLine < 20 {
					methodPath = path
					httpMethod = strings.ToUpper(methodType)
					if httpMethod == "REQUEST" {
						httpMethod = "ANY"
					}
				}
			}
		}

		// 2. 查找类定义，确定 Class Path
		// 如果遇到了 class 定义，且之前最近的一个 RequestMapping 离得不远，那它就是 Class Path
		if strings.Contains(text, "class ") && strings.Contains(text, "{") {
			// 这里简单判断，只要之前有 potentialClassPath，就认为是它
			// 实际场景中，类注解就在 class 上方
			if potentialClassPath != "" {
				finalClassPath = potentialClassPath
				potentialClassPath = "" // 锁定后清空，避免干扰后续内部类
			}
		}
		
		// 如果超过了目标行太多，就不找了
		if currentLine > targetLine + 5 {
			break
		}
	}

	if methodPath == "" {
		return ""
	}

	// 拼接路径
	fullPath := strings.TrimSuffix(finalClassPath, "/") + "/" + strings.TrimPrefix(methodPath, "/")
	// 清理双斜杠
	fullPath = strings.ReplaceAll(fullPath, "//", "/")

	if httpMethod == "" {
		httpMethod = "ANY"
	}

	return fmt.Sprintf("%s %s", httpMethod, fullPath)
}
