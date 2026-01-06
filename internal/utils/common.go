// Package utils 提供了通用工具函数，用于辅助代码审计工具的各项功能
package utils

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// ReadCodeSnippet 读取文件中特定行及其上下文的代码片段
// 用于获取漏洞所在位置的代码上下文，便于AI分析和报告生成
// 参数：
//   filePath - 文件路径
//   line - 目标行号（从1开始）
//   context - 上下文行数，目标行前后各显示context行
// 返回：
//   string - 读取到的代码片段，包含目标行及其上下文
//   error - 如果读取失败则返回错误信息

func ReadCodeSnippet(filePath string, line int, context int) (string, error) {
	// 打开文件
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close() // 确保文件在函数结束时关闭

	// 创建扫描器
	scanner := bufio.NewScanner(file)
	currentLine := 0   // 当前读取的行号
	var snippet string // 代码片段字符串

	// 计算开始和结束行号
	startLine := line - context // 开始行号
	endLine := line + context   // 结束行号
	// 确保开始行号不小于1
	if startLine < 1 {
		startLine = 1
	}

	// 逐行扫描文件
	for scanner.Scan() {
		currentLine++
		// 如果当前行在目标范围内，添加到代码片段
		if currentLine >= startLine && currentLine <= endLine {
			snippet += scanner.Text() + "\n"
		}
		// 如果当前行超过结束行号，提前退出循环
		if currentLine > endLine {
			break
		}
	}

	// 返回代码片段和可能的扫描错误
	return snippet, scanner.Err()
}

// DetectJavaVersion 检测Java项目需要的Java版本
// 检查pom.xml、build.gradle等构建文件，提取目标Java版本
// 会递归检查所有pom.xml文件，取最高版本
// 参数：
//   projectPath - 项目根目录路径
// 返回：
//   string - 检测到的Java版本，如"8", "11", "17", "21"
//   error - 如果检测失败则返回错误信息
func DetectJavaVersion(projectPath string) (string, error) {
	maxVersion := 0

	// 1. 递归检查所有 pom.xml 文件
	err := filepath.Walk(projectPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // 忽略访问错误
		}
		if !info.IsDir() && info.Name() == "pom.xml" {
			vStr, err := detectJavaVersionFromPom(path)
			if err == nil && vStr != "" {
				v := parseJavaVersion(vStr)
				if v > maxVersion {
					maxVersion = v
				}
			}
		}
		return nil
	})
	if err == nil && maxVersion > 0 {
		return fmt.Sprintf("%d", maxVersion), nil
	}

	// 2. 检查根目录 build.gradle 文件
	gradlePath := filepath.Join(projectPath, "build.gradle")
	if _, err := os.Stat(gradlePath); err == nil {
		vStr, err := detectJavaVersionFromGradle(gradlePath)
		if err == nil && vStr != "" {
			return vStr, nil // Gradle通常在根目录定义，暂不递归
		}
	}

	// 3. 检查根目录 build.gradle.kts 文件
	gradleKtsPath := filepath.Join(projectPath, "build.gradle.kts")
	if _, err := os.Stat(gradleKtsPath); err == nil {
		vStr, err := detectJavaVersionFromGradleKts(gradleKtsPath)
		if err == nil && vStr != "" {
			return vStr, nil
		}
	}

	// 4. 检查 .settings 目录
	settingsPath := filepath.Join(projectPath, ".settings")
	if _, err := os.Stat(settingsPath); err == nil {
		vStr, err := detectJavaVersionFromSettings(settingsPath)
		if err == nil && vStr != "" {
			return vStr, nil
		}
	}

	// 默认返回Java 8
	return "8", nil
}

// parseJavaVersion 将版本字符串转换为整数，如 "1.8"->8, "17"->17
func parseJavaVersion(v string) int {
	v = strings.TrimSpace(v)
	// 处理 1.8 格式
	if strings.HasPrefix(v, "1.") && len(v) > 2 {
		v = v[2:]
	}
	// 处理 17.0.1 格式
	if idx := strings.Index(v, "."); idx != -1 {
		v = v[:idx]
	}
	var ver int
	fmt.Sscanf(v, "%d", &ver)
	return ver
}

// detectJavaVersionFromPom 从pom.xml中检测Java版本
func detectJavaVersionFromPom(pomPath string) (string, error) {
	file, err := os.Open(pomPath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var content string
	for scanner.Scan() {
		content += scanner.Text() + "\n"
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}

	// 增强的正则表达式
	// 支持 <java.version>17</java.version>, <source>1.8</source> 等
	// 同时也支持 properties 中的定义
	regexes := []string{
		`<(?:maven\.compiler\.source|source|target|release|java\.version)>.*?((?:1\.)?[0-9]+).*?</(?:maven\.compiler\.source|source|target|release|java\.version)>`,
		`maven\.compiler\.source.*?((?:1\.)?[0-9]+)`,
		`maven\.compiler\.target.*?((?:1\.)?[0-9]+)`,
	}

	for _, regex := range regexes {
		r := regexp.MustCompile(regex)
		matches := r.FindStringSubmatch(content)
		if len(matches) > 1 {
			// 归一化版本号
			return normalizeVersionString(matches[1]), nil
		}
	}

	return "", fmt.Errorf("无法从pom.xml中检测Java版本")
}

func normalizeVersionString(v string) string {
	if strings.HasPrefix(v, "1.") && len(v) > 2 {
		return v[2:]
	}
	return v
}

// detectJavaVersionFromGradle 从build.gradle中检测Java版本
func detectJavaVersionFromGradle(gradlePath string) (string, error) {
	// 打开build.gradle文件
	file, err := os.Open(gradlePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	// 读取文件内容
	scanner := bufio.NewScanner(file)
	var content string
	for scanner.Scan() {
		content += scanner.Text() + "\n"
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}

	// 正则表达式匹配Java版本
	regexes := []string{
		`sourceCompatibility.*?([89]|1[0-9]|2[0-1])`,
		`targetCompatibility.*?([89]|1[0-9]|2[0-1])`,
		`java\.version.*?([89]|1[0-9]|2[0-1])`,
		`release.*?([89]|1[0-9]|2[0-1])`,
		`source.*?([89]|1[0-9]|2[0-1])`,
		`target.*?([89]|1[0-9]|2[0-1])`,
	}

	for _, regex := range regexes {
		r := regexp.MustCompile(regex)
		matches := r.FindStringSubmatch(content)
		if len(matches) > 1 {
			return matches[1], nil
		}
	}

	return "", fmt.Errorf("无法从build.gradle中检测Java版本")
}

// detectJavaVersionFromGradleKts 从build.gradle.kts中检测Java版本
func detectJavaVersionFromGradleKts(gradleKtsPath string) (string, error) {
	// 打开build.gradle.kts文件
	file, err := os.Open(gradleKtsPath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	// 读取文件内容
	scanner := bufio.NewScanner(file)
	var content string
	for scanner.Scan() {
		content += scanner.Text() + "\n"
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}

	// 正则表达式匹配Java版本
	regexes := []string{
		`sourceCompatibility.*?([89]|1[0-9]|2[0-1])`,
		`targetCompatibility.*?([89]|1[0-9]|2[0-1])`,
		`java\.version.*?([89]|1[0-9]|2[0-1])`,
		`release.*?([89]|1[0-9]|2[0-1])`,
		`source.*?([89]|1[0-9]|2[0-1])`,
		`target.*?([89]|1[0-9]|2[0-1])`,
	}

	for _, regex := range regexes {
		r := regexp.MustCompile(regex)
		matches := r.FindStringSubmatch(content)
		if len(matches) > 1 {
			return matches[1], nil
		}
	}

	return "", fmt.Errorf("无法从build.gradle.kts中检测Java版本")
}

// detectJavaVersionFromSettings 从.settings目录下的文件中检测Java版本
func detectJavaVersionFromSettings(settingsPath string) (string, error) {
	// 检查org.eclipse.jdt.core.prefs文件
	prefsPath := filepath.Join(settingsPath, "org.eclipse.jdt.core.prefs")
	if _, err := os.Stat(prefsPath); err != nil {
		return "", err
	}

	// 打开文件
	file, err := os.Open(prefsPath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	// 读取文件内容
	scanner := bufio.NewScanner(file)
	var content string
	for scanner.Scan() {
		content += scanner.Text() + "\n"
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}

	// 正则表达式匹配Java版本
	r := regexp.MustCompile(`org\.eclipse\.jdt\.core\.compiler\.source.*?([89]|1[0-9]|2[0-1])`)
	matches := r.FindStringSubmatch(content)
	if len(matches) > 1 {
		return matches[1], nil
	}

	return "", fmt.Errorf("无法从.settings中检测Java版本")
}

// SelectJDK 根据Java版本选择合适的JDK路径
// 参数：
//   jdkConfig - JDK配置，包含版本映射
//   javaVersion - 目标Java版本，如"8", "11", "17", "21"
// 返回：
//   string - 选择的JDK路径
//   error - 如果选择失败则返回错误信息

func SelectJDK(jdkConfig map[string]string, javaVersion string, defaultJDK string) (string, error) {
	// 尝试直接匹配版本，如javaVersion为"8"，则尝试jdk8
	directKey := "jdk" + javaVersion
	if path, ok := jdkConfig[directKey]; ok {
		return path, nil
	}

	// 尝试匹配主要版本，如javaVersion为"11.0.12"，则尝试jdk11
	majorVersion := strings.Split(javaVersion, ".")[0]
	majorKey := "jdk" + majorVersion
	if path, ok := jdkConfig[majorKey]; ok {
		return path, nil
	}

	// 使用默认JDK
	if defaultJDK != "" {
		if path, ok := jdkConfig[defaultJDK]; ok {
			return path, nil
		}
	}

	// 尝试使用jdk8作为最后的fallback
	if path, ok := jdkConfig["jdk8"]; ok {
		return path, nil
	}

	return "", fmt.Errorf("无法找到合适的JDK路径")
}
