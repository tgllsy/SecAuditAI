// Package codeql 实现了CodeQL操作封装，包括数据库创建、分析和结果解析
package codeql

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/secauditai/secauditai/internal/config" // 配置管理模块
)

// CreateDatabase 从源代码创建CodeQL数据库
// 调用CodeQL CLI工具，将指定目录的源代码转换为CodeQL数据库，用于后续分析
// 参数：
//
//	cfg - 配置结构体，包含Maven路径等配置
//	cliPath - CodeQL CLI工具的路径
//	sourcePath - 源代码目录路径
//	dbPath - 数据库输出路径
//	language - 源代码语言（如java、python、go等）
//	threads - 使用的线程数，留空则使用默认值
//	ram - 使用的内存大小(MB)，留空则使用默认值
//	jdkPath - JDK路径，用于Java项目的构建
//	buildModeNone - 是否使用CodeQL的无构建模式(--build-mode=none)
//
// 返回：
//
//	error - 如果创建失败则返回错误信息
func CreateDatabase(cfg *config.Config, cliPath, sourcePath, dbPath, language, threads, ram, jdkPath string, buildModeNone bool) error {
	// 获取源代码绝对路径
	absSourcePath, err := filepath.Abs(sourcePath)
	if err != nil {
		return fmt.Errorf("无法获取源代码绝对路径: %w", err)
	}

	// 构建CodeQL数据库创建命令参数
	// 使用--overwrite选项，如果数据库已存在则覆盖
	args := []string{"database", "create", dbPath,
		"--language=" + language,         // 指定源代码语言
		"--source-root=" + absSourcePath, // 指定源代码根目录
		"--overwrite"}                    // 覆盖已存在的数据库

	// 添加可选参数：线程数
	if threads != "" {
		args = append(args, "--threads="+threads)
	}
	// 添加可选参数：内存大小
	if ram != "" {
		args = append(args, "--ram="+ram)
	}

	// 如果启用无构建模式，则追加对应参数
	if buildModeNone {
		args = append(args, "--build-mode=none")
	}

	// 增加详细日志，帮助排查卡死问题
	// args = append(args, "-vv")

	// 创建并执行命令
	cmd := exec.Command(cliPath, args...)

	// 将命令输出重定向到标准输出和错误输出，便于查看执行过程
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// 如果指定了JDK路径，设置环境变量
	if jdkPath != "" {
		// 获取当前环境变量
		env := os.Environ()

		// 直接获取JAVA_HOME路径（从java.exe路径推断）
		// jdkPath格式：D:\Service\jdk-17.0.12\bin\java.exe
		// jdkBinDir: D:\Service\jdk-17.0.12\bin
		// javaHome: D:\Service\jdk-17.0.12
		jdkBinDir := filepath.Dir(jdkPath)
		javaHome := filepath.Dir(jdkBinDir)

		// 打印调试信息
		fmt.Printf("DEBUG: JDK Path: %s\n", jdkPath)
		fmt.Printf("DEBUG: JDK Bin Dir: %s\n", jdkBinDir)
		fmt.Printf("DEBUG: JAVA_HOME: %s\n", javaHome)

		// 完全替换环境变量列表，确保JAVA_HOME被正确设置
		var newEnv []string
		newEnv = append(newEnv, "JAVA_HOME="+javaHome)

		// 添加其他环境变量，但跳过现有的JAVA_HOME
		for _, e := range env {
			if !strings.HasPrefix(e, "JAVA_HOME=") {
				newEnv = append(newEnv, e)
			}
		}

		// 更新PATH环境变量，将JDK的bin目录放在最前面
		pathUpdated := false
		pathListSep := string(os.PathListSeparator) // 获取系统特定的路径分隔符
		for i, e := range newEnv {
			if strings.HasPrefix(e, "PATH=") {
				pathValue := e[5:]
				newPath := jdkBinDir + pathListSep + pathValue
				newEnv[i] = "PATH=" + newPath
				pathUpdated = true
				break
			}
		}
		if !pathUpdated {
			newEnv = append(newEnv, "PATH="+jdkBinDir)
		}

		// 使用新的环境变量列表
		env = newEnv

		// 从配置中获取Maven路径列表
		mavenPaths := cfg.CodeQL.MavenPaths
		// 检查Maven是否存在
		var mavenBinDir string
		// 根据平台确定Maven可执行文件名
		mvnExe := "mvn"
		if runtime.GOOS == "windows" {
			mvnExe = "mvn.cmd"
		}

		for _, path := range mavenPaths {
			if _, err := os.Stat(filepath.Join(path, mvnExe)); err == nil {
				mavenBinDir = path
				break
			}
		}

		// 从配置中获取Gradle路径列表
		gradlePaths := cfg.CodeQL.GradlePaths
		// 检查Gradle是否存在
		var gradleBinDir string
		// 根据平台确定Gradle可执行文件名
		gradleExe := "gradle"
		if runtime.GOOS == "windows" {
			gradleExe = "gradle.bat"
		}

		for _, path := range gradlePaths {
			if _, err := os.Stat(filepath.Join(path, gradleExe)); err == nil {
				gradleBinDir = path
				break
			}
		}

		// 设置PATH环境变量，将JDK、Maven和Gradle的bin目录放在最前面
		pathFound := false
		for i, e := range env {
			if strings.HasPrefix(e, "PATH=") {
				pathValue := e[5:]
				// 构建新的PATH值
				newPath := jdkBinDir
				if mavenBinDir != "" {
					newPath += pathListSep + mavenBinDir
				}
				if gradleBinDir != "" {
					newPath += pathListSep + gradleBinDir
				}
				newPath += pathListSep + pathValue
				env[i] = "PATH=" + newPath
				pathFound = true
				break
			}
		}
		if !pathFound {
			newPath := jdkBinDir
			if mavenBinDir != "" {
				newPath += pathListSep + mavenBinDir
			}
			if gradleBinDir != "" {
				newPath += pathListSep + gradleBinDir
			}
			env = append(env, "PATH="+newPath)
		}

		// 设置命令的环境变量
		cmd.Env = env
	}

	// 执行命令并处理错误
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("创建CodeQL数据库失败: %w", err)
	}

	return nil
}
