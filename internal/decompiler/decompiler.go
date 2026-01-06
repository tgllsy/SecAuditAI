package decompiler

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/fatih/color"
)

// Decompiler 处理反编译逻辑
type Decompiler struct {
	JadxPath string // Jadx可执行文件路径
}

// NewDecompiler 创建新的反编译处理器
// 参数:
//
//	jadxPath - Jadx可执行文件路径
func NewDecompiler(jadxPath string) *Decompiler {
	return &Decompiler{
		JadxPath: jadxPath,
	}
}

// IsArchive 检查文件是否为支持的归档格式 (jar, war, apk)
// 参数:
//
//	path - 文件路径
func (d *Decompiler) IsArchive(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".jar" || ext == ".war" || ext == ".apk"
}

// Decompile 执行反编译
// 参数:
//
//	srcPath - 源文件路径
//	outDir - 输出目录
func (d *Decompiler) Decompile(srcPath, outDir string) error {
	jadxPath := d.JadxPath

	// 如果没有指定路径，尝试在环境变量中查找
	if jadxPath == "" {
		// 尝试直接查找 jadx 命令
		path, err := exec.LookPath("jadx")
		if err == nil {
			jadxPath = path
		} else {
			return fmt.Errorf("未配置Jadx路径，且在系统PATH中未找到jadx")
		}
	}

	// 检查路径是否存在
	stat, err := os.Stat(jadxPath)
	if err != nil {
		// 如果是 Windows，可能需要加上 .bat (如果用户没加)
		if runtime.GOOS == "windows" {
			if _, err := os.Stat(jadxPath + ".bat"); err == nil {
				jadxPath += ".bat"
				stat, _ = os.Stat(jadxPath)
			}
		} else {
			// Linux/Mac 下可能是 jadx 脚本
			if _, err := os.Stat(jadxPath); err != nil {
				// 尝试查找是否有同名文件但没给绝对路径的情况（虽然通常不会）
			}
		}
	}

	// 再次检查是否存在
	if _, err := os.Stat(jadxPath); err != nil {
		return fmt.Errorf("jadx文件不存在: %s", jadxPath)
	}

	// 如果是目录，尝试在其中寻找可执行文件
	if stat != nil && stat.IsDir() {
		possibleExes := []string{"jadx"}
		if runtime.GOOS == "windows" {
			possibleExes = []string{"jadx.bat", "jadx.exe"}
		} else {
			possibleExes = []string{"jadx", "jadx.sh"}
		}

		found := false
		for _, exe := range possibleExes {
			// 1. 尝试直接在目录下查找
			tryPath := filepath.Join(jadxPath, exe)
			if s, err := os.Stat(tryPath); err == nil && !s.IsDir() {
				jadxPath = tryPath
				found = true
				break
			}
			// 2. 尝试在 bin 子目录下查找
			tryPath = filepath.Join(jadxPath, "bin", exe)
			if s, err := os.Stat(tryPath); err == nil && !s.IsDir() {
				jadxPath = tryPath
				found = true
				break
			}
		}

		if !found {
			return fmt.Errorf("指定的路径是目录，且未在其中找到Jadx可执行文件: %s", jadxPath)
		}
	}

	info := color.New(color.FgCyan).PrintfFunc()
	info("🔄 正在反编译 %s 到 %s ...\n", srcPath, outDir)

	// jadx -d <outDir> <srcPath>
	// 增加 --no-replace-consts 以保留原始常量，可能有助于分析
	cmd := exec.Command(jadxPath, "-d", outDir, srcPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		// 检查输出目录是否包含文件，如果有文件则认为是部分成功
		if !d.isDirEmpty(outDir) {
			warn := color.New(color.FgYellow).PrintfFunc()
			warn("\n⚠️  反编译过程遇到错误 (exit code %v)，但已生成部分代码。\n", err)
			warn("⚠️  将尝试基于已反编译的代码继续执行审计...\n")
			// 即使部分成功，也进行清理
			d.CleanIrrelevantFiles(outDir)
			return nil
		}
		return fmt.Errorf("反编译失败: %v", err)
	}

	// 反编译成功后，清理无关文件
	if err := d.CleanIrrelevantFiles(outDir); err != nil {
		// 清理失败不应阻断流程，只打印警告
		fmt.Printf("警告: 清理无关文件失败: %v\n", err)
	}

	return nil
}

// CleanIrrelevantFiles 清理反编译结果中的无关文件和目录
// 只保留 .java 文件，删除资源文件和库文件，以提高CodeQL分析速度
// 参数:
//
//	dir - 反编译输出目录
func (d *Decompiler) CleanIrrelevantFiles(dir string) error {
	info := color.New(color.FgCyan).PrintfFunc()
	info("🧹 正在清理无关文件以优化分析速度...\n")

	// 定义要删除的目录名（全小写比较）
	dirsToRemove := map[string]bool{
		"resources": true, "assets": true, "META-INF": true,
		"res": true, "lib": true, "libs": true, "original": true,
		"kotlin": true, "android": true, // 根据情况可能需要删除
	}

	// 遍历目录
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // 忽略访问错误，继续处理其他文件
		}

		// 跳过根目录
		if path == dir {
			return nil
		}

		name := info.Name()

		// 处理目录
		if info.IsDir() {
			if dirsToRemove[strings.ToLower(name)] {
				// 删除目录及其内容
				if err := os.RemoveAll(path); err == nil {
					// 成功删除后跳过该目录
					return filepath.SkipDir
				}
			}
			return nil
		}

		// 处理文件：只保留 .java 文件
		if strings.ToLower(filepath.Ext(path)) != ".java" {
			os.Remove(path)
		}

		return nil
	})
}

// isDirEmpty 检查目录是否为空
func (d *Decompiler) isDirEmpty(name string) bool {
	f, err := os.Open(name)
	if err != nil {
		return true
	}
	defer f.Close()

	// 读取目录中的一个文件
	_, err = f.Readdirnames(1)
	// 如果读取到 EOF，说明目录为空
	return err != nil
}
