// Package config 实现了配置加载与管理功能
// 使用viper库从YAML文件和环境变量中加载配置
package config

import (
	"fmt"
	"strings"

	"github.com/spf13/viper" // viper库用于配置管理
)

// ToolConfig 定义了工具的基本信息结构体
// 包含工具的名称和版本信息

type ToolConfig struct {
	Name    string `mapstructure:"name"`    // 工具名称
	Version string `mapstructure:"version"` // 工具版本号
}

// CodeQLConfig 定义了CodeQL相关的配置结构体
// 包含CodeQL CLI的路径、数据库存储目录、规则集路径等

type CodeQLConfig struct {
	CLIPath     string                `mapstructure:"cli_path"`     // CodeQL CLI可执行文件路径
	DatabaseDir string                `mapstructure:"database_dir"` // 数据库存储目录
	RepoPath    string                `mapstructure:"repo_path"`    // 规则集仓库根路径（可选）
	Threads     string                `mapstructure:"threads"`      // 使用的线程数，"0"表示使用所有核心
	RAM         string                `mapstructure:"ram"`          // 使用的内存限制（MB）
	MavenPaths  []string              `mapstructure:"maven_paths"`  // Maven可执行文件路径列表
	GradlePaths []string              `mapstructure:"gradle_paths"` // Gradle可执行文件路径列表
	Languages   map[string]LangConfig `mapstructure:"languages"`    // 语言特定配置映射
}

// LangConfig 定义了特定语言的规则集配置结构体
// 包含主规则集和额外规则集的路径

type LangConfig struct {
	Ruleset            string   `mapstructure:"ruleset"`             // 主规则集路径
	AdditionalRulesets []string `mapstructure:"additional_rulesets"` // 额外规则集路径列表
}

// AIModelConfig 定义了单个AI模型的配置结构体
// 包含AI提供商信息、API密钥、模型名称等
type AIModelConfig struct {
	Provider string `mapstructure:"provider"` // AI提供商API地址（如"https://api.siliconflow.cn/v1"）
	APIKey   string `mapstructure:"api_key"`  // API密钥，用于认证
	Model    string `mapstructure:"model"`    // 使用的模型名称
}

// AIConfig 定义了AI模型相关的配置结构体
// 包含AI模型列表、温度和最大令牌数等全局配置
type AIConfig struct {
	// 单模型配置（旧格式，兼容）
	Provider string `mapstructure:"provider"` // AI提供商API地址
	APIKey   string `mapstructure:"api_key"`  // API密钥
	Model    string `mapstructure:"model"`    // 模型名称

	// 多模型配置（新格式，支持轮询）
	Models      []AIModelConfig `mapstructure:"models"`      // AI模型配置列表，支持轮询
	Temperature float64         `mapstructure:"temperature"` // 生成温度，控制输出的随机性（0-2）
	MaxTokens   int             `mapstructure:"max_tokens"`  // 最大生成Token数，限制输出长度
}

// ReportConfig 定义了报告生成的配置结构体
// 包含报告的输出目录、格式和是否包含Payload等

type ReportConfig struct {
	OutputDir      string   `mapstructure:"output_dir"`      // 默认报告输出目录
	Formats        []string `mapstructure:"formats"`         // 报告输出格式列表（如html、json）
	IncludePayload bool     `mapstructure:"include_payload"` // 是否在报告中包含Payload
}

// JDKConfig 定义了JDK相关的配置结构体
// 包含JDK版本映射和默认JDK版本

type JDKConfig struct {
	Versions map[string]string `mapstructure:"versions"` // JDK版本映射，如jdk8: "path/to/java.exe"
	Default  string            `mapstructure:"default"`  // 默认JDK版本
}

// DecompilerConfig 定义了反编译相关的配置结构体
// 包含Jadx路径等配置
type DecompilerConfig struct {
	JadxPath string `mapstructure:"jadx_path"` // Jadx可执行文件路径
}

// Config 是总配置结构体，包含所有配置项
// 用于统一管理工具的各项配置

type Config struct {
	Tool       ToolConfig       `mapstructure:"tool"`       // 工具基本信息配置
	JDK        JDKConfig        `mapstructure:"jdk"`        // JDK相关配置
	Decompiler DecompilerConfig `mapstructure:"decompiler"` // 反编译配置
	CodeQL     CodeQLConfig     `mapstructure:"codeql"`     // CodeQL相关配置
	AI         AIConfig         `mapstructure:"ai"`         // AI模型相关配置
	Report     ReportConfig     `mapstructure:"report"`     // 报告生成相关配置
}

// LoadConfig 从指定文件或默认位置加载配置
// 支持从YAML文件和环境变量中加载配置，环境变量优先级高于文件配置
// 参数：
//   cfgFile - 配置文件路径，留空则使用默认位置和名称
// 返回：
//   *Config - 加载后的配置结构体指针
//   error - 如果加载失败则返回错误信息

func LoadConfig(cfgFile string) (*Config, error) {
	// 设置配置文件路径和名称
	if cfgFile != "" {
		// 使用指定的配置文件
		viper.SetConfigFile(cfgFile)
	} else {
		// 使用默认配置文件：当前目录下的config.yaml
		viper.AddConfigPath(".")      // 添加当前目录作为配置搜索路径
		viper.SetConfigName("config") // 配置文件名称（不含扩展名）
		viper.SetConfigType("yaml")   // 配置文件类型
	}

	// 设置环境变量前缀和键替换规则
	viper.SetEnvPrefix("AUDIT")                            // 环境变量前缀为AUDIT
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_")) // 将配置键中的点替换为下划线（如codeql.cli_path -> AUDIT_CODEQL_CLI_PATH）
	viper.AutomaticEnv()                                   // 自动读取环境变量

	// 读取配置文件
	if err := viper.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("读取配置文件失败: %w", err)
	}

	// 将配置解析到结构体
	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("解析配置失败: %w", err)
	}

	return &config, nil
}
