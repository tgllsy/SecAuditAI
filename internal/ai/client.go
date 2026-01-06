// Package ai 实现了AI客户端与验证逻辑，用于与大语言模型交互
package ai

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	// openai 是与OpenAI API兼容的客户端库
	openai "github.com/sashabaranov/go-openai"
)

// Client 是AI客户端结构体，用于与大语言模型进行交互
// 支持兼容OpenAI API格式的各种模型服务，支持多模型轮询
type Client struct {
	clients []*openai.Client // OpenAI客户端实例列表
	models  []string         // 模型名称列表
	index   uint32           // 当前轮询索引，使用原子操作确保线程安全
	cache   sync.Map         // 验证结果缓存，避免重复请求
}

// NewClient 创建一个新的AI客户端实例，支持多模型轮询
// 参数：
//   models - 模型配置列表，包含API密钥、模型名称和基础URL
// 返回：
//   *Client - 创建的AI客户端实例

func NewClient(models []struct {
	APIKey  string
	Model   string
	BaseURL string
}) *Client {
	clients := make([]*openai.Client, len(models))
	modelNames := make([]string, len(models))

	// 创建多个OpenAI客户端实例
	for i, model := range models {
		config := openai.DefaultConfig(model.APIKey)
		if model.BaseURL != "" {
			config.BaseURL = model.BaseURL
		}
		clients[i] = openai.NewClientWithConfig(config)
		modelNames[i] = model.Model
	}

	return &Client{
		clients: clients,
		models:  modelNames,
		index:   0,
	}
}

// SendPrompt 向AI模型发送提示词并获取响应，支持轮询机制
// 如果当前模型请求失败，自动尝试下一个模型
// 参数：
//   ctx - 上下文，用于控制请求的生命周期
//   prompt - 要发送给AI的提示词内容
// 返回：
//   string - AI模型的响应内容
//   error - 如果所有模型都请求失败则返回错误信息

func (c *Client) SendPrompt(ctx context.Context, prompt string) (string, error) {
	maxRetries := 3 // 最大重试轮数
	retryDelay := 5 * time.Second

	// 循环进行多轮重试
	for retry := 0; retry < maxRetries; retry++ {
		// 获取当前索引
		startIndex := atomic.AddUint32(&c.index, 1) - 1

		// 尝试所有模型
		for i := 0; i < len(c.clients); i++ {
			// 计算当前尝试的客户端索引
			clientIndex := int(startIndex+uint32(i)) % len(c.clients)

			// 调用当前客户端发送请求
			resp, err := c.clients[clientIndex].CreateChatCompletion(
				ctx,
				openai.ChatCompletionRequest{
					Model: c.models[clientIndex], // 使用当前模型
					Messages: []openai.ChatCompletionMessage{
						{
							Role:    openai.ChatMessageRoleUser, // 用户角色
							Content: prompt,                     // 提示词内容
						},
					},
				},
			)

			// 如果请求成功，返回响应
			if err == nil {
				// 检查响应是否包含有效结果
				if len(resp.Choices) > 0 {
					return resp.Choices[0].Message.Content, nil
				}
			}

			// 请求失败，打印警告信息
			fmt.Printf("WARN: 模型 %s 请求失败: %v，尝试下一个模型...\n", c.models[clientIndex], err)
		}

		// 如果所有模型在这一轮都失败了，且不是最后一轮重试，则进行延迟
		if retry < maxRetries-1 {
			fmt.Printf("WARN: 所有模型在第 %d 轮尝试中均失败，将在 %v 后进行第 %d 轮重试...\n", retry+1, retryDelay, retry+2)
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(retryDelay):
				// 继续下一轮重试
			}
		}
	}

	// 所有模型在所有重试轮次中都请求失败
	return "", fmt.Errorf("所有AI模型请求都失败了，已重试 %d 轮", maxRetries)
}
