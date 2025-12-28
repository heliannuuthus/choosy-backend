package openrouter

import (
	"context"
	"sync"

	"choosy-backend/internal/config"

	openai "github.com/sashabaranov/go-openai"
)

type Client struct {
	*openai.Client
	model string
}

var (
	client     *Client
	clientOnce sync.Once
)

func GetClient() *Client {
	clientOnce.Do(func() {
		cfg := openai.DefaultConfig(config.GetString("openrouter.api_key"))
		cfg.BaseURL = "https://openrouter.ai/api/v1"

		model := config.GetString("openrouter.model")
		if model == "" {
			model = "deepseek/deepseek-chat-v3-0324:free"
		}

		client = &Client{
			Client: openai.NewClientWithConfig(cfg),
			model:  model,
		}
	})
	return client
}

func (c *Client) Chat(ctx context.Context, messages []openai.ChatCompletionMessage) (string, error) {
	resp, err := c.CreateChatCompletion(ctx, openai.ChatCompletionRequest{
		Model:    c.model,
		Messages: messages,
	})
	if err != nil {
		return "", err
	}
	if len(resp.Choices) == 0 {
		return "", nil
	}
	return resp.Choices[0].Message.Content, nil
}

func (c *Client) ChatWithModel(ctx context.Context, model string, messages []openai.ChatCompletionMessage) (string, error) {
	resp, err := c.CreateChatCompletion(ctx, openai.ChatCompletionRequest{
		Model:    model,
		Messages: messages,
	})
	if err != nil {
		return "", err
	}
	if len(resp.Choices) == 0 {
		return "", nil
	}
	return resp.Choices[0].Message.Content, nil
}

type StreamHandler func(content string) error

func (c *Client) ChatStream(ctx context.Context, messages []openai.ChatCompletionMessage, handler StreamHandler) error {
	stream, err := c.CreateChatCompletionStream(ctx, openai.ChatCompletionRequest{
		Model:    c.model,
		Messages: messages,
		Stream:   true,
	})
	if err != nil {
		return err
	}
	defer stream.Close()

	for {
		resp, err := stream.Recv()
		if err != nil {
			if err.Error() == "EOF" {
				return nil
			}
			return err
		}
		if len(resp.Choices) > 0 && resp.Choices[0].Delta.Content != "" {
			if err := handler(resp.Choices[0].Delta.Content); err != nil {
				return err
			}
		}
	}
}

func (c *Client) Model() string {
	return c.model
}
