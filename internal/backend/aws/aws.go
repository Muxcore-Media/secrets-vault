package aws

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"

	"github.com/Muxcore-Media/secrets-vault/internal/backend"
)

type api interface {
	GetSecretValue(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
	CreateSecret(ctx context.Context, params *secretsmanager.CreateSecretInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.CreateSecretOutput, error)
	PutSecretValue(ctx context.Context, params *secretsmanager.PutSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.PutSecretValueOutput, error)
	DeleteSecret(ctx context.Context, params *secretsmanager.DeleteSecretInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.DeleteSecretOutput, error)
	ListSecrets(ctx context.Context, params *secretsmanager.ListSecretsInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretsOutput, error)
}

// Client implements backend.Backend against AWS Secrets Manager.
type Client struct {
	api    api
	prefix string
}

// NewFromEnv builds an AWS Secrets Manager client.
func NewFromEnv(ctx context.Context, prefix string) (*Client, error) {
	var opts []func(*config.LoadOptions) error
	if region := os.Getenv("AWS_SECRETS_REGION"); region != "" {
		opts = append(opts, config.WithRegion(region))
	}
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("aws config: %w", err)
	}
	return &Client{api: secretsmanager.NewFromConfig(cfg), prefix: prefix}, nil
}

// NewWithAPI is used by tests.
func NewWithAPI(a api, prefix string) *Client {
	return &Client{api: a, prefix: prefix}
}

func (c *Client) name(key string) string {
	return backend.PrefixedName(c.prefix, key)
}

func (c *Client) Get(ctx context.Context, key string) (string, error) {
	if key == "" {
		return "", backend.ErrEmptyKey
	}
	out, err := c.api.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(c.name(key)),
	})
	if err != nil {
		return "", mapAWSErr(err)
	}
	if out.SecretString != nil {
		return *out.SecretString, nil
	}
	if len(out.SecretBinary) > 0 {
		return string(out.SecretBinary), nil
	}
	return "", fmt.Errorf("%w: %s", backend.ErrNotFound, key)
}

func (c *Client) Set(ctx context.Context, key, value string) error {
	if key == "" {
		return backend.ErrEmptyKey
	}
	name := c.name(key)
	_, err := c.api.PutSecretValue(ctx, &secretsmanager.PutSecretValueInput{
		SecretId:     aws.String(name),
		SecretString: aws.String(value),
	})
	if err == nil {
		return nil
	}
	var notFound *types.ResourceNotFoundException
	if errors.As(err, &notFound) {
		_, createErr := c.api.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
			Name:         aws.String(name),
			SecretString: aws.String(value),
		})
		return mapAWSErr(createErr)
	}
	return mapAWSErr(err)
}

func (c *Client) Delete(ctx context.Context, key string) error {
	if key == "" {
		return backend.ErrEmptyKey
	}
	input := &secretsmanager.DeleteSecretInput{
		SecretId: aws.String(c.name(key)),
	}
	if forceDeleteWithoutRecovery() {
		force := true
		input.ForceDeleteWithoutRecovery = &force
	}
	_, err := c.api.DeleteSecret(ctx, input)
	return mapAWSErr(err)
}

func forceDeleteWithoutRecovery() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("AWS_SECRETS_FORCE_DELETE")))
	return v == "1" || v == "true" || v == "yes"
}

func (c *Client) List(ctx context.Context) ([]string, error) {
	var (
		out    []string
		token  *string
		prefix = c.prefix
	)
	for {
		resp, err := c.api.ListSecrets(ctx, &secretsmanager.ListSecretsInput{
			NextToken: token,
			Filters: []types.Filter{{
				Key:    types.FilterNameStringTypeName,
				Values: []string{strings.TrimSuffix(prefix, "/")},
			}},
		})
		if err != nil {
			return nil, mapAWSErr(err)
		}
		for _, s := range resp.SecretList {
			if s.Name == nil {
				continue
			}
			if key, ok := backend.StripPrefix(prefix, *s.Name); ok && key != "" {
				out = append(out, key)
			}
		}
		if resp.NextToken == nil || *resp.NextToken == "" {
			break
		}
		token = resp.NextToken
	}
	return out, nil
}

func (c *Client) Ping(ctx context.Context) error {
	_, err := c.api.ListSecrets(ctx, &secretsmanager.ListSecretsInput{MaxResults: aws.Int32(1)})
	return mapAWSErr(err)
}

func (c *Client) Close() error {
	return nil
}

func mapAWSErr(err error) error {
	if err == nil {
		return nil
	}
	var notFound *types.ResourceNotFoundException
	if errors.As(err, &notFound) {
		return fmt.Errorf("%w: %v", backend.ErrNotFound, err)
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "accessdenied") || strings.Contains(msg, "not authorized") || strings.Contains(msg, "unauthorized") {
		return fmt.Errorf("%w: %v", backend.ErrPermissionDenied, err)
	}
	if strings.Contains(msg, "resourcenotfound") {
		return fmt.Errorf("%w: %v", backend.ErrNotFound, err)
	}
	return err
}
