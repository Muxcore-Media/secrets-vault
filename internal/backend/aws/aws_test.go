package aws_test

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"

	awsbackend "github.com/Muxcore-Media/secrets-vault/internal/backend/aws"
)

type fakeAPI struct {
	secrets map[string]string
}

func (f *fakeAPI) GetSecretValue(_ context.Context, params *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	v, ok := f.secrets[aws.ToString(params.SecretId)]
	if !ok {
		return nil, &types.ResourceNotFoundException{Message: aws.String("missing")}
	}
	return &secretsmanager.GetSecretValueOutput{SecretString: aws.String(v)}, nil
}

func (f *fakeAPI) CreateSecret(_ context.Context, params *secretsmanager.CreateSecretInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.CreateSecretOutput, error) {
	f.secrets[aws.ToString(params.Name)] = aws.ToString(params.SecretString)
	return &secretsmanager.CreateSecretOutput{}, nil
}

func (f *fakeAPI) PutSecretValue(_ context.Context, params *secretsmanager.PutSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.PutSecretValueOutput, error) {
	id := aws.ToString(params.SecretId)
	if _, ok := f.secrets[id]; !ok {
		return nil, &types.ResourceNotFoundException{Message: aws.String("missing")}
	}
	f.secrets[id] = aws.ToString(params.SecretString)
	return &secretsmanager.PutSecretValueOutput{}, nil
}

func (f *fakeAPI) DeleteSecret(_ context.Context, params *secretsmanager.DeleteSecretInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.DeleteSecretOutput, error) {
	delete(f.secrets, aws.ToString(params.SecretId))
	return &secretsmanager.DeleteSecretOutput{}, nil
}

func (f *fakeAPI) ListSecrets(_ context.Context, _ *secretsmanager.ListSecretsInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretsOutput, error) {
	out := &secretsmanager.ListSecretsOutput{}
	for name := range f.secrets {
		n := name
		out.SecretList = append(out.SecretList, types.SecretListEntry{Name: &n})
	}
	return out, nil
}

func TestAWSBackendCRUD(t *testing.T) {
	api := &fakeAPI{secrets: map[string]string{}}
	c := awsbackend.NewWithAPI(api, "muxcore/")
	ctx := context.Background()
	if err := c.Set(ctx, "api_key", "v"); err != nil {
		t.Fatalf("set: %v", err)
	}
	got, err := c.Get(ctx, "api_key")
	if err != nil || got != "v" {
		t.Fatalf("get: %v %q", err, got)
	}
	keys, err := c.List(ctx)
	if err != nil || len(keys) != 1 || keys[0] != "api_key" {
		t.Fatalf("list: %v %#v", err, keys)
	}
	if err := c.Delete(ctx, "api_key"); err != nil {
		t.Fatalf("delete: %v", err)
	}
}
