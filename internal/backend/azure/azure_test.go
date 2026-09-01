package azure_test

import (
	"context"
	"errors"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"

	"github.com/Muxcore-Media/secrets-vault/internal/backend"
	azurebackend "github.com/Muxcore-Media/secrets-vault/internal/backend/azure"
)

type fakePager struct {
	pages []azsecrets.ListSecretPropertiesResponse
	idx   int
	err   error
}

func (p *fakePager) More() bool {
	return p.err != nil || p.idx < len(p.pages)
}

func (p *fakePager) NextPage(_ context.Context) (azsecrets.ListSecretPropertiesResponse, error) {
	if p.err != nil {
		return azsecrets.ListSecretPropertiesResponse{}, p.err
	}
	if p.idx >= len(p.pages) {
		return azsecrets.ListSecretPropertiesResponse{}, errors.New("no more pages")
	}
	page := p.pages[p.idx]
	p.idx++
	return page, nil
}

type fakeAPI struct {
	secrets map[string]string
	pager   *fakePager
}

func (f *fakeAPI) GetSecret(_ context.Context, name string, _ string, _ *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error) {
	val, ok := f.secrets[name]
	if !ok {
		return azsecrets.GetSecretResponse{}, &azcore.ResponseError{StatusCode: 404}
	}
	return azsecrets.GetSecretResponse{Secret: azsecrets.Secret{Value: &val}}, nil
}

func (f *fakeAPI) SetSecret(_ context.Context, name string, parameters azsecrets.SetSecretParameters, _ *azsecrets.SetSecretOptions) (azsecrets.SetSecretResponse, error) {
	if parameters.Value == nil {
		return azsecrets.SetSecretResponse{}, errors.New("empty value")
	}
	f.secrets[name] = *parameters.Value
	return azsecrets.SetSecretResponse{}, nil
}

func (f *fakeAPI) DeleteSecret(_ context.Context, name string, _ *azsecrets.DeleteSecretOptions) (azsecrets.DeleteSecretResponse, error) {
	if _, ok := f.secrets[name]; !ok {
		return azsecrets.DeleteSecretResponse{}, &azcore.ResponseError{StatusCode: 404}
	}
	delete(f.secrets, name)
	return azsecrets.DeleteSecretResponse{}, nil
}

func (f *fakeAPI) NewListSecretPropertiesPager(_ *azsecrets.ListSecretPropertiesOptions) *runtime.Pager[azsecrets.ListSecretPropertiesResponse] {
	return runtime.NewPager(runtime.PagingHandler[azsecrets.ListSecretPropertiesResponse]{
		More: func(azsecrets.ListSecretPropertiesResponse) bool {
			return f.pager.More()
		},
		Fetcher: func(_ context.Context, _ *azsecrets.ListSecretPropertiesResponse) (azsecrets.ListSecretPropertiesResponse, error) {
			return f.pager.NextPage(context.Background())
		},
	})
}

func TestPrefixedNameForAzure(t *testing.T) {
	got := backend.PrefixedName("muxcore/", "api_key")
	if got != "muxcore/api_key" {
		t.Fatalf("got %q", got)
	}
}

func TestAzureBackendCRUD(t *testing.T) {
	store := map[string]string{}
	pager := &fakePager{}
	api := &fakeAPI{secrets: store, pager: pager}
	c := azurebackend.NewWithAPI(api, "muxcore/")
	ctx := context.Background()

	if err := c.Set(ctx, "api_key", "v"); err != nil {
		t.Fatalf("set: %v", err)
	}
	got, err := c.Get(ctx, "api_key")
	if err != nil || got != "v" {
		t.Fatalf("get: %v %q", err, got)
	}

	name := "muxcore-api-key"
	id := azsecrets.ID("https://vault.example.net/secrets/" + name + "/abc123")
	pager.pages = []azsecrets.ListSecretPropertiesResponse{{
		SecretPropertiesListResult: azsecrets.SecretPropertiesListResult{
			Value: []*azsecrets.SecretProperties{{ID: &id}},
		},
	}}
	keys, err := c.List(ctx)
	if err != nil || len(keys) != 1 || keys[0] != "api-key" {
		t.Fatalf("list: %v %#v", err, keys)
	}
	pager.idx = 0
	if err := c.Ping(ctx); err != nil {
		t.Fatalf("ping: %v", err)
	}
	if err := c.Delete(ctx, "api_key"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := c.Get(ctx, "api_key"); !errors.Is(err, backend.ErrNotFound) {
		t.Fatalf("expected not found, got %v", err)
	}
}

func TestAzureBackendPermissionDenied(t *testing.T) {
	api := &fakeAPI{
		secrets: map[string]string{},
		pager:   &fakePager{err: &azcore.ResponseError{StatusCode: 403}},
	}
	c := azurebackend.NewWithAPI(api, "muxcore/")
	if err := c.Ping(context.Background()); !errors.Is(err, backend.ErrPermissionDenied) {
		t.Fatalf("ping: %v", err)
	}
}
