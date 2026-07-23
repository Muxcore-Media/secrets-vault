package infisical

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Muxcore-Media/secrets-vault/internal/backend"
)

const defaultAPIURL = "https://app.infisical.com"

// Client implements backend.Backend against the Infisical REST API.
type Client struct {
	httpClient *http.Client
	baseURL    string
	projectID  string
	env        string
	prefix     string

	mu           sync.Mutex
	token        string
	clientID     string
	clientSecret string
}

// NewFromEnv builds an Infisical client from environment variables.
func NewFromEnv(ctx context.Context, prefix string) (*Client, error) {
	base := strings.TrimRight(os.Getenv("INFISICAL_API_URL"), "/")
	if base == "" {
		base = defaultAPIURL
	}
	projectID := os.Getenv("INFISICAL_PROJECT_ID")
	if projectID == "" {
		return nil, fmt.Errorf("INFISICAL_PROJECT_ID is required")
	}
	envSlug := os.Getenv("INFISICAL_ENV")
	if envSlug == "" {
		envSlug = "dev"
	}

	c := &Client{
		httpClient:   &http.Client{Timeout: 30 * time.Second},
		baseURL:      base,
		projectID:    projectID,
		env:          envSlug,
		prefix:       prefix,
		token:        os.Getenv("INFISICAL_TOKEN"),
		clientID:     os.Getenv("INFISICAL_CLIENT_ID"),
		clientSecret: os.Getenv("INFISICAL_CLIENT_SECRET"),
	}
	if c.token == "" && (c.clientID == "" || c.clientSecret == "") {
		return nil, fmt.Errorf("set INFISICAL_TOKEN or INFISICAL_CLIENT_ID and INFISICAL_CLIENT_SECRET")
	}
	if c.token == "" {
		if err := c.refreshToken(ctx); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// NewWithHTTP is used by tests.
func NewWithHTTP(httpClient *http.Client, baseURL, projectID, env, token, prefix string) *Client {
	return &Client{
		httpClient: httpClient,
		baseURL:    strings.TrimRight(baseURL, "/"),
		projectID:  projectID,
		env:        env,
		token:      token,
		prefix:     prefix,
	}
}

func (c *Client) secretName(key string) string {
	return backend.PrefixedName(c.prefix, key)
}

func (c *Client) Get(ctx context.Context, key string) (string, error) {
	if key == "" {
		return "", backend.ErrEmptyKey
	}
	name := c.secretName(key)
	q := url.Values{}
	q.Set("workspaceId", c.projectID)
	q.Set("environment", c.env)
	q.Set("secretPath", "/")
	q.Set("secretName", name)
	var resp struct {
		Secret struct {
			SecretValue string `json:"secretValue"`
		} `json:"secret"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/api/v3/secrets/raw/"+url.PathEscape(name)+"?"+q.Encode(), nil, &resp); err != nil {
		return "", err
	}
	if resp.Secret.SecretValue == "" {
		// empty value is valid; distinguish missing via HTTP status in doJSON
	}
	return resp.Secret.SecretValue, nil
}

func (c *Client) Set(ctx context.Context, key, value string) error {
	if key == "" {
		return backend.ErrEmptyKey
	}
	name := c.secretName(key)
	body := map[string]interface{}{
		"workspaceId": c.projectID,
		"environment": c.env,
		"secretPath":  "/",
		"secretValue": value,
		"type":        "shared",
	}
	// Try create; on conflict, update.
	err := c.doJSON(ctx, http.MethodPost, "/api/v3/secrets/raw/"+url.PathEscape(name), body, nil)
	if err == nil {
		return nil
	}
	if !isConflict(err) {
		return err
	}
	return c.doJSON(ctx, http.MethodPatch, "/api/v3/secrets/raw/"+url.PathEscape(name), body, nil)
}

func (c *Client) Delete(ctx context.Context, key string) error {
	if key == "" {
		return backend.ErrEmptyKey
	}
	name := c.secretName(key)
	body := map[string]interface{}{
		"workspaceId": c.projectID,
		"environment": c.env,
		"secretPath":  "/",
	}
	return c.doJSON(ctx, http.MethodDelete, "/api/v3/secrets/raw/"+url.PathEscape(name), body, nil)
}

func (c *Client) List(ctx context.Context) ([]string, error) {
	q := url.Values{}
	q.Set("workspaceId", c.projectID)
	q.Set("environment", c.env)
	q.Set("secretPath", "/")
	var resp struct {
		Secrets []struct {
			SecretKey string `json:"secretKey"`
		} `json:"secrets"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/api/v3/secrets/raw?"+q.Encode(), nil, &resp); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(resp.Secrets))
	for _, s := range resp.Secrets {
		if key, ok := backend.StripPrefix(c.prefix, s.SecretKey); ok && key != "" {
			out = append(out, key)
		}
	}
	return out, nil
}

func (c *Client) Ping(ctx context.Context) error {
	_, err := c.List(ctx)
	return err
}

func (c *Client) Close() error {
	return nil
}

func (c *Client) refreshToken(ctx context.Context) error {
	body := map[string]string{
		"clientId":     c.clientID,
		"clientSecret": c.clientSecret,
	}
	var resp struct {
		AccessToken string `json:"accessToken"`
	}
	if err := c.doJSONUnauth(ctx, http.MethodPost, "/api/v1/auth/universal-auth/login", body, &resp); err != nil {
		return fmt.Errorf("infisical auth: %w", err)
	}
	if resp.AccessToken == "" {
		return fmt.Errorf("infisical auth: empty access token")
	}
	c.mu.Lock()
	c.token = resp.AccessToken
	c.mu.Unlock()
	return nil
}

func (c *Client) doJSON(ctx context.Context, method, path string, body, out interface{}) error {
	err := c.doJSONOnce(ctx, method, path, body, out)
	if err == nil {
		return nil
	}
	if isUnauthorized(err) && c.clientID != "" && c.clientSecret != "" {
		if refreshErr := c.refreshToken(ctx); refreshErr != nil {
			return err
		}
		return c.doJSONOnce(ctx, method, path, body, out)
	}
	return err
}

func (c *Client) doJSONOnce(ctx context.Context, method, path string, body, out interface{}) error {
	c.mu.Lock()
	token := c.token
	c.mu.Unlock()
	return c.roundTrip(ctx, method, path, token, body, out)
}

func (c *Client) doJSONUnauth(ctx context.Context, method, path string, body, out interface{}) error {
	return c.roundTrip(ctx, method, path, "", body, out)
}

func (c *Client) roundTrip(ctx context.Context, method, path, token string, body, out interface{}) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		if resp.StatusCode == http.StatusForbidden {
			return fmt.Errorf("%w: infisical status %d", backend.ErrPermissionDenied, resp.StatusCode)
		}
		return fmt.Errorf("%w: infisical status %d", errUnauthorized, resp.StatusCode)
	}
	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("%w", backend.ErrNotFound)
	}
	if resp.StatusCode == http.StatusConflict {
		return fmt.Errorf("%w", errConflict)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("infisical status %d", resp.StatusCode)
	}
	if out == nil || len(data) == 0 {
		return nil
	}
	return json.Unmarshal(data, out)
}

var (
	errUnauthorized = errors.New("unauthorized")
	errConflict     = errors.New("conflict")
)

func isUnauthorized(err error) bool {
	return errors.Is(err, errUnauthorized) || (err != nil && strings.Contains(err.Error(), "unauthorized"))
}

func isConflict(err error) bool {
	return errors.Is(err, errConflict) || (err != nil && strings.Contains(err.Error(), "conflict"))
}
