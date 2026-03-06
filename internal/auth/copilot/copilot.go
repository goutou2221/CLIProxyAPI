// Package copilot provides authentication and token management for GitHub Copilot API.
// It handles the GitHub OAuth2 device flow to obtain GitHub tokens,
// and exchanges them for short-lived Copilot API tokens.
package copilot

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/util"
	log "github.com/sirupsen/logrus"
)

const (
	// CopilotClientID is the GitHub OAuth client ID for the Copilot VSCode extension.
	CopilotClientID = "Iv1.b507a08c87ecfe98"

	// deviceCodeURL is the GitHub device code authorization endpoint.
	deviceCodeURL = "https://github.com/login/device/code"

	// tokenURL is the GitHub OAuth token endpoint.
	tokenURL = "https://github.com/login/oauth/access_token"

	// copilotTokenURL is the endpoint to exchange GitHub tokens for Copilot API tokens.
	copilotTokenURL = "https://api.github.com/copilot_internal/v2/token"

	// CopilotAPIBaseURL is the base URL for GitHub Copilot API (individual plan).
	CopilotAPIBaseURL = "https://api.individual.githubcopilot.com"

	// CopilotEditorVersion is the editor version sent with Copilot API requests.
	CopilotEditorVersion = "vscode/1.99.0"

	// CopilotPluginVersion is the Copilot plugin version sent with requests.
	CopilotPluginVersion = "copilot-chat/0.26.7"

	// copilotScope is the GitHub OAuth scope required for Copilot.
	copilotScope = "read:user"

	// defaultPollInterval is the default interval for polling the token endpoint.
	defaultPollInterval = 5 * time.Second

	// maxPollDuration is the maximum time to wait for user authorization.
	maxPollDuration = 15 * time.Minute
)

// CopilotAuth handles GitHub Copilot authentication flow.
type CopilotAuth struct {
	httpClient *http.Client
	cfg        *config.Config
}

// NewCopilotAuth creates a new CopilotAuth service instance.
func NewCopilotAuth(cfg *config.Config) *CopilotAuth {
	return &CopilotAuth{
		httpClient: util.SetProxy(&cfg.SDKConfig, &http.Client{}),
		cfg:        cfg,
	}
}

// RequestDeviceCode initiates the GitHub device flow and returns the device code response.
func (a *CopilotAuth) RequestDeviceCode(ctx context.Context) (*DeviceCodeResponse, error) {
	data := url.Values{
		"client_id": {CopilotClientID},
		"scope":     {copilotScope},
	}

	req, err := http.NewRequestWithContext(ctx, "POST", deviceCodeURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("copilot: failed to create device code request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("copilot: device code request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("copilot: failed to read device code response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("copilot: device code request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var dcResp DeviceCodeResponse
	if err = json.Unmarshal(body, &dcResp); err != nil {
		return nil, fmt.Errorf("copilot: failed to parse device code response: %w", err)
	}
	if dcResp.DeviceCode == "" {
		return nil, fmt.Errorf("copilot: empty device code in response")
	}
	if dcResp.Interval == 0 {
		dcResp.Interval = 5
	}

	return &dcResp, nil
}

// PollForToken polls the GitHub token endpoint until the user authorizes the device.
func (a *CopilotAuth) PollForToken(ctx context.Context, dc *DeviceCodeResponse) (*CopilotAuthBundle, error) {
	if dc == nil {
		return nil, fmt.Errorf("copilot: device code response is nil")
	}

	pollInterval := time.Duration(dc.Interval) * time.Second
	if pollInterval < defaultPollInterval {
		pollInterval = defaultPollInterval
	}

	deadline := time.Now().Add(maxPollDuration)
	if dc.ExpiresIn > 0 {
		expiry := time.Now().Add(time.Duration(dc.ExpiresIn) * time.Second)
		if expiry.Before(deadline) {
			deadline = expiry
		}
	}

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		if time.Now().After(deadline) {
			return nil, fmt.Errorf("copilot: authorization timed out")
		}

		bundle, pending, err := a.tryExchangeDeviceCode(ctx, dc.DeviceCode)
		if err != nil {
			return nil, err
		}
		if bundle != nil {
			return bundle, nil
		}
		if !pending {
			return nil, fmt.Errorf("copilot: authorization failed")
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(pollInterval):
		}
	}
}

// tryExchangeDeviceCode attempts to exchange a device code for tokens.
// Returns (bundle, true, nil) when still pending, (bundle, false, nil) when succeeded,
// and (nil, false, err) on a terminal error.
func (a *CopilotAuth) tryExchangeDeviceCode(ctx context.Context, deviceCode string) (*CopilotAuthBundle, bool, error) {
	data := url.Values{
		"client_id":   {CopilotClientID},
		"device_code": {deviceCode},
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
	}

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, false, fmt.Errorf("copilot: failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, false, fmt.Errorf("copilot: token poll request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, false, fmt.Errorf("copilot: failed to read token response: %w", err)
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		Scope       string `json:"scope"`
		Error       string `json:"error"`
		ErrorDesc   string `json:"error_description"`
	}
	if err = json.Unmarshal(body, &tokenResp); err != nil {
		return nil, false, fmt.Errorf("copilot: failed to parse token response: %w", err)
	}

	switch tokenResp.Error {
	case "":
		// success
	case "authorization_pending", "slow_down":
		return nil, true, nil
	case "expired_token":
		return nil, false, fmt.Errorf("copilot: device code expired")
	case "access_denied":
		return nil, false, fmt.Errorf("copilot: user denied authorization")
	default:
		return nil, false, fmt.Errorf("copilot: token exchange error %q: %s", tokenResp.Error, tokenResp.ErrorDesc)
	}

	if tokenResp.AccessToken == "" {
		return nil, true, nil
	}

	return &CopilotAuthBundle{
		AccessToken: tokenResp.AccessToken,
		TokenType:   tokenResp.TokenType,
		Scope:       tokenResp.Scope,
	}, false, nil
}

// FetchGitHubLogin retrieves the authenticated user's GitHub login name.
func (a *CopilotAuth) FetchGitHubLogin(ctx context.Context, accessToken string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "token "+accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var user struct {
		Login string `json:"login"`
	}
	if err = json.Unmarshal(body, &user); err != nil {
		return "", err
	}
	return user.Login, nil
}

// ExchangeForCopilotToken exchanges a GitHub access token for a short-lived Copilot API token.
func ExchangeForCopilotToken(ctx context.Context, httpClient *http.Client, githubToken string) (string, time.Time, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", copilotTokenURL, nil)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("copilot: failed to create copilot token request: %w", err)
	}
	req.Header.Set("Authorization", "token "+githubToken)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Editor-Version", CopilotEditorVersion)
	req.Header.Set("Editor-Plugin-Version", CopilotPluginVersion)
	req.Header.Set("Copilot-Integration-Id", "vscode-chat")
	req.Header.Set("User-Agent", "GitHubCopilotChat/0.26.7")

	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("copilot: copilot token request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("copilot: failed to read copilot token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", time.Time{}, fmt.Errorf("copilot: copilot token request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		Token     string `json:"token"`
		ExpiresAt int64  `json:"expires_at"`
	}
	if err = json.Unmarshal(body, &tokenResp); err != nil {
		return "", time.Time{}, fmt.Errorf("copilot: failed to parse copilot token response: %w", err)
	}

	if tokenResp.Token == "" {
		return "", time.Time{}, fmt.Errorf("copilot: empty copilot token in response")
	}

	expiresAt := time.Time{}
	if tokenResp.ExpiresAt > 0 {
		expiresAt = time.Unix(tokenResp.ExpiresAt, 0)
	}

	log.Debugf("copilot: obtained copilot token, expires at %v", expiresAt)
	return tokenResp.Token, expiresAt, nil
}

// CreateTokenStorage creates a CopilotTokenStorage from an auth bundle.
func (a *CopilotAuth) CreateTokenStorage(bundle *CopilotAuthBundle) *CopilotTokenStorage {
	return &CopilotTokenStorage{
		AccessToken: bundle.AccessToken,
		TokenType:   bundle.TokenType,
		Scope:       bundle.Scope,
		Login:       bundle.Login,
		Type:        "copilot",
	}
}
