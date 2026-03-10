// Package copilot provides authentication and token management for GitHub Copilot API.
// It handles the GitHub OAuth2 device flow and Copilot token exchange.
package copilot

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/misc"
)

// CopilotTokenStorage stores OAuth2 token information for GitHub Copilot API authentication.
type CopilotTokenStorage struct {
	// AccessToken is the GitHub OAuth2 access token used to obtain Copilot tokens.
	AccessToken string `json:"access_token"`
	// TokenType is the type of token, typically "bearer".
	TokenType string `json:"token_type"`
	// Scope is the OAuth2 scope granted to the token.
	Scope string `json:"scope,omitempty"`
	// Login is the GitHub username associated with this token.
	Login string `json:"login,omitempty"`
	// Type indicates the authentication provider type, always "copilot" for this storage.
	Type string `json:"type"`

	// Metadata holds arbitrary key-value pairs injected via hooks.
	Metadata map[string]any `json:"-"`
}

// SetMetadata allows external callers to inject metadata into the storage before saving.
func (ts *CopilotTokenStorage) SetMetadata(meta map[string]any) {
	ts.Metadata = meta
}

// SaveTokenToFile serializes the Copilot token storage to a JSON file.
func (ts *CopilotTokenStorage) SaveTokenToFile(authFilePath string) error {
	misc.LogSavingCredentials(authFilePath)
	ts.Type = "copilot"

	if err := os.MkdirAll(filepath.Dir(authFilePath), 0700); err != nil {
		return fmt.Errorf("failed to create directory: %v", err)
	}

	f, err := os.Create(authFilePath)
	if err != nil {
		return fmt.Errorf("failed to create token file: %w", err)
	}
	defer func() {
		_ = f.Close()
	}()

	// Merge metadata using helper
	data, errMerge := misc.MergeMetadata(ts, ts.Metadata)
	if errMerge != nil {
		return fmt.Errorf("failed to merge metadata: %w", errMerge)
	}

	encoder := json.NewEncoder(f)
	encoder.SetIndent("", "  ")
	if err = encoder.Encode(data); err != nil {
		return fmt.Errorf("failed to write token to file: %w", err)
	}
	return nil
}

// CopilotAuthBundle bundles authentication data after the GitHub device flow completes.
type CopilotAuthBundle struct {
	// AccessToken is the GitHub OAuth access token.
	AccessToken string `json:"access_token"`
	// TokenType is the token type ("bearer").
	TokenType string `json:"token_type"`
	// Scope is the granted OAuth scope.
	Scope string `json:"scope"`
	// Login is the GitHub username.
	Login string `json:"login,omitempty"`
}

// DeviceCodeResponse holds the GitHub device code authorization response.
type DeviceCodeResponse struct {
	// DeviceCode is the device verification code.
	DeviceCode string `json:"device_code"`
	// UserCode is the code the user must enter at the verification URI.
	UserCode string `json:"user_code"`
	// VerificationURI is the URL where the user should enter the code.
	VerificationURI string `json:"verification_uri"`
	// ExpiresIn is the number of seconds until the device code expires.
	ExpiresIn int `json:"expires_in"`
	// Interval is the minimum number of seconds to wait between polling requests.
	Interval int `json:"interval"`
}
