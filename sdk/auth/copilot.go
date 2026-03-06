package auth

import (
	"context"
	"fmt"
	"strings"
	"time"

	copilotpkg "github.com/router-for-me/CLIProxyAPI/v6/internal/auth/copilot"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/browser"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

// CopilotAuthenticator implements the GitHub OAuth device flow for GitHub Copilot.
type CopilotAuthenticator struct{}

// NewCopilotAuthenticator constructs a new Copilot authenticator.
func NewCopilotAuthenticator() Authenticator {
	return &CopilotAuthenticator{}
}

// Provider returns the provider key for GitHub Copilot.
func (CopilotAuthenticator) Provider() string {
	return "copilot"
}

// RefreshLead returns nil since GitHub tokens do not have a refresh flow;
// Copilot tokens are short-lived and fetched on demand by the executor.
func (CopilotAuthenticator) RefreshLead() *time.Duration {
	return nil
}

// Login initiates the GitHub device flow authentication for Copilot.
func (a CopilotAuthenticator) Login(ctx context.Context, cfg *config.Config, opts *LoginOptions) (*coreauth.Auth, error) {
	if cfg == nil {
		return nil, fmt.Errorf("cliproxy auth: configuration is required")
	}
	if opts == nil {
		opts = &LoginOptions{}
	}

	authSvc := copilotpkg.NewCopilotAuth(cfg)

	fmt.Println("Starting GitHub Copilot authentication...")
	deviceCode, err := authSvc.RequestDeviceCode(ctx)
	if err != nil {
		return nil, fmt.Errorf("copilot: failed to start device flow: %w", err)
	}

	fmt.Printf("\nTo authenticate with GitHub Copilot, visit:\n%s\n\n", deviceCode.VerificationURI)
	if deviceCode.UserCode != "" {
		fmt.Printf("Enter the user code: %s\n\n", deviceCode.UserCode)
	}

	if !opts.NoBrowser {
		verificationURL := deviceCode.VerificationURI
		if browser.IsAvailable() {
			if errOpen := browser.OpenURL(verificationURL); errOpen != nil {
				log.Warnf("Failed to open browser automatically: %v", errOpen)
			} else {
				fmt.Println("Browser opened automatically.")
			}
		}
	}

	if deviceCode.ExpiresIn > 0 {
		fmt.Printf("(This will timeout in %d seconds if not authorized)\n", deviceCode.ExpiresIn)
	}
	fmt.Println("Waiting for GitHub authorization...")

	bundle, err := authSvc.PollForToken(ctx, deviceCode)
	if err != nil {
		return nil, fmt.Errorf("copilot: %w", err)
	}

	// Try to fetch the GitHub username
	login, errLogin := authSvc.FetchGitHubLogin(ctx, bundle.AccessToken)
	if errLogin != nil {
		log.Warnf("copilot: could not fetch GitHub login: %v", errLogin)
	} else {
		bundle.Login = login
	}

	tokenStorage := authSvc.CreateTokenStorage(bundle)

	login = strings.TrimSpace(bundle.Login)
	label := "GitHub Copilot User"
	if login != "" {
		label = login
	}

	metadata := map[string]any{
		"type":         "copilot",
		"access_token": bundle.AccessToken,
		"token_type":   bundle.TokenType,
		"scope":        bundle.Scope,
		"login":        bundle.Login,
		"timestamp":    time.Now().UnixMilli(),
	}

	fileName := "copilot"
	if login != "" {
		fileName = fmt.Sprintf("copilot-%s", login)
	}
	fileName = fmt.Sprintf("%s.json", fileName)

	fmt.Println("\nGitHub Copilot authentication successful!")

	return &coreauth.Auth{
		ID:       fileName,
		Provider: a.Provider(),
		FileName: fileName,
		Label:    label,
		Storage:  tokenStorage,
		Metadata: metadata,
	}, nil
}
