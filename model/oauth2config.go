package model

import (
	"context"

	oidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type Oauth2Config struct {
	ClientID     string         `koanf:"client_id" json:"client_id,omitempty"`
	ClientSecret string         `koanf:"client_secret" json:"client_secret,omitempty"`
	Endpoint     Oauth2Endpoint `koanf:"endpoint" json:"endpoint,omitempty"`
	Scopes       []string       `koanf:"scopes" json:"scopes,omitempty"`
	OIDCIssuer   string         `koanf:"oidc_issuer" json:"oidc_issuer,omitempty"`
	OIDCUserID   string         `koanf:"oidc_user_id_claim" json:"oidc_user_id_claim,omitempty"`

	UserInfoURL string `koanf:"user_info_url" json:"user_info_url,omitempty"`
	UserIDPath  string `koanf:"user_id_path" json:"user_id_path,omitempty"`
}

func (c *Oauth2Config) IsOIDC() bool {
	return c.OIDCIssuer != ""
}

type Oauth2Endpoint struct {
	AuthURL  string `koanf:"auth_url" json:"auth_url,omitempty"`
	TokenURL string `koanf:"token_url" json:"token_url,omitempty"`
}

func (c *Oauth2Config) ensureOpenIDScope(scopes []string) []string {
	for _, s := range scopes {
		if s == "openid" {
			return scopes
		}
	}
	return append(scopes, "openid")
}

func (c *Oauth2Config) Setup(redirectURL string) *oauth2.Config {
	scopes := c.Scopes
	if c.IsOIDC() {
		scopes = c.ensureOpenIDScope(scopes)
	}

	return &oauth2.Config{
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  c.Endpoint.AuthURL,
			TokenURL: c.Endpoint.TokenURL,
		},
		RedirectURL: redirectURL,
		Scopes:      scopes,
	}
}

// SetupWithContext 在 OIDC 模式下通过 oidc_issuer 自动 discovery 获取 endpoint，
// 非 OIDC 模式等同于 Setup。
func (c *Oauth2Config) SetupWithContext(ctx context.Context, redirectURL string) (*oauth2.Config, error) {
	if !c.IsOIDC() {
		return c.Setup(redirectURL), nil
	}

	provider, err := oidc.NewProvider(ctx, c.OIDCIssuer)
	if err != nil {
		return nil, err
	}

	return &oauth2.Config{
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  redirectURL,
		Scopes:       c.ensureOpenIDScope(c.Scopes),
	}, nil
}
