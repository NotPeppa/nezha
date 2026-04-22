package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	oidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/tidwall/gjson"

	"github.com/nezhahq/nezha/model"
)

func exchangeOIDCOpenID(c context.Context, conf *model.Oauth2Config, callbackData *model.Oauth2Callback,
	redirectURL string, nonce string) (string, error) {
	provider, err := oidc.NewProvider(c, conf.OIDCIssuer)
	if err != nil {
		return "", err
	}

	o2conf := conf.Setup(redirectURL)
	otk, err := o2conf.Exchange(c, callbackData.Code)
	if err != nil {
		return "", err
	}

	rawIDToken, ok := otk.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return "", errors.New("missing id_token")
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: conf.ClientID})
	idToken, err := verifier.Verify(c, rawIDToken)
	if err != nil {
		return "", err
	}
	if nonce != "" && idToken.Nonce != nonce {
		return "", errors.New("invalid nonce")
	}

	claims := make(map[string]any)
	if err := idToken.Claims(&claims); err != nil {
		return "", err
	}

	claimPath := conf.OIDCUserID
	if claimPath == "" {
		claimPath = "sub"
	}
	body, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	openID := gjson.GetBytes(body, claimPath).String()
	if openID == "" {
		return "", fmt.Errorf("missing claim in id_token: %s", claimPath)
	}

	return openID, nil
}
