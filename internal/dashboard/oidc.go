package dashboard

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/fadhaw/grepalert/internal/rules"
)

// OpenID Connect sign-in: authorization-code flow with PKCE, state and
// nonce. The code is exchanged and the ID token verified (signature, issuer,
// audience, expiry, nonce) on the server; the browser only gets the session
// cookie.

type oidcClient struct {
	cfg        *OIDCConfig
	verifier   *oidc.IDTokenVerifier
	oauth      oauth2.Config
	endSession string // provider logout URL, if it supports RP-initiated logout
}

// oidcState travels in a short-lived signed cookie between the redirect to
// the identity provider and the callback.
type oidcState struct {
	State     string `json:"s"`
	Nonce     string `json:"n"`
	Verifier  string `json:"v"`
	Next      string `json:"x"`
	ExpiresAt int64  `json:"e"`
}

type oidcOnce struct {
	mu     sync.Mutex
	client *oidcClient
}

// oidc returns the provider client, discovering it on first use (and
// retrying later if the identity provider was unreachable).
func (s *Server) oidc(ctx context.Context) (*oidcClient, error) {
	cfg := s.cfg.Auth.OIDC
	if cfg == nil {
		return nil, errors.New("single sign-on is not configured")
	}
	s.oidcInit.mu.Lock()
	defer s.oidcInit.mu.Unlock()
	if s.oidcInit.client != nil {
		return s.oidcInit.client, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	discover := cfg.Issuer
	if cfg.DiscoveryURL != "" {
		// Fetch metadata from the internal URL but still require tokens to be
		// issued by the public issuer.
		ctx = oidc.InsecureIssuerURLContext(ctx, cfg.Issuer)
		discover = cfg.DiscoveryURL
	}
	p, err := oidc.NewProvider(ctx, discover)
	if err != nil {
		return nil, fmt.Errorf("identity provider %s: %w", cfg.Issuer, err)
	}
	s.oidcInit.client = &oidcClient{
		cfg:      cfg,
		verifier: p.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		oauth: oauth2.Config{ClientID: cfg.ClientID, ClientSecret: rules.ExpandEnv(cfg.ClientSecret),
			Endpoint: p.Endpoint(), RedirectURL: cfg.RedirectURL, Scopes: cfg.Scopes},
	}
	var meta struct {
		EndSession string `json:"end_session_endpoint"`
	}
	if p.Claims(&meta) == nil {
		s.oidcInit.client.endSession = meta.EndSession
	}
	return s.oidcInit.client, nil
}

func loginError(w http.ResponseWriter, r *http.Request, msg string) {
	http.Redirect(w, r, "/login?error="+url.QueryEscape(msg), http.StatusFound)
}

// handleOIDCStart redirects to the identity provider.
func (s *Server) handleOIDCStart(w http.ResponseWriter, r *http.Request) {
	c, err := s.oidc(r.Context())
	if err != nil {
		s.log.Error("oidc", "err", err)
		loginError(w, r, "Single sign-on is unavailable: "+err.Error())
		return
	}
	st := oidcState{State: randomToken(""), Nonce: randomToken(""), Verifier: oauth2.GenerateVerifier(),
		Next: safeNext(r.URL.Query().Get("next")), ExpiresAt: time.Now().Add(10 * time.Minute).Unix()}
	http.SetCookie(w, &http.Cookie{Name: oidcCookie, Value: s.sign(st), Path: "/auth/", HttpOnly: true,
		Secure: s.secureCookie(r), SameSite: http.SameSiteLaxMode, MaxAge: 600})
	http.Redirect(w, r, c.oauth.AuthCodeURL(st.State, oidc.Nonce(st.Nonce), oauth2.S256ChallengeOption(st.Verifier)), http.StatusFound)
}

// handleOIDCCallback completes sign-in.
func (s *Server) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	fail := func(msg string, detail string) {
		s.audit.recordAs(r, Identity{User: "unknown", Method: "oidc"}, "login.oidc", "", "", "failed", detail, "")
		loginError(w, r, msg)
	}
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		fail("The identity provider refused the sign-in: "+e+" "+q.Get("error_description"), e)
		return
	}
	var st oidcState
	ck, err := r.Cookie(oidcCookie)
	if err != nil || !s.verify(ck.Value, &st) || time.Now().Unix() > st.ExpiresAt || q.Get("state") != st.State {
		fail("The sign-in expired or was tampered with. Please try again.", "bad or missing state")
		return
	}
	clearCookie(w, oidcCookie)
	c, err := s.oidc(r.Context())
	if err != nil {
		fail("Single sign-on is unavailable.", err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	tok, err := c.oauth.Exchange(ctx, q.Get("code"), oauth2.VerifierOption(st.Verifier))
	if err != nil {
		fail("Could not complete sign-in with the identity provider.", "code exchange: "+err.Error())
		return
	}
	raw, _ := tok.Extra("id_token").(string)
	idt, err := c.verifier.Verify(ctx, raw)
	if err != nil {
		fail("The identity provider's token was not valid.", "id token: "+err.Error())
		return
	}
	if idt.Nonce != st.Nonce {
		fail("The sign-in response did not match this browser. Please try again.", "nonce mismatch")
		return
	}
	var claims map[string]any
	if err := idt.Claims(&claims); err != nil {
		fail("Could not read the identity provider's response.", err.Error())
		return
	}
	id, err := identityFromClaims(claims, c.cfg)
	if err != nil {
		fail(err.Error(), err.Error())
		return
	}
	s.setSession(w, r, id)
	// Kept only for signing out of the identity provider too (id_token_hint).
	http.SetCookie(w, &http.Cookie{Name: idTokenCookie, Value: raw, Path: "/auth/", HttpOnly: true,
		Secure: s.secureCookie(r), SameSite: http.SameSiteLaxMode, MaxAge: int(s.cfg.Auth.SessionTTL.D().Seconds())})
	s.audit.recordAs(r, id, "login.oidc", id.User, "", "ok", fmt.Sprintf("groups: %s", strings.Join(id.Groups, ", ")), "")
	http.Redirect(w, r, safeNext(st.Next), http.StatusFound)
}

// identityFromClaims builds an identity from ID-token claims.
func identityFromClaims(claims map[string]any, cfg *OIDCConfig) (Identity, error) {
	str := func(k string) string { v, _ := claims[k].(string); return v }
	id := Identity{Method: "oidc", Name: str("name")}
	email := str("email")
	if email != "" {
		if v, ok := claims["email_verified"].(bool); ok && !v {
			return Identity{}, errors.New("your email address is not verified with the identity provider")
		}
		id.User = strings.ToLower(email)
	} else if u := str("preferred_username"); u != "" {
		id.User = strings.ToLower(u)
	} else {
		id.User = str("sub")
	}
	if len(cfg.AllowedDomains) > 0 {
		_, domain, _ := strings.Cut(email, "@")
		ok := false
		for _, d := range cfg.AllowedDomains {
			ok = ok || strings.EqualFold(domain, d)
		}
		if !ok {
			return Identity{}, fmt.Errorf("accounts from %q are not allowed to sign in here", domain)
		}
	}
	switch g := claims[cfg.GroupsClaim].(type) {
	case []any:
		for _, v := range g {
			if s, ok := v.(string); ok {
				id.Groups = append(id.Groups, strings.TrimPrefix(s, "/")) // Keycloak prefixes "/"
			}
		}
	case string:
		id.Groups = []string{strings.TrimPrefix(g, "/")}
	}
	return id, nil
}

const idTokenCookie = "grepalert_idt"

// providerLogoutURL returns where to send the browser to end the identity
// provider's session as well, or "" if the provider does not support it.
func (s *Server) providerLogoutURL(r *http.Request) string {
	c, err := s.oidc(r.Context())
	if err != nil || c.endSession == "" {
		return ""
	}
	q := url.Values{"client_id": {c.cfg.ClientID}}
	if ck, err := r.Cookie(idTokenCookie); err == nil && ck.Value != "" {
		q.Set("id_token_hint", ck.Value) // lets the provider skip its confirmation page
	}
	if u, err := url.Parse(c.cfg.RedirectURL); err == nil {
		u.Path, u.RawQuery = "/login", ""
		q.Set("post_logout_redirect_uri", u.String())
	}
	return c.endSession + "?" + q.Encode()
}
