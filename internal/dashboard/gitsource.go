package dashboard

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/fadhaw/grepalert/internal/rules"
)

const maxRulesSize = 1 << 20

// fetchSource downloads the rules file described by s.
func fetchSource(ctx context.Context, client *http.Client, s GitSource) ([]byte, error) {
	req, err := sourceRequest(ctx, s)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRulesSize+1))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		msg := strings.TrimSpace(string(body))
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return nil, fmt.Errorf("%s: HTTP %d: %s", s.Provider, resp.StatusCode, msg)
	}
	if len(body) > maxRulesSize {
		return nil, fmt.Errorf("rules file larger than %d bytes", maxRulesSize)
	}
	return body, nil
}

func sourceRequest(ctx context.Context, s GitSource) (*http.Request, error) {
	var (
		u      string
		header = http.Header{}
		token  = rules.ExpandEnv(s.Token) // may be ${GITHUB_TOKEN}
	)
	switch s.Provider {
	case "github":
		base := strings.TrimSuffix(s.BaseURL, "/")
		if base == "" {
			base = "https://api.github.com"
		}
		u = fmt.Sprintf("%s/repos/%s/contents/%s?ref=%s", base, s.Repo,
			escapePath(s.Path), url.QueryEscape(s.Ref))
		header.Set("Accept", "application/vnd.github.raw")
		header.Set("X-GitHub-Api-Version", "2022-11-28")
		if token != "" {
			header.Set("Authorization", "Bearer "+token)
		}
	case "gitlab":
		base := strings.TrimSuffix(s.BaseURL, "/")
		if base == "" {
			base = "https://gitlab.com"
		}
		u = fmt.Sprintf("%s/api/v4/projects/%s/repository/files/%s/raw?ref=%s", base,
			url.PathEscape(s.Repo), url.PathEscape(s.Path), url.QueryEscape(s.Ref))
		if token != "" {
			header.Set("PRIVATE-TOKEN", token)
		}
	case "url":
		u = s.Path
		if token != "" {
			header.Set("Authorization", "Bearer "+token)
		}
	default:
		return nil, fmt.Errorf("unknown provider %q", s.Provider)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header = header
	req.Header.Set("User-Agent", "grepalert-dashboard")
	return req, nil
}

func escapePath(p string) string {
	parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
	for i, s := range parts {
		parts[i] = url.PathEscape(s)
	}
	return strings.Join(parts, "/")
}
