package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/shyim/agm/internal/db"
)

const (
	clientID     = "1071006060591-tmhssin2h21lcre235vtolojh4g403ep.apps.googleusercontent.com"
	clientSecret = "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"
	userAgent    = "antigravity/1.11.3 Darwin/arm64"
	urlToken     = "https://oauth2.googleapis.com/token"
	urlAuth      = "https://accounts.google.com/o/oauth2/v2/auth"
	urlUserInfo  = "https://www.googleapis.com/oauth2/v2/userinfo"
	urlQuota     = "https://daily-cloudcode-pa.sandbox.googleapis.com/v1internal:fetchAvailableModels"
	urlProject   = "https://cloudcode-pa.googleapis.com/v1internal:loadCodeAssist"
)

var oauthScopes = strings.Join([]string{
	"https://www.googleapis.com/auth/cloud-platform",
	"https://www.googleapis.com/auth/userinfo.email",
	"https://www.googleapis.com/auth/userinfo.profile",
	"https://www.googleapis.com/auth/cclog",
	"https://www.googleapis.com/auth/experimentsandconfigs",
	"https://www.googleapis.com/auth/aicode",
}, " ")

var httpClient = &http.Client{Timeout: 30 * time.Second}

// TokenResponse is a Google OAuth token response.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	IDToken      string `json:"id_token"`
	Scope        string `json:"scope"`
}

// UserInfo is Google userinfo.
type UserInfo struct {
	ID      string `json:"id"`
	Email   string `json:"email"`
	Name    string `json:"name"`
	Picture string `json:"picture"`
}

// AuthURL builds the Google OAuth authorization URL for the given redirect.
func AuthURL(redirectURI string) string {
	params := url.Values{}
	params.Set("access_type", "offline")
	params.Set("scope", oauthScopes)
	params.Set("prompt", "consent")
	params.Set("response_type", "code")
	params.Set("client_id", clientID)
	params.Set("redirect_uri", redirectURI)
	params.Set("include_granted_scopes", "true")
	return urlAuth + "?" + params.Encode()
}

// ExchangeCode swaps an auth code for tokens.
func ExchangeCode(code, redirectURI string) (*TokenResponse, error) {
	form := url.Values{}
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("grant_type", "authorization_code")

	req, err := http.NewRequest(http.MethodPost, urlToken, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("token exchange failed (%d): %s", resp.StatusCode, truncate(string(body), 300))
	}
	var tr TokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, err
	}
	if tr.AccessToken == "" {
		return nil, fmt.Errorf("token exchange returned empty access_token")
	}
	return &tr, nil
}

// FetchUserInfo loads the Google profile for an access token.
func FetchUserInfo(accessToken string) (*UserInfo, error) {
	req, err := http.NewRequest(http.MethodGet, urlUserInfo, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("userinfo failed (%d): %s", resp.StatusCode, truncate(string(body), 200))
	}
	var u UserInfo
	if err := json.Unmarshal(body, &u); err != nil {
		return nil, err
	}
	return &u, nil
}

// LoginInteractive runs a local OAuth callback server, opens the browser, and returns tokens + profile.
func LoginInteractive(onURL func(authURL string)) (*TokenResponse, *UserInfo, error) {
	ports := []int{8888, 8889, 8890, 8891, 8892}
	var ln net.Listener
	var port int
	var listenErr error
	for _, p := range ports {
		ln, listenErr = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p))
		if listenErr == nil {
			port = p
			break
		}
	}
	if ln == nil {
		return nil, nil, fmt.Errorf("no free OAuth callback port (tried 8888-8892): %v", listenErr)
	}

	redirectURI := fmt.Sprintf("http://localhost:%d/oauth-callback", port)
	codeCh := make(chan string, 1)
	errCh := make(chan error, 1)

	mux := http.NewServeMux()
	mux.HandleFunc("/oauth-callback", func(w http.ResponseWriter, r *http.Request) {
		if errParam := r.URL.Query().Get("error"); errParam != "" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("<html><body><h1>Login failed</h1><p>" + errParam + "</p></body></html>"))
			errCh <- fmt.Errorf("oauth error: %s", errParam)
			return
		}
		code := r.URL.Query().Get("code")
		if code == "" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("missing code"))
			errCh <- fmt.Errorf("missing code")
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<html><body style="font-family:sans-serif;text-align:center;padding-top:50px">
			<h1>Login successful</h1>
			<p>You can close this window and return to the terminal.</p>
			<script>setTimeout(()=>window.close(),2000)</script>
			</body></html>`))
		codeCh <- code
	})

	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	authURL := AuthURL(redirectURI)
	if onURL != nil {
		onURL(authURL)
	}
	_ = openBrowser(authURL)

	select {
	case code := <-codeCh:
		tr, err := ExchangeCode(code, redirectURI)
		if err != nil {
			return nil, nil, err
		}
		ui, err := FetchUserInfo(tr.AccessToken)
		if err != nil {
			return tr, nil, err
		}
		return tr, ui, nil
	case err := <-errCh:
		return nil, nil, err
	case <-time.After(5 * time.Minute):
		return nil, nil, fmt.Errorf("timed out waiting for OAuth callback")
	}
}

// LoginAndSave runs interactive OAuth and upserts the account into the standalone DB.
func LoginAndSave(onURL func(string)) (*db.Account, error) {
	if err := db.EnsureStore(); err != nil {
		return nil, err
	}
	tr, ui, err := LoginInteractive(onURL)
	if err != nil {
		return nil, err
	}
	if ui == nil || ui.Email == "" {
		return nil, fmt.Errorf("login succeeded but email is empty")
	}

	token := &db.Token{
		AccessToken:     tr.AccessToken,
		RefreshToken:    tr.RefreshToken,
		ExpiresIn:       tr.ExpiresIn,
		ExpiryTimestamp: time.Now().Unix() + tr.ExpiresIn,
		TokenType:       firstNonEmpty(tr.TokenType, "Bearer"),
		IDToken:         tr.IDToken,
		Email:           ui.Email,
		OAuthClientKey:  "antigravity_enterprise",
	}
	if token.RefreshToken == "" {
		return nil, fmt.Errorf("no refresh_token returned (Google only issues it with prompt=consent; try again)")
	}

	// Best-effort project id + quota
	if project, err := fetchProjectID(tr.AccessToken); err == nil && project != "" {
		token.ProjectID = project
	}
	quota, _ := FetchLiveQuota(tr.AccessToken)

	if err := db.UpsertAccount(ui.Email, ui.Name, ui.Picture, token, quota); err != nil {
		return nil, err
	}
	_ = db.SetActive(ui.Email)

	return db.FindAccount(ui.Email)
}

// ImportToken upserts a token (from IDE or credential store) after optional refresh + userinfo.
func ImportToken(token *db.Token, preferredEmail, preferredName string) (*db.Account, error) {
	if err := db.EnsureStore(); err != nil {
		return nil, err
	}
	if token == nil || token.RefreshToken == "" {
		return nil, fmt.Errorf("missing refresh token")
	}
	if tr, err := RefreshAccessToken(token.RefreshToken); err == nil {
		token.AccessToken = tr.AccessToken
		if tr.ExpiresIn > 0 {
			token.ExpiryTimestamp = time.Now().Unix() + tr.ExpiresIn
			token.ExpiresIn = tr.ExpiresIn
		}
		if tr.IDToken != "" {
			token.IDToken = tr.IDToken
		}
	}

	email := preferredEmail
	name := preferredName
	avatar := ""
	if ui, err := FetchUserInfo(token.AccessToken); err == nil && ui != nil {
		if ui.Email != "" {
			email = ui.Email
		}
		if ui.Name != "" {
			name = ui.Name
		}
		avatar = ui.Picture
	}
	// Prefer identity from the token itself when IDE auth-status email disagrees
	if jwtEmail := emailFromIDToken(token.IDToken); jwtEmail != "" {
		email = jwtEmail
	}
	if email == "" {
		return nil, fmt.Errorf("could not determine account email (userinfo failed and no hint)")
	}
	token.Email = email
	if name == "" {
		name = email
	}
	if project, err := fetchProjectID(token.AccessToken); err == nil {
		token.ProjectID = project
	}
	quota, _ := FetchLiveQuota(token.AccessToken)
	if err := db.UpsertAccount(email, name, avatar, token, quota); err != nil {
		return nil, err
	}
	return db.FindAccount(email)
}

// ImportFromIDE copies the currently signed-in IDE account into the standalone store.
func ImportFromIDE() (*db.Account, error) {
	if err := db.EnsureStore(); err != nil {
		return nil, err
	}
	email, err := db.GetIDEActiveEmail()
	if err != nil {
		return nil, fmt.Errorf("read IDE auth status: %w", err)
	}
	access, refresh, expiry, err := db.ReadIDEOAuthToken()
	if err != nil {
		return nil, err
	}
	if expiry == 0 {
		expiry = time.Now().Unix() + 3600
	}
	token := &db.Token{
		AccessToken:     access,
		RefreshToken:    refresh,
		ExpiryTimestamp: expiry,
		TokenType:       "Bearer",
		Email:           email,
	}
	acc, err := ImportToken(token, email, email)
	if err != nil {
		return nil, err
	}
	_ = db.SetActive(acc.Email)
	return acc, nil
}

// RefreshAccessToken refreshes an OAuth access token.
func RefreshAccessToken(refreshToken string) (*TokenResponse, error) {
	form := url.Values{}
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("refresh_token", refreshToken)
	form.Set("grant_type", "refresh_token")

	req, err := http.NewRequest(http.MethodPost, urlToken, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("token refresh failed (%d): %s", resp.StatusCode, truncate(string(body), 200))
	}
	var tr TokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, err
	}
	return &tr, nil
}

// FetchLiveQuota loads model quotas for an access token.
func FetchLiveQuota(accessToken string) (*db.Quota, error) {
	projectID, _ := fetchProjectID(accessToken)

	payload := map[string]any{}
	if projectID != "" {
		payload["project"] = projectID
	}
	raw, _ := json.Marshal(payload)

	req, err := http.NewRequest(http.MethodPost, urlQuota, strings.NewReader(string(raw)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("quota fetch failed (%d): %s", resp.StatusCode, truncate(string(body), 200))
	}

	var parsed struct {
		Models map[string]struct {
			QuotaInfo *struct {
				RemainingFraction float64 `json:"remainingFraction"`
				ResetTime         string  `json:"resetTime"`
			} `json:"quotaInfo"`
		} `json:"models"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, err
	}

	q := &db.Quota{Models: map[string]db.ModelQuota{}}
	for name, info := range parsed.Models {
		if info.QuotaInfo == nil {
			continue
		}
		q.Models[name] = db.ModelQuota{
			Percentage: int(info.QuotaInfo.RemainingFraction * 100),
			ResetTime:  info.QuotaInfo.ResetTime,
		}
	}
	return q, nil
}

func fetchProjectID(accessToken string) (string, error) {
	payload := []byte(`{"metadata":{"ideType":"ANTIGRAVITY"}}`)
	req, err := http.NewRequest(http.MethodPost, urlProject, strings.NewReader(string(payload)))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("status %d", resp.StatusCode)
	}
	var out struct {
		Project string `json:"cloudaicompanionProject"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	return out.Project, nil
}

// RefreshAccountQuota refreshes token + quota and persists both.
func RefreshAccountQuota(account *db.Account) error {
	if account.Token == nil || account.Token.RefreshToken == "" {
		return fmt.Errorf("no refresh token (decrypt failed?)")
	}

	tr, err := RefreshAccessToken(account.Token.RefreshToken)
	if err != nil {
		return err
	}
	account.Token.AccessToken = tr.AccessToken
	if tr.ExpiresIn > 0 {
		account.Token.ExpiryTimestamp = time.Now().Unix() + tr.ExpiresIn
		account.Token.ExpiresIn = tr.ExpiresIn
	}
	if tr.IDToken != "" {
		account.Token.IDToken = tr.IDToken
	}

	quota, err := FetchLiveQuota(tr.AccessToken)
	if err != nil {
		return err
	}
	if err := db.UpdateTokenJSON(account.Email, account.Token); err != nil {
		return err
	}
	return db.UpdateQuotaJSON(account.Email, quota)
}

// ValidateAccount refreshes token if expired and persists.
func ValidateAccount(account *db.Account) (valid bool, refreshed bool, err error) {
	if account.Token == nil {
		return false, false, fmt.Errorf("no token data")
	}
	if !db.IsTokenExpired(account.Token) {
		return true, false, nil
	}
	if account.Token.RefreshToken == "" {
		return false, false, fmt.Errorf("no refresh token")
	}
	tr, err := RefreshAccessToken(account.Token.RefreshToken)
	if err != nil {
		return false, false, err
	}
	account.Token.AccessToken = tr.AccessToken
	if tr.ExpiresIn > 0 {
		account.Token.ExpiryTimestamp = time.Now().Unix() + tr.ExpiresIn
		account.Token.ExpiresIn = tr.ExpiresIn
	}
	if err := db.UpdateTokenJSON(account.Email, account.Token); err != nil {
		return false, false, err
	}
	return true, true, nil
}

func openBrowser(u string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", u)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", u)
	default:
		cmd = exec.Command("xdg-open", u)
	}
	return cmd.Start()
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// emailFromIDToken extracts email from an OIDC JWT payload (no signature verify).
func emailFromIDToken(idToken string) string {
	parts := strings.Split(idToken, ".")
	if len(parts) < 2 {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		raw, err = base64.URLEncoding.DecodeString(parts[1])
		if err != nil {
			return ""
		}
	}
	var claims struct {
		Email string `json:"email"`
	}
	if json.Unmarshal(raw, &claims) != nil {
		return ""
	}
	return claims.Email
}
