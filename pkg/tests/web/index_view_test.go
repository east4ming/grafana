package web

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/tests/testinfra"
)

// TestIntegrationIndexView tests the Grafana index view.
func TestIntegrationIndexView(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	t.Run("CSP enabled", func(t *testing.T) {
		grafDir, cfgPath := testinfra.CreateGrafDir(t, testinfra.GrafanaOpts{
			EnableCSP: true,
		})

		addr, _ := testinfra.StartGrafana(t, grafDir, cfgPath)

		// nolint:bodyclose
		resp, html := makeRequest(t, addr)
		assert.Regexp(t, `script-src 'self' 'unsafe-eval' 'unsafe-inline' 'strict-dynamic' 'nonce-[^']+';object-src 'none';font-src 'self';style-src 'self' 'unsafe-inline' blob:;img-src \* data:;base-uri 'self';connect-src 'self' grafana.com ws://localhost:3000/ wss://localhost:3000/;manifest-src 'self';media-src 'none';form-action 'self';`, resp.Header.Get("Content-Security-Policy"))
		assert.Regexp(t, `<script nonce="[^"]+"`, html)
	})

	t.Run("CSP disabled", func(t *testing.T) {
		grafDir, cfgPath := testinfra.CreateGrafDir(t)
		addr, _ := testinfra.StartGrafana(t, grafDir, cfgPath)

		// nolint:bodyclose
		resp, html := makeRequest(t, addr)

		assert.Empty(t, resp.Header.Get("Content-Security-Policy"))
		assert.Regexp(t, `<script nonce=""`, html)
	})

	//{identifier: '949028', intercomIdentifier: 'fd71c7d76b234b32e19ed38a7f59d18b0857e6a3d57f993d73b275d41417e266'}
	t.Run("Test the exposed user data contains the analytics identifiers", func(t *testing.T) {
		grafDir, cfgPath := testinfra.CreateGrafDir(t, testinfra.GrafanaOpts{
			EnableFeatureToggles: []string{"authnService"},
		})
		fmt.Println(cfgPath)

		addr, store := testinfra.StartGrafana(t, grafDir, cfgPath)

		// insert user_auth
		query := "INSERT INTO 'main'.'user_auth' ('id', 'user_id', 'auth_module', 'auth_id', 'created', 'o_auth_access_token', 'o_auth_refresh_token', 'o_auth_token_type', 'o_auth_expiry', 'o_auth_id_token') VALUES ('1', '1', 'oauth_grafana_com', 'test-id-oauth-grafana', '2023-03-13 14:08:11', '', '', '', '', '');"
		if r, err := store.GetEngine().Exec(query); err != nil {
			assert.Fail(t, err.Error())
		} else {
			fmt.Println(r.LastInsertId())
		}

		query = "UPDATE 'main'.'user' SET email = 'bogus@email.com';"
		if r, err := store.GetEngine().Exec(query); err != nil {
			assert.Fail(t, err.Error())
		} else {
			fmt.Println(r.LastInsertId())
		}

		query = "SELECT * FROM user WHERE id = 1;"
		if r, err := store.GetEngine().Query(query); err != nil {
			assert.Fail(t, err.Error())
		} else {
			fmt.Println(r)
		}

		// nolint:bodyclose
		_, html := makeRequest(t, addr)

		// parse User JSON object from HTML view
		parsedHTML := strings.Split(html, "user: ")[1]
		parsedHTML = strings.Split(parsedHTML, ",\n")[0]

		var jsonMap map[string]interface{}
		err := json.Unmarshal([]byte(parsedHTML), &jsonMap)
		if err != nil {
			assert.Fail(t, err.Error())
		}

		fmt.Println(jsonMap["analytics"])
		assert.Fail(t, "UNIMPLEMENTED")
	})
}

/*
dir, path := testinfra.CreateGrafDir(t, testinfra.GrafanaOpts{
		DisableLegacyAlerting:          true,
		EnableUnifiedAlerting:          true,
		DisableAnonymous:               true,
		NGAlertAdminConfigPollInterval: 2 * time.Second,
		UnifiedAlertingDisabledOrgs:    []int64{disableOrgID}, // disable unified alerting for organisation 3
		AppModeProduction:              true,
	})

	grafanaListedAddr, s := testinfra.StartGrafana(t, dir, path)

	orgService, err := orgimpl.ProvideService(s, s.Cfg, q
	apiClient := newAlertingApiClient(grafanaListedAddr, "grafana", "password")
*/

func makeRequest(t *testing.T, addr string) (*http.Response, string) {
	t.Helper()

	u := fmt.Sprintf("http://%s", addr)
	t.Logf("Making GET request to %s", u)
	// nolint:gosec
	resp, err := http.Get(u)
	require.NoError(t, err)
	require.NotNil(t, resp)
	t.Cleanup(func() {
		err := resp.Body.Close()
		assert.NoError(t, err)
	})

	var b strings.Builder
	_, err = io.Copy(&b, resp.Body)
	require.NoError(t, err)
	require.Equal(t, 200, resp.StatusCode)

	return resp, b.String()
}
