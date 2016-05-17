package registry

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/docker/distribution/registry/client/auth"
	"github.com/docker/distribution/registry/client/transport"
	"github.com/docker/engine-api/types"
	registrytypes "github.com/docker/engine-api/types/registry"
)

const (
	// AuthClientID is used the ClientID used for the token server
	AuthClientID = "docker"
)

// loginV1 tries to register/login to the v1 registry server.
func loginV1(authConfig *types.AuthConfig, apiEndpoint APIEndpoint, userAgent string) (string, string, error) {
	registryEndpoint, err := apiEndpoint.ToV1Endpoint(userAgent, nil)
	if err != nil {
		return "", "", err
	}

	serverAddress := registryEndpoint.String()

	logrus.Debugf("attempting v1 login to registry endpoint %s", serverAddress)

	if serverAddress == "" {
		return "", "", fmt.Errorf("Server Error: Server Address not set.")
	}

	loginAgainstOfficialIndex := serverAddress == IndexServer

	req, err := http.NewRequest("GET", serverAddress+"users/", nil)
	if err != nil {
		return "", "", err
	}
	req.SetBasicAuth(authConfig.Username, authConfig.Password)
	resp, err := registryEndpoint.client.Do(req)
	if err != nil {
		// fallback when request could not be completed
		return "", "", fallbackError{
			err: err,
		}
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", "", err
	}
	if resp.StatusCode == http.StatusOK {
		return "Login Succeeded", "", nil
	} else if resp.StatusCode == http.StatusUnauthorized {
		if loginAgainstOfficialIndex {
			return "", "", fmt.Errorf("Wrong login/password, please try again. Haven't got a Docker ID? Create one at https://hub.docker.com")
		}
		return "", "", fmt.Errorf("Wrong login/password, please try again")
	} else if resp.StatusCode == http.StatusForbidden {
		if loginAgainstOfficialIndex {
			return "", "", fmt.Errorf("Login: Account is not active. Please check your e-mail for a confirmation link.")
		}
		// *TODO: Use registry configuration to determine what this says, if anything?
		return "", "", fmt.Errorf("Login: Account is not active. Please see the documentation of the registry %s for instructions how to activate it.", serverAddress)
	} else if resp.StatusCode == http.StatusInternalServerError { // Issue #14326
		logrus.Errorf("%s returned status code %d. Response Body :\n%s", req.URL.String(), resp.StatusCode, body)
		return "", "", fmt.Errorf("Internal Server Error")
	}
	return "", "", fmt.Errorf("Login: %s (Code: %d; Headers: %s)", body,
		resp.StatusCode, resp.Header)
}

type loginCredentialStore struct {
	authConfig *types.AuthConfig
}

func (lcs loginCredentialStore) Basic(*url.URL) (string, string) {
	return lcs.authConfig.Username, lcs.authConfig.Password
}

func (lcs loginCredentialStore) RefreshToken(*url.URL, string) string {
	return lcs.authConfig.IdentityToken
}

func (lcs loginCredentialStore) SetRefreshToken(u *url.URL, service, token string) {
	lcs.authConfig.IdentityToken = token
}

type fallbackError struct {
	err error
}

func (err fallbackError) Error() string {
	return err.err.Error()
}

// loginV2 tries to login to the v2 registry server. The given registry
// endpoint will be pinged to get authorization challenges. These challenges
// will be used to authenticate against the registry to validate credentials.
func loginV2(authConfig *types.AuthConfig, endpoint APIEndpoint, userAgent string) (string, string, error) {
	logrus.Debugf("attempting v2 login to registry endpoint %s", strings.TrimRight(endpoint.URL.String(), "/")+"/v2/")

	modifiers := DockerHeaders(userAgent, nil)
	authTransport := transport.NewTransport(NewTransport(endpoint.TLSConfig), modifiers...)

	challengeManager, foundV2, err := PingV2Registry(endpoint, authTransport)
	if err != nil {
		if !foundV2 {
			err = fallbackError{err: err}
		}
		return "", "", err
	}

	credentialAuthConfig := *authConfig
	creds := loginCredentialStore{
		authConfig: &credentialAuthConfig,
	}

	tokenHandlerOptions := auth.TokenHandlerOptions{
		Transport:     authTransport,
		Credentials:   creds,
		OfflineAccess: true,
		ClientID:      AuthClientID,
	}
	hmacHandler := auth.NewHMACHandler(creds)
	tokenHandler := auth.NewTokenHandlerWithOptions(tokenHandlerOptions)
	basicHandler := auth.NewBasicHandler(creds)
	modifiers = append(modifiers, auth.NewAuthorizer(challengeManager, hmacHandler, tokenHandler, basicHandler))
	tr := transport.NewTransport(authTransport, modifiers...)

	loginClient := &http.Client{
		Transport: tr,
		Timeout:   15 * time.Second,
	}

	endpointStr := strings.TrimRight(endpoint.URL.String(), "/") + "/v2/"
	req, err := http.NewRequest("GET", endpointStr, nil)
	if err != nil {
		if !foundV2 {
			err = fallbackError{err: err}
		}
		return "", "", err
	}

	resp, err := loginClient.Do(req)
	if err != nil {
		if !foundV2 {
			err = fallbackError{err: err}
		}
		return "", "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// TODO(dmcgowan): Attempt to further interpret result, status code and error code string
		err := fmt.Errorf("login attempt to %s failed with status: %d %s", endpointStr, resp.StatusCode, http.StatusText(resp.StatusCode))
		if !foundV2 {
			err = fallbackError{err: err}
		}
		return "", "", err
	}

	return "Login Succeeded", credentialAuthConfig.IdentityToken, nil

}

// ResolveAuthConfig matches an auth configuration to a server address or a URL
func ResolveAuthConfig(authConfigs map[string]types.AuthConfig, index *registrytypes.IndexInfo) types.AuthConfig {
	configKey := GetAuthConfigKey(index)
	// First try the happy case
	if c, found := authConfigs[configKey]; found || index.Official {
		return c
	}

	convertToHostname := func(url string) string {
		stripped := url
		if strings.HasPrefix(url, "http://") {
			stripped = strings.Replace(url, "http://", "", 1)
		} else if strings.HasPrefix(url, "https://") {
			stripped = strings.Replace(url, "https://", "", 1)
		}

		nameParts := strings.SplitN(stripped, "/", 2)

		return nameParts[0]
	}

	// Maybe they have a legacy config file, we will iterate the keys converting
	// them to the new format and testing
	for registry, ac := range authConfigs {
		if configKey == convertToHostname(registry) {
			return ac
		}
	}

	// When all else fails, return an empty auth config
	return types.AuthConfig{}
}

// PingResponseError is used when the response from a ping
// was received but invalid.
type PingResponseError struct {
	Err error
}

func (err PingResponseError) Error() string {
	return err.Error()
}

// PingV2Registry attempts to ping a v2 registry and on success return a
// challenge manager for the supported authentication types and
// whether v2 was confirmed by the response. If a response is received but
// cannot be interpreted a PingResponseError will be returned.
func PingV2Registry(endpoint APIEndpoint, transport http.RoundTripper) (auth.ChallengeManager, bool, error) {
	var (
		foundV2   = false
		v2Version = auth.APIVersion{
			Type:    "registry",
			Version: "2.0",
		}
	)

	pingClient := &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
	}
	endpointStr := strings.TrimRight(endpoint.URL.String(), "/") + "/v2/"
	req, err := http.NewRequest("GET", endpointStr, nil)
	if err != nil {
		return nil, false, err
	}
	resp, err := pingClient.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()

	versions := auth.APIVersions(resp, DefaultRegistryVersionHeader)
	for _, pingVersion := range versions {
		if pingVersion == v2Version {
			// The version header indicates we're definitely
			// talking to a v2 registry. So don't allow future
			// fallbacks to the v1 protocol.

			foundV2 = true
			break
		}
	}

	challengeManager := auth.NewSimpleChallengeManager()
	if err := challengeManager.AddResponse(resp); err != nil {
		return nil, foundV2, PingResponseError{
			Err: err,
		}
	}

	return challengeManager, foundV2, nil
}
