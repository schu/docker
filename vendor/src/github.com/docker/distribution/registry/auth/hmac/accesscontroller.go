package hmac

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/docker/distribution/context"
	"github.com/docker/distribution/registry/auth"
)

var (
	// ErrInvalidCredential is returned when the auth token does not authenticate correctly.
	ErrInvalidCredential = errors.New("invalid authorization credential")

	// ErrAuthenticationFailure returned when authentication failure to be presented to agent.
	ErrAuthenticationFailure = errors.New("authentication failure")
)

type accessController struct {
	realm string
}

// challenge implements the auth.Challenge interface.
type challenge struct {
	realm string
	err   error
}

var _ auth.Challenge = challenge{}

// SetHeaders sets the basic challenge header on the response.
func (ch challenge) SetHeaders(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", fmt.Sprintf("Docker-HMAC-v1 realm=%q", ch.realm))
}

func (ch challenge) Error() string {
	return fmt.Sprintf("hmacdigest authentication challenge for realm %q: %s", ch.realm, ch.err)
}

func newAccessController(options map[string]interface{}) (auth.AccessController, error) {
	realm, present := options["realm"]
	if _, ok := realm.(string); !present || !ok {
		return nil, fmt.Errorf(`"realm" must be set for hmacdigest access controller`)
	}

	return &accessController{realm: realm.(string)}, nil
}

func (ac *accessController) Authorized(ctx context.Context, accessRecords ...auth.Access) (context.Context, error) {
	req, err := context.GetRequest(ctx)
	if err != nil {
		return nil, err
	}

	fmt.Printf("DEBUG Authorization: %s\n", req.Header.Get("Authorization"))
	parts := strings.Split(req.Header.Get("Authorization"), " ")

	if len(parts) != 2 || strings.ToLower(parts[0]) != "docker-hmac-v1" {
		return nil, &challenge{
			realm: ac.realm,
			err:   ErrInvalidCredential,
		}
	}

	hmac := parts[1]

	fmt.Printf("DEBUG hmacdigest: %s\n", hmac)

	// TODO(schu)

	return auth.WithUser(ctx, auth.UserInfo{Name: "TODO"}), nil
}

func init() {
	auth.Register("docker-hmac-v1", auth.InitFunc(newAccessController))
}
