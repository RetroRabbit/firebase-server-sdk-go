package firebase

import (
	"context"
	"errors"
)

var (
	createSessionCookieAPI = &apiSettings{
		method:   "POST",
		endpoint: "createSessionCookie",
		reqFn: func(src interface{}) error {
			if r, ok := src.(*getAccountInfoRequest); !ok {
				return errIllegalType
			} else if s1, s2 := len(r.LocalID), len(r.Email); s1 == 0 && s2 == 0 {
				return errMissingRequestTarget
			}
			return nil
		},
		respFn: func(src interface{}) error {
			if _, ok := src.(*getAccountInfoResponse); !ok {
				return errIllegalType
			}
			return nil
		},
	}
)

type createSessionCookieRequest struct {
	IDToken  string `json:"idToken"`
	Duration int64  `json:"validDuration"`
}

type createSessionCookieResponse struct {
	SessionCookie string `json:"sessionCookie"`
}

func (h *requestHandler) createSessionCookie(idToken string, duration int64) (*string, error) {
	req := &createSessionCookieRequest{
		IDToken:  idToken,
		Duration: duration,
	}
	resp := new(createSessionCookieResponse)
	if err := h.call(createSessionCookieAPI, req, resp); err != nil {
		return nil, err
	}
	return &resp.SessionCookie, nil
}

// VerifySessionCookieAndCheckRevoked checks if the cookie is valid and has not been revoked
func (h *requestHandler) verifySessionCookieAndCheckRevoked(projectID string, cookie string) (*UserRecord, error) {
	token, err := h.verifySessionCookie(projectID, cookie)
	if err != nil {
		return nil, err
	}

	valid, err := h.checkRevoked(token)

	if err != nil {
		return nil, err
	}

	if !valid {
		return nil, errors.New("Token has been revoked")
	}

	uid := token.UID

	return h.getAccountByUID(uid)
}

// VerifySessionCookie checks if the cookie is valid
func (h *requestHandler) verifySessionCookie(projectID string, cookie string) (*Token, error) {
	verifier, err := newIDTokenVerifier(context.Background(), projectID)
	if err != nil {
		return nil, err
	}
	return verifier.VerifyToken(context.Background(), cookie)
}

// checkSessionCookieRevoked checks if the given session cookie has been revoked
func (h *requestHandler) checkSessionCookieRevoked(projectID string, cookie string) (bool, error) {
	token, err := h.verifySessionCookie(projectID, cookie)
	if err != nil {
		return false, err
	}

	valid, err := h.checkRevoked(token)

	return valid, err
}

// checkRevoked checks if the given session cookie has been revoked
func (h *requestHandler) checkRevoked(token *Token) (bool, error) {
	uid := token.UID

	user, err := h.getAccountByUID(uid)
	if err != nil {
		return false, err
	}

	iat := token.IssuedAt

	return ((int64)(iat*1000) < user.TokensValidAfterMillis), nil
}
