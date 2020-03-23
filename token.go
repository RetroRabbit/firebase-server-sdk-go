package firebase

// Token represents a decoded Firebase ID token.
//
// Token provides typed accessors to the common JWT fields such as Audience (aud) and Expiry (exp).
// Additionally it provides a UID field, which indicates the user ID of the account to which this token
// belongs. Any additional JWT claims can be accessed via the Claims map of Token.
type Token struct {
	Issuer   string                 `json:"iss"`
	Audience string                 `json:"aud"`
	Expires  int64                  `json:"exp"`
	IssuedAt int64                  `json:"iat"`
	Subject  string                 `json:"sub,omitempty"`
	UID      string                 `json:"uid,omitempty"`
	Claims   map[string]interface{} `json:"-"`
}

// IssuedAt returns the time this token was issued
func (t *Token) AuthTime() int64 {
	return t.Claims["auth_time"].(int64)
}

// Name returns the user's display name.
func (t *Token) Name() string {
	return t.Claims["name"].(string)
}

// Picture returns the URI string of the user's profile photo.
func (t *Token) Picture() string {
	return t.Claims["picture"].(string)
}

// Email returns the email address for this user, or nil if it's unavailable.
func (t *Token) Email() string {
	return t.Claims["email"].(string)
}

// IsEmailVerified indicates if the email address returned by Email() has been
// verified as good.
func (t *Token) IsEmailVerified() bool {
	return t.Claims["email_verified"].(bool)
}

// Claims returns all of the claims on this token.
func (t *Token) GetClaims() Claims {
	return Claims(t.Claims)
}

func (t *Token) SetClaims(claims map[string]interface{}) {
	if t.Claims == nil {
		t.Claims = claims
	} else {
		for key, val := range claims {
			t.Claims[key] = val
		}
	}
}
