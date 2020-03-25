// Copyright 2017 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package firebase

import (
	"testing"
	"time"
)

func TestTokenClaims(t *testing.T) {
	authTime := time.Now().Unix()
	name := "test"
	picture := "https://img.url.com/img.png"
	email := "test@test.com"
	verified := true

	token := &Token{
		Audience: "aud",
		Expires:  100,
		IssuedAt: 100,
		Issuer:   "iss",
		Subject:  "sub",
		UID:      "uid",
		Claims: map[string]interface{}{
			"auth_time":      authTime,
			"name":           "test",
			"picture":        picture,
			"email":          email,
			"email_verified": verified,
		},
	}

	if token.AuthTime() != authTime {
		t.Errorf("token.authTime = %v; want = %v", token.AuthTime(), authTime)
	}

	if token.Name() != name {
		t.Errorf("token.name = %v; want = %v", token.Name(), name)
	}

	if token.Picture() != picture {
		t.Errorf("token.picture = %v; want = %v", token.Picture(), picture)
	}

	if token.Email() != email {
		t.Errorf("token.email = %v; want = %v", token.Email(), email)
	}

	if token.IsEmailVerified() != verified {
		t.Errorf("token.isEmailVerified = %v; want = %v", token.IsEmailVerified(), verified)
	}
}
func TestTokenEmptyClaims(t *testing.T) {
	token := &Token{
		Audience: "aud",
		Claims:   make(map[string]interface{}),
		Expires:  100,
		IssuedAt: 100,
		Issuer:   "iss",
		Subject:  "sub",
		UID:      "uid",
	}

	if token.AuthTime() != 0 {
		t.Errorf("token.authTime = %v; want = %v", token.AuthTime(), 0)
	}

	if token.Name() != "" {
		t.Errorf("token.name = %v; want = %v", token.Name(), "")
	}

	if token.Picture() != "" {
		t.Errorf("token.picture = %v; want = %v", token.Picture(), "")
	}

	if token.Email() != "" {
		t.Errorf("token.email = %v; want = %v", token.Email(), "")
	}

	if token.IsEmailVerified() != false {
		t.Errorf("token.isEmailVerified = %v; want = %v", token.IsEmailVerified(), false)
	}
}
