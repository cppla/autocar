package security

import (
	"encoding/base64"
	"testing"
)

func TestConstantTimeEqual(t *testing.T) {
	if !ConstantTimeEqual("same", "same") {
		t.Fatal("equal strings were not equal")
	}
	for _, different := range []string{"", "Same", "same!", "a much longer value"} {
		if ConstantTimeEqual(different, "same") {
			t.Fatalf("%q unexpectedly matched", different)
		}
	}
}

func TestVerifyToken(t *testing.T) {
	if !VerifyToken("a-secret-token", "a-secret-token") {
		t.Fatal("valid token rejected")
	}
	if VerifyToken("wrong", "a-secret-token") {
		t.Fatal("invalid token accepted")
	}
	if VerifyToken("", "") {
		t.Fatal("empty configured token accepted")
	}
}

func TestVerifyBasicCredentials(t *testing.T) {
	if !VerifyBasicCredentials("alice", "correct horse", "alice", "correct horse") {
		t.Fatal("valid credentials rejected")
	}
	tests := []struct{ user, password, expectedUser, expectedPassword string }{
		{"mallory", "correct horse", "alice", "correct horse"},
		{"alice", "wrong", "alice", "correct horse"},
		{"mallory", "wrong", "alice", "correct horse"},
		{"", "", "", ""},
		{"alice", "", "alice", ""},
	}
	for _, test := range tests {
		if VerifyBasicCredentials(test.user, test.password, test.expectedUser, test.expectedPassword) {
			t.Fatalf("invalid credentials accepted: %#v", test)
		}
	}
}

func TestVerifyBasicAuthorization(t *testing.T) {
	valid := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:p:a:ss"))
	if !VerifyBasicAuthorization(valid, "alice", "p:a:ss") {
		t.Fatal("valid Basic header rejected")
	}
	if !VerifyBasicAuthorization("bAsIc "+base64.StdEncoding.EncodeToString([]byte("alice:secret")), "alice", "secret") {
		t.Fatal("case-insensitive Basic scheme rejected")
	}
	for _, header := range []string{
		"",
		"Bearer token",
		"Basic !!!",
		"Basic " + base64.StdEncoding.EncodeToString([]byte("missing-colon")),
		"Basic " + base64.StdEncoding.EncodeToString([]byte("alice:wrong")),
	} {
		if VerifyBasicAuthorization(header, "alice", "secret") {
			t.Fatalf("invalid header accepted: %q", header)
		}
	}
}
