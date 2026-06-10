package crypto

import "testing"

func TestDeviceCookieRoundTrip(t *testing.T) {
	secret := []byte("test-secret")
	value, err := NewDeviceCookieValue(secret)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	id, ok := VerifyDeviceCookieValue(value, secret)
	if !ok || id == "" {
		t.Fatalf("expected valid cookie, got id=%q ok=%v", id, ok)
	}
}

func TestDeviceCookieRejectsTampering(t *testing.T) {
	secret := []byte("test-secret")
	value, _ := NewDeviceCookieValue(secret)

	if _, ok := VerifyDeviceCookieValue(value, []byte("other-secret")); ok {
		t.Fatal("accepted cookie signed with another secret")
	}
	if _, ok := VerifyDeviceCookieValue("v1.deadbeef.deadbeef", secret); ok {
		t.Fatal("accepted forged signature")
	}
	for _, bad := range []string{"", "v1.", "v0.id.sig", "junk", "v1..sig"} {
		if _, ok := VerifyDeviceCookieValue(bad, secret); ok {
			t.Fatalf("accepted malformed value %q", bad)
		}
	}
}
