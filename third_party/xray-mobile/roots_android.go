//go:build android

// Go's crypto/x509 knows only Android's legacy /system/etc/security/cacerts,
// which stops being updated when the system image ships. Roots added since
// then live in the Conscrypt APEX, so a server chaining to one fails to
// verify here while every Android TLS stack accepts it.

package XRay

import "os"

// Set before the first handshake: crypto/x509 caches the root pool behind a
// sync.Once, and SSL_CERT_DIR replaces its directory list rather than adding
// to it. Missing directories are skipped, so one value covers every API level.
func init() {
	if os.Getenv("SSL_CERT_DIR") != "" {
		return
	}
	_ = os.Setenv("SSL_CERT_DIR", "/apex/com.android.conscrypt/cacerts:/system/etc/security/cacerts:/data/misc/keychain/certs-added")
}
