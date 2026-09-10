package maxproto

import (
	"crypto/x509"
	_ "embed"
	"errors"
	"sync"
)

// onemeCAPEM is the "Russian Trusted Sub CA" that issues api2.oneme.ru's
// certificate. MAX's chain is not anchored in the system root store, so we
// carry the one CA we need instead of turning verification off.
//
// This is deliberately scoped: it is only ever loaded into the private pool
// returned by onemeRoots and handed to the MAX client's own tls.Config. It is
// never added to the system store, never installed process-wide, and cannot
// influence the trust decisions of any other TLS connection in this binary.
//
//go:embed oneme_ca.pem
var onemeCAPEM []byte

var (
	onemeRootsOnce sync.Once
	onemeRootsPool *x509.CertPool
	onemeRootsErr  error
)

// onemeRoots returns the private CertPool used to verify MAX's control-plane
// endpoint. Built once and reused.
func onemeRoots() (*x509.CertPool, error) {
	onemeRootsOnce.Do(func() {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(onemeCAPEM) {
			onemeRootsErr = errors.New("failed to parse embedded oneme CA")
			return
		}
		onemeRootsPool = pool
	})
	return onemeRootsPool, onemeRootsErr
}
