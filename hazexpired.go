// Package hazexpired provides simple functions that determine when a remote system's SSL/TLS certificates expire.
//
//    import hazexpired
//
//    check, err := hazexpired.Expired("example.com:443")
//    if err != nil {
//      // do something
//    }
//    if check {
//      // do something else
//    }
package hazexpired

import (
	"crypto/tls"
	"fmt"
	"math/big"
	"net"
	"time"
)

// CertificateStatus represents the status and metadata of a Certificate within the remote system's certificate chain.
type CertificateStatus struct {
	// ExpiredNow indicates if this certificate is expired currently
	ExpiredNow bool

	// ExpiresInDays is an numeric count of days this certificate will expire
	ExpiresInDays int

	// ExpirationDate is the datetime the certificate will expire
	ExpirationDate time.Time

	// Signature is the certificate signature
	Signature []byte

	// SerialNumber is the Serial Number from the certificate
	SerialNumber *big.Int
}

var dialer = &net.Dialer{
	Timeout: 3 * time.Second,
}

// FetchChain will fetch a remote system's certificate chain and return a CertificateStatus object for each certificate in the chain.
func FetchChain(address string) ([]*CertificateStatus, error) {
	conf := &tls.Config{InsecureSkipVerify: true}
	c, err := tls.DialWithDialer(dialer, "tcp", address, conf)
	if err != nil {
		return nil, fmt.Errorf("Could not establish connection to outbound address %s - %s", address, err)
	}
	defer c.Close()

	var chain []*CertificateStatus
	now := time.Now()
	for _, cert := range c.ConnectionState().PeerCertificates {
		status := &CertificateStatus{}
		// set expiration date
		status.ExpirationDate = cert.NotAfter
		// check if currently expired
		if cert.NotAfter.Before(now) {
			status.ExpiredNow = true
		}
		// extract number of days until expiration
		status.ExpiresInDays = int(cert.NotAfter.Sub(now).Hours() / 24)
		// grab certificate details for identification
		status.Signature = cert.Signature
		status.SerialNumber = cert.SerialNumber
		chain = append(chain, status)
	}
	return chain, nil
}

// Expired indicates whether there is an expired certificate within the remote system's certificate chain.
func Expired(address string) (bool, error) {
	chain, err := FetchChain(address)
	if err != nil {
		return true, fmt.Errorf("Error Fetching Certificate Chain - %s", err)
	}
	for _, cert := range chain {
		if cert.ExpiredNow {
			return true, nil
		}
	}
	return false, nil
}

// ExpiresWithinDays will return true if a certificate within the remote system's certificate chain expires within the specified number of days.
func ExpiresWithinDays(address string, days int) (bool, error) {
	chain, err := FetchChain(address)
	if err != nil {
		return true, fmt.Errorf("Error Fetching Certificate Chain - %s", err)
	}
	for _, cert := range chain {
		if cert.ExpiresInDays < days {
			return true, nil
		}
	}
	return false, nil
}

// ExpiresBeforeDate will return true if a certificate within the remote system's certificate chain expires before the specified date.
func ExpiresBeforeDate(address string, t time.Time) (bool, error) {
	chain, err := FetchChain(address)
	if err != nil {
		return true, fmt.Errorf("Error Fetching Certificate Chain - %s", err)
	}
	for _, cert := range chain {
		if cert.ExpirationDate.Before(t) {
			return true, nil
		}
	}
	return false, nil
}
