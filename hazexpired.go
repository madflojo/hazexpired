package hazexpired

import (
	"crypto/tls"
	"fmt"
	"math/big"
	"net"
	"time"
)

type CertificateStatus struct {
	ExpiredNow     bool
	ExpiresInDays  int
	ExpirationDate time.Time
	Signature      []byte
	SerialNumber   *big.Int
}

var dialer = &net.Dialer{
	Timeout: 3 * time.Second,
}

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
