package hazexpired

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"testing"
	"time"
)

// genCerts is a test case helper that will create certificates with the specified expiration date
//    cert, key, err := genCerts(time.Now().Add(900 * time.Hour))
func genCerts(date time.Time) ([]byte, []byte, error) {
	// Create ca signing key
	ca := &x509.Certificate{
		Subject: pkix.Name{
			Organization: []string{"I Can Haz Expired Certs"},
		},
		SerialNumber:          big.NewInt(42),
		NotBefore:             date.Truncate(8760 * time.Hour),
		NotAfter:              date,
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// Create a private key
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, fmt.Errorf("Could not generate rsa key - %s", err)
	}

	// Use ca key to sign a CSR and create a public Cert
	csr := &key.PublicKey
	cert, err := x509.CreateCertificate(rand.Reader, ca, ca, csr, key)
	if err != nil {
		return nil, nil, fmt.Errorf("Could not generate certificate - %s", err)
	}

	// Convert keys into []byte
	c := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})
	k := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return c, k, nil
}

// startListener will start a TLS listener and return the listener which can be used for control actions like l.Close()
func startListener(cert, key []byte) (net.Listener, error) {
	// Load the cert and key into a tls.Config{}
	certs, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return nil, fmt.Errorf("Could not start test listener - %s", err)
	}
	conf := tls.Config{Certificates: []tls.Certificate{certs}}

	// Start the tls listener
	l, err := tls.Listen("tcp", "0.0.0.0:9000", &conf)
	if err != nil {
		return nil, fmt.Errorf("Could not start test listener - %s", err)
	}

	// Create a routine for accepting new connections
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			// Try to read from connections, tls handshakes occur on first read attempt
			go func() {
				b := make([]byte, 2)
				_, _ = conn.Read(b)
				return
			}()
		}
	}()

	return l, nil
}

// Test with an Address/Port that doesn't resolve
func TestInvalidAddress(t *testing.T) {
	t.Run("FetchChain", func(t *testing.T) {
		_, err := FetchChain("iamateapot:418")
		if err == nil {
			t.Errorf("Expected failure when calling with an invalid address, err is nil")
		}
	})

	t.Run("Expired", func(t *testing.T) {
		_, err := Expired("iamateapot:418")
		if err == nil {
			t.Errorf("Expected failure when calling with an invalid address, err is nil")
		}
	})

	t.Run("ExiresWithinDays", func(t *testing.T) {
		_, err := ExpiresWithinDays("iamateapot:418", 30)
		if err == nil {
			t.Errorf("Expected failure when calling with an invalid address, err is nil")
		}
	})

	t.Run("ExpiresBeforeDate", func(t *testing.T) {
		_, err := ExpiresBeforeDate("iamateapot:418", time.Now())
		if err == nil {
			t.Errorf("Expected failure when calling with an invalid address, err is nil")
		}
	})
}

// Test with a valid Address/Port and valid certificate chain
func TestHappyPathGoodCert(t *testing.T) {
	// Create cert/key pair
	cert, key, err := genCerts(time.Now().Add(900 * time.Hour))
	if err != nil {
		t.Logf("Unable to generate test certificates - %s", err)
		t.FailNow()
	}

	// Start Listener
	l, err := startListener(cert, key)
	if err != nil {
		t.Logf("%s", err)
		t.FailNow()
	}
	time.Sleep(30 * time.Millisecond)
	defer l.Close()

	// Start tests
	t.Run("FetchChain", func(t *testing.T) {
		var chain []*CertificateStatus
		chain, err := FetchChain("127.0.0.1:9000")
		if err != nil {
			t.Errorf("Unexpected failure when fetching Certificate Chain - %s", err)
		}
		for _, cert := range chain {
			if cert.ExpiredNow != false {
				t.Errorf("Unexpected expired certificate found - %+v", cert)
			}
		}
	})

	t.Run("Expired", func(t *testing.T) {
		var v bool
		v, err := Expired("127.0.0.1:9000")
		if err != nil {
			t.Errorf("Unexpected failure when testing for Expired certificates - %s", err)
		}
		if v {
			t.Errorf("Unexpected result when testing Expired on happy path expected false got %+v", v)
		}
	})

	t.Run("ExiresWithinDays", func(t *testing.T) {
		var v bool
		v, err := ExpiresWithinDays("127.0.0.1:9000", 30)
		if err != nil {
			t.Errorf("Unexpected failure when calling ExpiresWithinDays - %s", err)
		}
		if v {
			t.Errorf("Unexpected result when testing ExpiresWithinDays on happy path expected false got %+v", v)
		}
	})

	t.Run("ExpiresBeforeDate", func(t *testing.T) {
		var v bool
		v, err := ExpiresBeforeDate("127.0.0.1:9000", time.Now())
		if err != nil {
			t.Errorf("Unexpected failure when calling ExpiresBeforeDate - %s", err)
		}
		if v {
			t.Errorf("Unexpected result when testing ExpiredsBeforeDate on happy path expected false got %+v", v)
		}
	})
}

// Test with a valid Address/Port and expired certificate
func TestHappyPathExpiredCert(t *testing.T) {
	// Create cert/key pair
	cert, key, err := genCerts(time.Now().Truncate(24 * time.Hour))
	if err != nil {
		t.Logf("Unable to generate test certificates - %s", err)
		t.FailNow()
	}

	// Start Listener
	l, err := startListener(cert, key)
	if err != nil {
		t.Logf("%s", err)
		t.FailNow()
	}
	time.Sleep(30 * time.Millisecond)
	defer l.Close()

	// Start tests
	t.Run("FetchChain", func(t *testing.T) {
		var chain []*CertificateStatus
		chain, err := FetchChain("127.0.0.1:9000")
		if err != nil {
			t.Errorf("Unexpected failure when fetching Certificate Chain - %s", err)
		}
		found := false
		for _, cert := range chain {
			if cert.ExpiredNow == true {
				found = true
			}
		}
		if found == false {
			t.Errorf("Could not find an expected expired certificate")
		}
	})

	t.Run("Expired", func(t *testing.T) {
		var v bool
		v, err := Expired("127.0.0.1:9000")
		if err != nil {
			t.Errorf("Unexpected failure when testing for Expired certificates - %s", err)
		}
		if v == false {
			t.Errorf("Unexpected result when testing Expired on happy path expected true got %+v", v)
		}
	})

	t.Run("ExiresWithinDays", func(t *testing.T) {
		var v bool
		v, err := ExpiresWithinDays("127.0.0.1:9000", 30)
		if err != nil {
			t.Errorf("Unexpected failure when calling ExpiresWithinDays - %s", err)
		}
		if v == false {
			t.Errorf("Unexpected result when testing ExpiresWithinDays on happy path expected true got %+v", v)
		}
	})

	t.Run("ExpiresBeforeDate", func(t *testing.T) {
		var v bool
		v, err := ExpiresBeforeDate("127.0.0.1:9000", time.Now())
		if err != nil {
			t.Errorf("Unexpected failure when calling ExpiresBeforeDate - %s", err)
		}
		if v == false {
			t.Errorf("Unexpected result when testing ExpiredsBeforeDate on happy path expected true got %+v", v)
		}
	})
}

// Test a certificate that is expiring soon
func TestExpiringCert(t *testing.T) {
	// Create cert/key pair
	cert, key, err := genCerts(time.Now().Add(360 * time.Hour))
	if err != nil {
		t.Logf("Unable to generate test certificates - %s", err)
		t.FailNow()
	}

	// Start Listener
	l, err := startListener(cert, key)
	if err != nil {
		t.Logf("%s", err)
		t.FailNow()
	}
	time.Sleep(30 * time.Millisecond)
	defer l.Close()

	// Test if it expires within x days
	t.Run("ExpiresWithin30Days", func(t *testing.T) {
		var v bool
		v, err := ExpiresWithinDays("127.0.0.1:9000", 30)
		if err != nil {
			t.Errorf("Unexpected failure when calling ExpiresWithinDays - %s", err)
		}
		if v == false {
			t.Errorf("Unexpected result when testing ExpiresWithinDays with a cert that expires in 15 days, expected true and got %+v", v)
		}
	})

	// Test if it expires by x date
	t.Run("ExpiresBeforeDate", func(t *testing.T) {
		var v bool
		v, err := ExpiresBeforeDate("127.0.0.1:9000", time.Now().Add(720*time.Hour))
		if err != nil {
			t.Errorf("Unexpected failure when calling ExpiresBeforeDate - %s", err)
		}
		if v == false {
			t.Errorf("Unexpected result when testing ExpiredsBeforeDate with a cert that expires in 15 days, expected true got %+v", v)
		}
	})
}
