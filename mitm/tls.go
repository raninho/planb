package mitm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"net/http"
	"os"
	"time"
)

const (
	caMaxAge = 5 * 365 * 24 * time.Hour
	caUsage = x509.KeyUsageDigitalSignature |
		x509.KeyUsageContentCommitment |
		x509.KeyUsageKeyEncipherment |
		x509.KeyUsageDataEncipherment |
		x509.KeyUsageKeyAgreement |
		x509.KeyUsageCertSign |
		x509.KeyUsageCRLSign
)

type OneShotListener struct {
	C net.Conn
}

func (l *OneShotListener) Accept() (net.Conn, error) {
	if l.C == nil {
		return nil, errors.New("closed")
	}
	c := l.C
	l.C = nil
	return c, nil
}

func (l *OneShotListener) Close() error {
	return nil
}

func (l *OneShotListener) Addr() net.Addr {
	return l.C.LocalAddr()
}

// A onCloseConn implements net.Conn and calls its f on Close.
type OnCloseConn struct {
	net.Conn
	F func()
}

func (c *OnCloseConn) Close() error {
	if c.F != nil {
		c.F()
		c.F = nil
	}
	return c.Conn.Close()
}

func LoadCA(certFilePath string, keyFilePath string) (tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certFilePath, keyFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			hostname, _ := os.Hostname()
			return genCA(hostname, certFilePath, keyFilePath)
		}
		return tls.Certificate{}, err
	}

	cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])

	return cert, nil
}

func genCA(hostname string, certFilePath string, keyFilePath string) (tls.Certificate, error) {
	certPEM, keyPEM, err := genCertAndKeyPEM(hostname)
	if err != nil {
		return tls.Certificate{}, err
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, err
	}

	print("antes daqui")

	if err = ioutil.WriteFile(certFilePath, certPEM, 0644); err != nil {
		print("antes certFilePath")

		return tls.Certificate{}, err
	}

	if err = ioutil.WriteFile(keyFilePath, keyPEM, 0644); err != nil {
		print("antes keyFilePath")

		return tls.Certificate{}, err
	}

	return cert, nil
}

func genCertAndKeyPEM(name string) ([]byte, []byte, error) {
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             now,
		NotAfter:              now.Add(caMaxAge),
		KeyUsage:              caUsage,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
		SignatureAlgorithm:    x509.ECDSAWithSHA512,
	}

	key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, nil, err
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "ECDSA PRIVATE KEY",
		Bytes: keyDER,
	})

	return certPEM, keyPEM, nil
}

func GenCert(ca *tls.Certificate, names []string) (*tls.Certificate, error) {
	now := time.Now().Add(-1 * time.Hour).UTC()
	if !ca.Leaf.IsCA {
		return nil, errors.New("CA cert is not a CA")
	}
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %s", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: names[0]},
		NotBefore:             now,
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature |
			x509.KeyUsageContentCommitment |
			x509.KeyUsageKeyEncipherment |
			x509.KeyUsageDataEncipherment |
			x509.KeyUsageKeyAgreement |
			x509.KeyUsageCertSign |
			x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		DNSNames:              names,
		SignatureAlgorithm:    x509.ECDSAWithSHA512,
	}

	key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		return nil, err
	}
	x, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Leaf, key.Public(), ca.PrivateKey)
	if err != nil {
		return nil, err
	}
	cert := new(tls.Certificate)
	cert.Certificate = append(cert.Certificate, x)
	cert.PrivateKey = key
	cert.Leaf, _ = x509.ParseCertificate(x)
	return cert, nil
}

func Handshake(w http.ResponseWriter, config *tls.Config) (net.Conn, error) {
	var okHeader = []byte("HTTP/1.1 200 OK\r\n\r\n")

	raw, _, err := w.(http.Hijacker).Hijack()
	if err != nil {
		http.Error(w, "no upstream", 503)
		return nil, err
	}

	if _, err = raw.Write(okHeader); err != nil {
		raw.Close()
		return nil, err
	}

	conn := tls.Server(raw, config)
	err = conn.Handshake()
	if err != nil {
		conn.Close()
		raw.Close()
		return nil, err
	}

	return conn, nil
}

