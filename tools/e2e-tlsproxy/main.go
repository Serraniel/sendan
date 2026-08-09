// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

// Command e2e-tlsproxy terminates TLS in front of an instance, for tests.
//
// It exists for one reason: `fetch` request streaming requires HTTP/2, and a
// browser only ever speaks HTTP/2 over TLS. The Sendan binary serves plain
// HTTP and expects a reverse proxy to terminate TLS, so without something in
// front of it the streaming upload path cannot be reached by a browser at all -
// and a path no test can reach is a path that rots.
//
// This is also the shape of a real deployment: TLS and HTTP/2 to the browser,
// HTTP/1.1 to the instance behind it. It is test tooling and is not shipped;
// the certificate is generated at startup, self-signed, and valid for an hour.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"
)

func main() {
	listen := flag.String("listen", ":18191", "address to serve TLS on")
	upstream := flag.String("upstream", "http://localhost:18091", "instance to proxy to")
	flag.Parse()

	target, err := url.Parse(*upstream)
	if err != nil {
		log.Fatalf("e2e-tlsproxy: upstream: %v", err)
	}

	certificate, err := selfSigned()
	if err != nil {
		log.Fatalf("e2e-tlsproxy: certificate: %v", err)
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	// The instance decides whether to send HSTS from its own configuration, and
	// a proxy that rewrote the request would change what is being tested. The
	// only thing added is the header a real deployment would add.
	director := proxy.Director
	proxy.Director = func(r *http.Request) {
		director(r)
		r.Header.Set("X-Forwarded-Proto", "https")
	}

	server := &http.Server{
		Addr:    *listen,
		Handler: proxy,
		// Left to Go's default ALPN, which offers h2 and http/1.1. h2 is the
		// point: it is what makes a streamed request body possible.
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12},
		ReadHeaderTimeout: 30 * time.Second,
	}

	log.Printf("e2e-tlsproxy: https://%s -> %s", *listen, target)
	if err := server.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("e2e-tlsproxy: %v", err)
	}
}

// selfSigned returns a certificate for localhost, valid for an hour.
//
// Generated rather than committed. A certificate in the tree is a certificate
// somebody eventually trusts somewhere it should not be, and one that expires
// within the hour cannot become that.
func selfSigned() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
