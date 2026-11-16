package wireproxy

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Given optional proxy TLS credentials, when a client sends a POST through the
// listener, then the origin receives its body and the client receives its reply.
func TestHTTPServerListenForwardsPost(t *testing.T) {
	certFile, keyFile, roots := httpTestTLSCredentials(t)
	for _, useTLS := range []bool{false, true} {
		name := "plain"
		if useTLS {
			name = "tls"
		}
		t.Run(name, func(t *testing.T) {
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				body, err := io.ReadAll(req.Body)
				if err != nil {
					t.Errorf("read origin request body: %v", err)
				}
				if req.Method != http.MethodPost || req.URL.Path != "/api" || string(body) != "hello" {
					t.Errorf("origin received %s %s with body %q", req.Method, req.URL.Path, body)
				}
				_, _ = io.WriteString(w, "reply from origin")
			}))
			t.Cleanup(origin.Close)

			server := &HTTPServer{
				config: &HTTPConfig{},
				dial: func(network, address string) (net.Conn, error) {
					return net.DialTimeout(network, address, 10*time.Second)
				},
			}
			if useTLS {
				server.config.CertFile = certFile
				server.config.KeyFile = keyFile
			}
			listener, err := server.listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			t.Cleanup(func() { _ = listener.Close() })
			served := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err == nil {
					server.serve(conn)
				}
				served <- err
			}()

			dialer := &net.Dialer{Timeout: 10 * time.Second}
			var client net.Conn
			if useTLS {
				client, err = tls.DialWithDialer(dialer, "tcp", listener.Addr().String(), &tls.Config{
					RootCAs: roots, ServerName: "localhost",
				})
			} else {
				client, err = dialer.Dial("tcp", listener.Addr().String())
			}
			if err != nil {
				t.Fatalf("connect to proxy: %v", err)
			}
			t.Cleanup(func() { _ = client.Close() })
			if err := client.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
				t.Fatal(err)
			}
			req, err := http.NewRequest(http.MethodPost, origin.URL+"/api", strings.NewReader("hello"))
			if err != nil {
				t.Fatal(err)
			}
			req.Close = true
			if err := req.WriteProxy(client); err != nil {
				t.Fatalf("send proxy request: %v", err)
			}
			response, err := http.ReadResponse(bufio.NewReader(client), req)
			if err != nil {
				t.Fatalf("read proxy response: %v", err)
			}
			defer func() { _ = response.Body.Close() }()
			body, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatalf("read proxy response body: %v", err)
			}
			if response.StatusCode != http.StatusOK || string(body) != "reply from origin" {
				t.Fatalf("proxy returned status %d with body %q", response.StatusCode, body)
			}
			if err := <-served; err != nil {
				t.Fatalf("accept proxy connection: %v", err)
			}
		})
	}
}

// Given incomplete or invalid TLS credentials, when the proxy starts listening,
// then it returns an error instead of accepting unencrypted requests.
func TestHTTPServerListenRejectsInvalidTLSCredentials(t *testing.T) {
	certFile, keyFile, _ := httpTestTLSCredentials(t)
	_, otherKeyFile, _ := httpTestTLSCredentials(t)
	invalidFile := filepath.Join(t.TempDir(), "invalid.pem")
	if err := os.WriteFile(invalidFile, []byte("invalid PEM"), 0o600); err != nil {
		t.Fatal(err)
	}
	missingFile := filepath.Join(t.TempDir(), "missing.pem")
	for _, tt := range []struct {
		name, certFile, keyFile string
	}{
		{"certificate_only", certFile, ""},
		{"key_only", "", keyFile},
		{"missing_certificate", missingFile, keyFile},
		{"missing_key", certFile, missingFile},
		{"invalid_certificate", invalidFile, keyFile},
		{"invalid_key", certFile, invalidFile},
		{"mismatched_key", certFile, otherKeyFile},
	} {
		t.Run(tt.name, func(t *testing.T) {
			server := &HTTPServer{config: &HTTPConfig{CertFile: tt.certFile, KeyFile: tt.keyFile}}
			listener, err := server.listen("tcp", "127.0.0.1:0")
			if listener != nil {
				_ = listener.Close()
				t.Error("invalid TLS credentials opened a listener")
			}
			if err == nil {
				t.Error("invalid TLS credentials did not produce an error")
			}
		})
	}
}

// Given a temporary directory, when credentials are generated, then the proxy
// gets a matching certificate/key pair and the client trusts only that certificate.
func httpTestTLSCredentials(t *testing.T) (certFile, keyFile string, roots *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{"localhost"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	certFile = filepath.Join(directory, "cert.pem")
	keyFile = filepath.Join(directory, "key.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	roots = x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		t.Fatal("could not trust test certificate")
	}
	return certFile, keyFile, roots
}
