package utils

import (
	"crypto/tls"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	testListen   = "127.82.39.147:12947"
	testCAFile   = "./testcerts/ca"
	testCertFile = "./testcerts/cert"
	testKeyFile  = "./testcerts/key"
)

func TestCertificateLoaderPathError(t *testing.T) {
	assert.NoError(t, os.RemoveAll(testCertFile))
	assert.NoError(t, os.RemoveAll(testKeyFile))
	loader := LocalCertificateLoader{
		CertFile: testCertFile,
		KeyFile:  testKeyFile,
		SNIGuard: SNIGuardStrict,
	}
	err := loader.InitializeCache()
	var pathErr *os.PathError
	assert.ErrorAs(t, err, &pathErr)
}

func TestCertificateLoaderFullChain(t *testing.T) {
	assert.NoError(t, generateTestCertificate([]string{"example.com"}, "fullchain"))

	loader := LocalCertificateLoader{
		CertFile: testCertFile,
		KeyFile:  testKeyFile,
		SNIGuard: SNIGuardStrict,
	}
	assert.NoError(t, loader.InitializeCache())

	lis, err := tls.Listen("tcp", testListen, &tls.Config{
		GetCertificate: loader.GetCertificate,
	})
	assert.NoError(t, err)
	defer lis.Close()
	go http.Serve(lis, nil)

	assert.Error(t, runTestTLSClient("unmatched-sni.example.com"))
	assert.Error(t, runTestTLSClient(""))
	assert.NoError(t, runTestTLSClient("example.com"))
}

func TestCertificateLoaderNoSAN(t *testing.T) {
	assert.NoError(t, generateTestCertificate(nil, "selfsign"))

	loader := LocalCertificateLoader{
		CertFile: testCertFile,
		KeyFile:  testKeyFile,
		SNIGuard: SNIGuardDNSSAN,
	}
	assert.NoError(t, loader.InitializeCache())

	lis, err := tls.Listen("tcp", testListen, &tls.Config{
		GetCertificate: loader.GetCertificate,
	})
	assert.NoError(t, err)
	defer lis.Close()
	go http.Serve(lis, nil)

	assert.NoError(t, runTestTLSClient(""))
}

func TestCertificateLoaderReplaceCertificate(t *testing.T) {
	assert.NoError(t, generateTestCertificate([]string{"example.com"}, "fullchain"))

	loader := LocalCertificateLoader{
		CertFile: testCertFile,
		KeyFile:  testKeyFile,
		SNIGuard: SNIGuardStrict,
	}
	assert.NoError(t, loader.InitializeCache())

	lis, err := tls.Listen("tcp", testListen, &tls.Config{
		GetCertificate: loader.GetCertificate,
	})
	assert.NoError(t, err)
	defer lis.Close()
	go http.Serve(lis, nil)

	assert.NoError(t, runTestTLSClient("example.com"))
	assert.Error(t, runTestTLSClient("2.example.com"))

	assert.NoError(t, generateTestCertificate([]string{"2.example.com"}, "fullchain"))

	assert.Error(t, runTestTLSClient("example.com"))
	assert.NoError(t, runTestTLSClient("2.example.com"))
}

func generateTestCertificate(dnssan []string, certType string) error {
	args := []string{
		"certloader_test_gencert.py",
		"--ca", testCAFile,
		"--cert", testCertFile,
		"--key", testKeyFile,
		"--type", certType,
	}
	if len(dnssan) > 0 {
		args = append(args, "--dnssan", strings.Join(dnssan, ","))
	}
	cmd := exec.Command("python", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("Failed to generate test certificate: %s", out)
		return err
	}
	return nil
}

func runTestTLSClient(sni string) error {
	args := []string{
		"certloader_test_tlsclient.py",
		"--server", testListen,
		"--ca", testCAFile,
	}
	if sni != "" {
		args = append(args, "--sni", sni)
	}
	cmd := exec.Command("python", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("Failed to run test TLS client: %s", out)
		return err
	}
	return nil
}
