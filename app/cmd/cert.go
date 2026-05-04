package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

const defaultCertValidFor = 365 * 24 * time.Hour

var (
	certHost      string
	certFile      string
	certKey       string
	certValidFor  time.Duration
	certOverwrite bool
)

// certCmd represents the cert command
var certCmd = &cobra.Command{
	Use:   "cert",
	Short: "Generate a self-signed TLS certificate",
	Long:  "Generate a self-signed TLS certificate and print sample TLS config with pinSHA256.",
	Run:   runCertCmd,
}

func init() {
	initCertFlags()
	rootCmd.AddCommand(certCmd)
}

func initCertFlags() {
	certCmd.Flags().StringVar(&certHost, "host", defaultCertHost(), "comma-separated DNS names or IP addresses for certificate SANs")
	certCmd.Flags().StringVar(&certFile, "cert", "server.crt", "output certificate file")
	certCmd.Flags().StringVar(&certKey, "key", "server.key", "output private key file")
	certCmd.Flags().DurationVar(&certValidFor, "valid-for", defaultCertValidFor, "certificate validity duration")
	certCmd.Flags().BoolVar(&certOverwrite, "overwrite", false, "overwrite existing certificate and key files")
}

func runCertCmd(cmd *cobra.Command, args []string) {
	logger.Info("certificate generation mode")

	if len(args) != 0 {
		logger.Fatal("cert command does not accept arguments")
	}
	_, err := runCert(certOptions{
		Hosts:     certHost,
		CertFile:  certFile,
		KeyFile:   certKey,
		ValidFor:  certValidFor,
		Overwrite: certOverwrite,
		Out:       os.Stdout,
	})
	if err != nil {
		logger.Fatal("failed to generate certificate", zap.Error(err))
	}
}

type certOptions struct {
	Hosts     string
	CertFile  string
	KeyFile   string
	ValidFor  time.Duration
	Overwrite bool
	Out       io.Writer
}

type certResult struct {
	CertFile  string
	KeyFile   string
	PinSHA256 string
}

type certHosts struct {
	DNSNames    []string
	IPAddresses []net.IP
}

func runCert(options certOptions) (*certResult, error) {
	if options.Out == nil {
		options.Out = io.Discard
	}
	if options.CertFile == "" {
		return nil, errors.New("cert path is empty")
	}
	if options.KeyFile == "" {
		return nil, errors.New("key path is empty")
	}
	if options.CertFile == options.KeyFile {
		return nil, errors.New("cert and key paths must be different")
	}
	if options.ValidFor <= 0 {
		return nil, errors.New("valid-for must be positive")
	}
	hosts, err := parseCertHosts(options.Hosts)
	if err != nil {
		return nil, err
	}
	if !options.Overwrite {
		if err := checkCertOutputPaths(options.CertFile, options.KeyFile); err != nil {
			return nil, err
		}
	}
	certPEM, keyPEM, certDER, err := generateSelfSignedCert(hosts, options.ValidFor)
	if err != nil {
		return nil, err
	}
	if err := writeCertFile(options.CertFile, certPEM, 0o644, options.Overwrite); err != nil {
		return nil, err
	}
	if err := writeCertFile(options.KeyFile, keyPEM, 0o600, options.Overwrite); err != nil {
		return nil, err
	}
	result := &certResult{
		CertFile:  options.CertFile,
		KeyFile:   options.KeyFile,
		PinSHA256: certPinSHA256(certDER),
	}
	printCertResult(options.Out, result)
	return result, nil
}

func defaultCertHost() string {
	hostname, err := os.Hostname()
	if err != nil || strings.TrimSpace(hostname) == "" {
		return "localhost"
	}
	return hostname
}

func parseCertHosts(hostList string) (certHosts, error) {
	var hosts certHosts
	seen := make(map[string]struct{})
	for _, rawHost := range strings.Split(hostList, ",") {
		host := strings.TrimSpace(rawHost)
		if host == "" {
			return certHosts{}, errors.New("host list contains an empty entry")
		}
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}

		ipHost := host
		if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
			ipHost = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
		}
		if ip := net.ParseIP(ipHost); ip != nil {
			hosts.IPAddresses = append(hosts.IPAddresses, ip)
			continue
		}
		if strings.Contains(host, ":") {
			return certHosts{}, fmt.Errorf("host %q is not a valid IP address; omit ports from DNS names", host)
		}
		hosts.DNSNames = append(hosts.DNSNames, host)
	}
	if len(hosts.DNSNames) == 0 && len(hosts.IPAddresses) == 0 {
		return certHosts{}, errors.New("host list is empty")
	}
	return hosts, nil
}

func generateSelfSignedCert(hosts certHosts, validFor time.Duration) (certPEM, keyPEM, certDER []byte, err error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, nil, nil, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: firstCertHost(hosts)},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(validFor),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              hosts.DNSNames,
		IPAddresses:           hosts.IPAddresses,
	}
	certDER, err = x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, nil, nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if certPEM == nil || keyPEM == nil {
		return nil, nil, nil, errors.New("failed to encode certificate or key PEM")
	}
	return certPEM, keyPEM, certDER, nil
}

func firstCertHost(hosts certHosts) string {
	if len(hosts.DNSNames) > 0 {
		return hosts.DNSNames[0]
	}
	if len(hosts.IPAddresses) > 0 {
		return hosts.IPAddresses[0].String()
	}
	return ""
}

func checkCertOutputPaths(paths ...string) error {
	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("%s already exists; use --overwrite to replace it", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func writeCertFile(path string, data []byte, perm os.FileMode, overwrite bool) error {
	flags := os.O_WRONLY | os.O_CREATE
	if overwrite {
		flags |= os.O_TRUNC
	} else {
		flags |= os.O_EXCL
	}
	f, err := os.OpenFile(path, flags, perm)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%s already exists; use --overwrite to replace it", path)
		}
		return err
	}
	if err := f.Chmod(perm); err != nil {
		_ = f.Close()
		return err
	}
	n, err := f.Write(data)
	if err != nil {
		_ = f.Close()
		return err
	}
	if n != len(data) {
		_ = f.Close()
		return io.ErrShortWrite
	}
	return f.Close()
}

func certPinSHA256(certDER []byte) string {
	sum := sha256.Sum256(certDER)
	return hex.EncodeToString(sum[:])
}

func printCertResult(w io.Writer, result *certResult) {
	fmt.Fprintf(w, "Generated self-signed certificate:\n")
	fmt.Fprintf(w, "  Certificate: %s\n", result.CertFile)
	fmt.Fprintf(w, "  Private key: %s\n", result.KeyFile)
	fmt.Fprintf(w, "  pinSHA256: %s\n\n", result.PinSHA256)
	fmt.Fprintf(w, "Sample TLS config:\n\n")
	fmt.Fprintf(w, "# server.yaml\n")
	fmt.Fprintf(w, "tls:\n")
	fmt.Fprintf(w, "  cert: %s\n", result.CertFile)
	fmt.Fprintf(w, "  key: %s\n\n", result.KeyFile)
	fmt.Fprintf(w, "# client.yaml\n")
	fmt.Fprintf(w, "tls:\n")
	fmt.Fprintf(w, "  insecure: true\n")
	fmt.Fprintf(w, "  pinSHA256: %s\n\n", result.PinSHA256)
	fmt.Fprintf(w, "WARNING: insecure: true is only MITM-resistant when paired with the shown pinSHA256.\n")
}
