package tinydoh

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

type Resolver struct {
	URL        string
	HTTPClient *http.Client
}

func (r *Resolver) lookup(dnsType dnsmessage.Type, host string) ([]dnsmessage.Resource, error) {
	url := r.URL
	if url == "" {
		return nil, errors.New("no DoH URL provided")
	}
	client := r.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	if !strings.HasSuffix(host, ".") {
		host += "."
	}
	name, err := dnsmessage.NewName(host)
	if err != nil {
		return nil, fmt.Errorf("failed to parse host %s: %w", host, err)
	}

	reqBuilder := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		RecursionDesired: true,
	})
	reqBuilder.EnableCompression()
	err = reqBuilder.StartQuestions()
	if err != nil {
		return nil, fmt.Errorf("failed to start dns questions for host %s: %w", host, err)
	}
	err = reqBuilder.Question(dnsmessage.Question{
		Name:  name,
		Type:  dnsType,
		Class: dnsmessage.ClassINET,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to build dns question for host %s: %w", host, err)
	}
	reqMsg, err := reqBuilder.Finish()
	if err != nil {
		return nil, fmt.Errorf("failed to finish dns message for host %s: %w", host, err)
	}
	httpReq, err := http.NewRequest("POST", url, strings.NewReader(string(reqMsg)))
	if err != nil {
		return nil, fmt.Errorf("failed to create http request for host %s: %w", host, err)
	}
	httpReq.Header.Set("Content-Type", "application/dns-message")

	httpResp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to perform http request for host %s: %w", host, err)
	}
	defer httpResp.Body.Close()
	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("non-200 status-code=%d for host %s", httpResp.StatusCode, host)
	}
	if httpResp.Header.Get("Content-Type") != "application/dns-message" {
		return nil, fmt.Errorf("unexpected content-type=%s for host %s", httpResp.Header.Get("Content-Type"), host)
	}

	// 64KB should be enough for all DNS response
	limitedBody := io.LimitReader(httpResp.Body, 65536)
	respMsg, err := io.ReadAll(limitedBody)
	if err != nil {
		return nil, fmt.Errorf("failed to read http response body for host %s: %w", host, err)
	}
	parser := dnsmessage.Parser{}
	header, err := parser.Start(respMsg)
	if err != nil {
		return nil, fmt.Errorf("failed to parse dns message header for host %s: %w", host, err)
	}
	if header.RCode != dnsmessage.RCodeSuccess {
		return nil, fmt.Errorf("dns query failed with %s for host %s", header.RCode, host)
	}
	err = parser.SkipAllQuestions()
	if err != nil {
		return nil, fmt.Errorf("failed to skip dns questions for host %s: %w", host, err)
	}
	answers, err := parser.AllAnswers()
	if err != nil {
		return nil, fmt.Errorf("failed to parse dns answers for host %s: %w", host, err)
	}
	return answers, nil
}

func (r *Resolver) LookupA(host string) ([]net.IP, error) {
	answers, err := r.lookup(dnsmessage.TypeA, host)
	if err != nil {
		return nil, err
	}
	var results []net.IP
	for _, rr := range answers {
		if rr.Header.Type == dnsmessage.TypeA {
			a := rr.Body.(*dnsmessage.AResource)
			results = append(results, a.A[:])
		}
	}
	return results, nil
}

func (r *Resolver) LookupAAAA(host string) ([]net.IP, error) {
	answers, err := r.lookup(dnsmessage.TypeAAAA, host)
	if err != nil {
		return nil, err
	}
	var results []net.IP
	for _, rr := range answers {
		if rr.Header.Type == dnsmessage.TypeAAAA {
			aaaa := rr.Body.(*dnsmessage.AAAAResource)
			results = append(results, aaaa.AAAA[:])
		}
	}
	return results, nil
}
