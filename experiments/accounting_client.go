// Independent standard-library HTTP/TLS client reference for the accounting study.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
)

type command struct {
	Action      string `json:"action"`
	Protocol    string `json:"protocol"`
	Scenario    string `json:"scenario"`
	Prefix      string `json:"prefix"`
	Concurrency int    `json:"concurrency"`
}

func opaqueID(prefix string, index, retry int) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s/%d/%d", prefix, index, retry)))
	return hex.EncodeToString(sum[:])[:24]
}

func transport(port int, roots *x509.CertPool, protocol string) *http.Transport {
	p := new(http.Protocols)
	p.SetHTTP1(protocol == "http1")
	p.SetHTTP2(protocol == "http2")
	t := &http.Transport{Protocols: p, ForceAttemptHTTP2: protocol == "http2",
		TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "api.openai.com", MinVersion: tls.VersionTLS12},
		MaxConnsPerHost: 32, MaxIdleConnsPerHost: 32, Proxy: nil}
	if protocol == "http2" {
		t.MaxConnsPerHost, t.MaxIdleConnsPerHost = 1, 1
	}
	t.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", port))
	}
	return t
}

func attempt(client *http.Client, c command, index, retry int) (map[string]any, error) {
	aid := opaqueID(c.Prefix, index, retry)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	body := []byte(`{"model":"gpt-fixture","messages":[{"role":"user","content":"fixture"}],"stream":true,"stream_options":{"include_usage":true}}`)
	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.openai.com/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Fixture-Attempt-Id", aid)
	req.Header.Set("X-Fixture-Scenario", c.Scenario)
	req.Header.Set("X-Fixture-Retry", fmt.Sprint(retry))
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if (c.Protocol == "http2") != (resp.ProtoMajor == 2) {
		return nil, fmt.Errorf("negotiated unexpected protocol %s", resp.Proto)
	}
	row := map[string]any{"attempt_id": aid, "task_id": fmt.Sprintf("%s-task%d", c.Prefix, index),
		"response_id": nil, "status": resp.StatusCode, "usage": nil, "sse_done": false, "termination": "complete"}
	if resp.StatusCode != 200 {
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		var result struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(data, &result); err != nil {
			return nil, err
		}
		row["response_id"] = result.ID
		return row, nil
	}
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 4096), 2*1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		data := strings.TrimPrefix(line, "data: ")
		if data == "[DONE]" {
			row["sse_done"] = true
			continue
		}
		var event struct {
			ID    string         `json:"id"`
			Usage map[string]int `json:"usage"`
		}
		if err := json.Unmarshal([]byte(data), &event); err != nil {
			return nil, err
		}
		if event.ID != "" {
			row["response_id"] = event.ID
		}
		if event.Usage != nil {
			row["usage"] = event.Usage
		}
		if c.Scenario == "cancel" {
			cancel()
			resp.Body.Close()
			row["termination"] = "client_cancel"
			return row, nil
		}
	}
	if err := scanner.Err(); err != nil {
		if c.Scenario != "disconnect" {
			return nil, err
		}
		row["termination"] = "server_disconnect"
	}
	return row, nil
}

func batch(client *http.Client, c command) ([]map[string]any, error) {
	var wg sync.WaitGroup
	rows := make(chan map[string]any, 2*c.Concurrency)
	errs := make(chan error, c.Concurrency)
	for i := 0; i < c.Concurrency; i++ {
		wg.Go(func() {
			first, err := attempt(client, c, i, 0)
			if err != nil {
				errs <- err
				return
			}
			rows <- first
			if c.Scenario == "retry" {
				if first["status"] != 429 {
					errs <- fmt.Errorf("retry fixture did not receive 429")
					return
				}
				second, err := attempt(client, c, i, 1)
				if err != nil {
					errs <- err
				} else {
					rows <- second
				}
			}
		})
	}
	wg.Wait()
	close(rows)
	close(errs)
	for err := range errs {
		return nil, err
	}
	result := make([]map[string]any, 0, len(rows))
	for row := range rows {
		result = append(result, row)
	}
	return result, nil
}

func cpu(r syscall.Rusage) float64 {
	return float64(r.Utime.Sec+r.Stime.Sec) + float64(r.Utime.Usec+r.Stime.Usec)/1e6
}

func main() {
	port := flag.Int("port", 0, "loopback fixture port")
	cert := flag.String("cert", "", "fixture certificate")
	flag.Parse()
	pem, err := os.ReadFile(*cert)
	if err != nil {
		panic(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		panic("invalid fixture certificate")
	}
	enc := json.NewEncoder(os.Stdout)
	enc.Encode(map[string]any{"ready": true})
	input := bufio.NewScanner(os.Stdin)
	var warm *http.Transport
	for input.Scan() {
		var c command
		if err := json.Unmarshal(input.Bytes(), &c); err != nil {
			panic(err)
		}
		if c.Action == "stop" {
			if warm != nil {
				warm.CloseIdleConnections()
			}
			return
		}
		t := warm
		warm = nil
		if t == nil {
			t = transport(*port, roots, c.Protocol)
		}
		if c.Action == "warm" {
			c.Scenario, c.Concurrency = "complete", 1
		}
		client := &http.Client{Transport: t, Timeout: 15 * time.Second}
		var before, after syscall.Rusage
		syscall.Getrusage(syscall.RUSAGE_SELF, &before)
		start := time.Now()
		rows, err := batch(client, c)
		syscall.Getrusage(syscall.RUSAGE_SELF, &after)
		result := map[string]any{"attempts": rows, "duration_seconds": time.Since(start).Seconds(),
			"client_cpu_seconds": cpu(after) - cpu(before), "client_peak_rss_kib": after.Maxrss}
		if err != nil {
			result = map[string]any{"error": err.Error()}
		}
		if c.Action == "warm" && err == nil {
			warm = t
			result["warm"] = true
		} else {
			t.CloseIdleConnections()
		}
		enc.Encode(result)
	}
	if err := input.Err(); err != nil {
		panic(err)
	}
}
