package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/grandcat/zeroconf"
)

type ServiceAsset struct {
	ServiceType string
	Name        string
	IPv4        string
	IPv6        string
	Hostname    string
	Port        int
	TTL         uint32
	Banner      string
}

func main() {
	cidr := flag.String("cidr", "", "Target IPv4 CIDR, e.g. 192.168.1.0/24")
	portsRaw := flag.String("ports", "1-65535", "Port range, e.g. 1-1024,445,5000-5010")
	mdnsWait := flag.Duration("wait", 8*time.Second, "mDNS browse wait time")
	connTimeout := flag.Duration("timeout", 2*time.Second, "Banner probe timeout")
	flag.Parse()

	if *cidr == "" {
		fmt.Fprintln(os.Stderr, "missing required flag: -cidr")
		os.Exit(1)
	}

	_, ipNet, err := net.ParseCIDR(*cidr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid cidr: %v\n", err)
		os.Exit(1)
	}
	portAllow, err := parsePorts(*portsRaw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid ports: %v\n", err)
		os.Exit(1)
	}

	ptrs, err := discoverServiceTypes(*mdnsWait)
	if err != nil {
		fmt.Fprintf(os.Stderr, "discover ptrs failed: %v\n", err)
		os.Exit(1)
	}
	sort.Strings(ptrs)

	var assets []ServiceAsset
	for _, st := range ptrs {
		items, derr := discoverServiceEntries(st, *mdnsWait)
		if derr != nil {
			continue
		}
		assets = append(assets, items...)
	}

	filtered := filterAssets(assets, ipNet, portAllow)
	enrichBanners(filtered, *connTimeout)
	printResult(filtered, ptrs)
}

func parsePorts(s string) (map[int]bool, error) {
	allow := make(map[int]bool)
	parts := strings.Split(strings.TrimSpace(s), ",")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if strings.Contains(p, "-") {
			lr := strings.SplitN(p, "-", 2)
			lo, err := strconv.Atoi(strings.TrimSpace(lr[0]))
			if err != nil {
				return nil, err
			}
			hi, err := strconv.Atoi(strings.TrimSpace(lr[1]))
			if err != nil {
				return nil, err
			}
			if lo < 1 || hi > 65535 || lo > hi {
				return nil, fmt.Errorf("bad range %q", p)
			}
			for i := lo; i <= hi; i++ {
				allow[i] = true
			}
			continue
		}
		v, err := strconv.Atoi(p)
		if err != nil {
			return nil, err
		}
		if v < 1 || v > 65535 {
			return nil, fmt.Errorf("port out of range: %d", v)
		}
		allow[v] = true
	}
	if len(allow) == 0 {
		return nil, fmt.Errorf("empty ports")
	}
	return allow, nil
}

func discoverServiceTypes(wait time.Duration) ([]string, error) {
	resolver, err := zeroconf.NewResolver(nil)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()

	entries := make(chan *zeroconf.ServiceEntry)
	defer close(entries)

	out := make(map[string]bool)
	go func() {
		for e := range entries {
			for _, ptr := range e.Text {
				if strings.HasSuffix(ptr, ".local.") {
					out[strings.TrimSuffix(ptr, ".local.")] = true
				} else if strings.Contains(ptr, "._") {
					out[ptr] = true
				}
			}
		}
	}()

	err = resolver.Browse(ctx, "_services._dns-sd._udp", "local.", entries)
	if err != nil {
		return nil, err
	}
	<-ctx.Done()

	var list []string
	for k := range out {
		list = append(list, k)
	}
	return list, nil
}

func discoverServiceEntries(serviceType string, wait time.Duration) ([]ServiceAsset, error) {
	resolver, err := zeroconf.NewResolver(nil)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()

	entries := make(chan *zeroconf.ServiceEntry)
	defer close(entries)

	var (
		mu     sync.Mutex
		result []ServiceAsset
	)
	go func() {
		for e := range entries {
			ipv4 := ""
			if len(e.AddrIPv4) > 0 {
				ipv4 = e.AddrIPv4[0].String()
			}
			ipv6 := ""
			if len(e.AddrIPv6) > 0 {
				ipv6 = e.AddrIPv6[0].String()
			}
			txt := strings.Join(e.Text, ",")
			mu.Lock()
			result = append(result, ServiceAsset{
				ServiceType: serviceType,
				Name:        e.Instance,
				IPv4:        ipv4,
				IPv6:        ipv6,
				Hostname:    strings.TrimSuffix(e.HostName, "."),
				Port:        e.Port,
				TTL:         e.TTL,
				Banner:      txt,
			})
			mu.Unlock()
		}
	}()

	err = resolver.Browse(ctx, serviceType, "local.", entries)
	if err != nil {
		return nil, err
	}
	<-ctx.Done()
	return result, nil
}

func filterAssets(in []ServiceAsset, ipNet *net.IPNet, portAllow map[int]bool) []ServiceAsset {
	var out []ServiceAsset
	for _, a := range in {
		if !portAllow[a.Port] {
			continue
		}
		ip := net.ParseIP(a.IPv4)
		if ip == nil || !ipNet.Contains(ip) {
			continue
		}
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Port == out[j].Port {
			return out[i].ServiceType < out[j].ServiceType
		}
		return out[i].Port < out[j].Port
	})
	return out
}

func enrichBanners(items []ServiceAsset, timeout time.Duration) {
	var wg sync.WaitGroup
	for i := range items {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			asset := &items[idx]
			probe := probeBanner(asset.IPv4, asset.Port, timeout)
			if asset.Banner != "" && probe != "" {
				asset.Banner = asset.Banner + " | " + probe
			} else if probe != "" {
				asset.Banner = probe
			}
		}(i)
	}
	wg.Wait()
}

func probeBanner(ip string, port int, timeout time.Duration) string {
	switch port {
	case 80, 8080, 8000, 5000:
		if v := httpProbe("http", ip, port, timeout); v != "" {
			return v
		}
	case 443, 8443, 9443, 86:
		if v := httpProbe("https", ip, port, timeout); v != "" {
			return v
		}
	case 445:
		if v := smbProbe(ip, port, timeout); v != "" {
			return v
		}
	case 548:
		return "afp: port-open"
	}
	return tcpFirstLineProbe(ip, port, timeout)
}

func httpProbe(schema, ip string, port int, timeout time.Duration) string {
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // nolint:gosec
		},
	}
	url := fmt.Sprintf("%s://%s:%d/", schema, ip, port)
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("User-Agent", "mdns-surveyor/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	_ = io.LimitReader(resp.Body, 512)
	server := resp.Header.Get("Server")
	if server == "" {
		server = "unknown"
	}
	return fmt.Sprintf("path=/,status=%d,server=%s", resp.StatusCode, server)
}

func smbProbe(ip string, port int, timeout time.Duration) string {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	_, _ = conn.Write([]byte{0x00, 0x00, 0x00, 0x90, 0xfe, 0x53, 0x4d, 0x42})
	buf := make([]byte, 128)
	n, _ := conn.Read(buf)
	if n > 0 {
		return "smb: negotiate-response"
	}
	return "smb: port-open"
}

func tcpFirstLineProbe(ip string, port int, timeout time.Duration) string {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil || strings.TrimSpace(line) == "" {
		return "tcp: port-open"
	}
	line = strings.TrimSpace(line)
	if len(line) > 120 {
		line = line[:120]
	}
	return "tcp-banner=" + line
}

func printResult(items []ServiceAsset, ptrs []string) {
	fmt.Println("services:")
	for _, a := range items {
		proto := strings.Trim(strings.TrimSuffix(a.ServiceType, ".local"), "_")
		fmt.Printf("%d/tcp %s:\n", a.Port, proto)
		fmt.Printf("Name=%s\n", a.Name)
		fmt.Printf("IPv4=%s\n", a.IPv4)
		if a.IPv6 != "" {
			fmt.Printf("IPv6=%s\n", a.IPv6)
		}
		fmt.Printf("Hostname=%s\n", a.Hostname)
		fmt.Printf("TTL=%d\n", a.TTL)
		if a.Banner != "" {
			fmt.Println(a.Banner)
		}
	}
	fmt.Println("answers:")
	fmt.Println("PTR:")
	for _, p := range ptrs {
		fmt.Printf("%s.local\n", p)
	}
}
