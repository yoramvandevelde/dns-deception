package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

type metricType int

const (
	metricA metricType = iota
	metricAAAA
	metricTXT
	metricMX
	metricOther
)

type metricResult int

const (
	resultReal metricResult = iota
	resultFake
	resultRefused
)

type metrics struct {
	counters [5][3]atomic.Int64
}

func (m *metrics) inc(t metricType, r metricResult) {
	m.counters[t][r].Add(1)
}

func (m *metrics) write(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintln(w, "# HELP dns_queries_total Total DNS queries handled")
	fmt.Fprintln(w, "# TYPE dns_queries_total counter")
	typeNames := map[metricType]string{
		metricA:     "A",
		metricAAAA:  "AAAA",
		metricTXT:   "TXT",
		metricMX:    "MX",
		metricOther: "other",
	}
	resultNames := map[metricResult]string{
		resultReal:    "real",
		resultFake:    "fake",
		resultRefused: "refused",
	}
	for ti := metricA; ti <= metricOther; ti++ {
		for ri := resultReal; ri <= resultRefused; ri++ {
			val := m.counters[ti][ri].Load()
			fmt.Fprintf(w, "dns_queries_total{type=%q,result=%q} %d\n", typeNames[ti], resultNames[ri], val)
		}
	}
}

var queryMetrics metrics

var (
	secretKey []byte
	fakeTTL   uint32
	domains   []domainConfig
)

// domainConfig binds a zone this server is responsible for to the upstream
// server that holds its real records. Sorted most-specific-zone-first so
// overlapping entries (e.g. "example.com" and "internal.example.com") match
// the more specific one.
type domainConfig struct {
	zone     string
	upstream string
}

// domainFlag implements flag.Value so --domain can be repeated on the command
// line, once per zone this server should handle.
type domainFlag []domainConfig

func (d *domainFlag) String() string {
	parts := make([]string, len(*d))
	for i, entry := range *d {
		parts[i] = entry.zone + "=" + entry.upstream
	}
	return strings.Join(parts, ",")
}

func (d *domainFlag) Set(value string) error {
	zone, upstreamOverride, _ := strings.Cut(value, "=")
	if zone == "" {
		return fmt.Errorf("invalid --domain value %q: expected zone[=upstream_host:port]", value)
	}
	*d = append(*d, domainConfig{zone: dns.Fqdn(strings.ToLower(zone)), upstream: upstreamOverride})
	return nil
}

// upstreamFor returns the upstream server responsible for qname, and whether
// this server is configured to handle that zone at all.
func upstreamFor(qname string) (string, bool) {
	normalized := dns.Fqdn(strings.ToLower(qname))
	for _, d := range domains {
		if dns.IsSubDomain(d.zone, normalized) {
			return d.upstream, true
		}
	}
	return "", false
}

// zoneFor returns the matching configured zone for qname.
func zoneFor(qname string) string {
	normalized := dns.Fqdn(strings.ToLower(qname))
	for _, d := range domains {
		if dns.IsSubDomain(d.zone, normalized) {
			return d.zone
		}
	}
	return ""
}

var blockedIPv4FirstOctets = map[byte]bool{10: true, 127: true, 172: true, 192: true}

const ipv4FirstOctetFallback = 45

// fc00::/7 (unique local), fe80::/10 (link-local), ff00::/8 (multicast) and the
// reserved 0000::/8 block (covers ::, ::1) are approximated here by their leading
// byte only, same simple over-blocking approach as the IPv4 octet check above.
var blockedIPv6FirstBytes = map[byte]bool{0x00: true, 0xfc: true, 0xfd: true, 0xfe: true, 0xff: true}

const ipv6FirstByteFallback = 0x20 // keeps the address inside the 2000::/3 global unicast range

func toOctet(b byte) byte {
	return b%255 + 1
}

func hashFor(qname, qtype string) []byte {
	normalized := strings.ToLower(strings.TrimSuffix(qname, "."))
	mac := hmac.New(sha256.New, secretKey)
	mac.Write([]byte(normalized + "|" + qtype))
	return mac.Sum(nil)
}

// fakeIPv4For derives a deterministic "fake" IPv4 address from the queried name,
// so repeated queries for the same name resolve consistently while different
// names produce different addresses (defeats wildcard-equality checks).
func fakeIPv4For(qname string) net.IP {
	digest := hashFor(qname, "A")

	octets := [4]byte{}
	for i := 0; i < 4; i++ {
		octets[i] = toOctet(digest[i])
	}
	if blockedIPv4FirstOctets[octets[0]] {
		octets[0] = ipv4FirstOctetFallback
	}
	return net.IPv4(octets[0], octets[1], octets[2], octets[3])
}

// fakeIPv6For does the same for AAAA queries, using the raw hash bytes as the
// address body instead of clamping each byte like the IPv4 version.
func fakeIPv6For(qname string) net.IP {
	digest := hashFor(qname, "AAAA")

	addr := make(net.IP, 16)
	copy(addr, digest[:16])
	if blockedIPv6FirstBytes[addr[0]] {
		addr[0] = ipv6FirstByteFallback
	}
	return addr
}

// fakeTXTFor returns a SPF-like TXT record unique per qname.
func fakeTXTFor(qname, zone string) string {
	digest := hashFor(qname, "TXT")
	return fmt.Sprintf("v=spf1 redirect=_%s.%s", hex.EncodeToString(digest[:4]), strings.TrimSuffix(zone, "."))
}

// fakeMXPrefFor returns a deterministic MX preference (1-50) for qname.
func fakeMXPrefFor(qname string) uint16 {
	digest := hashFor(qname, "MX")
	return uint16(digest[0])%50 + 1
}

// fakeMXTargetFor returns a deterministic MX target for qname.
func fakeMXTargetFor(qname, zone string) string {
	digest := hashFor(qname, "MX")
	return fmt.Sprintf("mail-%s.%s.", hex.EncodeToString(digest[:4]), strings.TrimSuffix(zone, "."))
}

func qtypeToMetric(qtype uint16) metricType {
	switch qtype {
	case dns.TypeA:
		return metricA
	case dns.TypeAAAA:
		return metricAAAA
	case dns.TypeTXT:
		return metricTXT
	case dns.TypeMX:
		return metricMX
	default:
		return metricOther
	}
}

func handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) == 0 {
		dns.HandleFailed(w, r)
		return
	}
	q := r.Question[0]
	t := qtypeToMetric(q.Qtype)

	m := new(dns.Msg)
	m.SetReply(r)
	if opt := r.IsEdns0(); opt != nil {
		m.SetEdns0(opt.UDPSize(), opt.Do())
	}

	up, ok := upstreamFor(q.Name)
	if !ok {
		m.Rcode = dns.RcodeRefused
		queryMetrics.inc(t, resultRefused)
		_ = w.WriteMsg(m)
		return
	}

	c := &dns.Client{Timeout: 2 * time.Second}
	upstreamMsg := new(dns.Msg)
	upstreamMsg.SetQuestion(q.Name, q.Qtype)
	upstreamMsg.RecursionDesired = true

	resp, _, err := c.Exchange(upstreamMsg, up)

	switch {
	case err == nil && resp != nil && resp.Rcode == dns.RcodeSuccess && len(resp.Answer) > 0:
		m.Answer = resp.Answer
		m.Rcode = dns.RcodeSuccess
		queryMetrics.inc(t, resultReal)

	case q.Qtype == dns.TypeA:
		rr := &dns.A{
			Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: fakeTTL},
			A:   fakeIPv4For(q.Name),
		}
		m.Answer = append(m.Answer, rr)
		m.Rcode = dns.RcodeSuccess
		queryMetrics.inc(t, resultFake)

	case q.Qtype == dns.TypeAAAA:
		rr := &dns.AAAA{
			Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: fakeTTL},
			AAAA: fakeIPv6For(q.Name),
		}
		m.Answer = append(m.Answer, rr)
		m.Rcode = dns.RcodeSuccess
		queryMetrics.inc(t, resultFake)

	case q.Qtype == dns.TypeTXT:
		zone := zoneFor(q.Name)
		rr := &dns.TXT{
			Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: fakeTTL},
			Txt: []string{fakeTXTFor(q.Name, zone)},
		}
		m.Answer = append(m.Answer, rr)
		m.Rcode = dns.RcodeSuccess
		queryMetrics.inc(t, resultFake)

	case q.Qtype == dns.TypeMX:
		zone := zoneFor(q.Name)
		rr := &dns.MX{
			Hdr:        dns.RR_Header{Name: q.Name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: fakeTTL},
			Preference: fakeMXPrefFor(q.Name),
			Mx:         fakeMXTargetFor(q.Name, zone),
		}
		m.Answer = append(m.Answer, rr)
		m.Rcode = dns.RcodeSuccess
		queryMetrics.inc(t, resultFake)

	default:
		if resp != nil {
			m.Rcode = resp.Rcode
		} else {
			m.Rcode = dns.RcodeServerFailure
		}
		queryMetrics.inc(t, resultReal)
	}

	if err := w.WriteMsg(m); err != nil {
		log.Printf("Error writing response: %v", err)
	}
}

const secretKeyEnvVar = "DECEPTION_SECRET_KEY"

func loadSecretKey(flagValue string) ([]byte, error) {
	if hexKey := os.Getenv(secretKeyEnvVar); hexKey != "" {
		return hex.DecodeString(hexKey)
	}
	if flagValue != "" {
		log.Printf("warning: reading the secret key from --key is insecure (visible in `ps` and shell history); prefer the %s environment variable", secretKeyEnvVar)
		return hex.DecodeString(flagValue)
	}
	return nil, fmt.Errorf("secret key required: set %s (hex-encoded, e.g. via `openssl rand -hex 32`) or pass --key", secretKeyEnvVar)
}

func envOrDefault(key, defaultVal string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return defaultVal
}

func uintEnvOrDefault(key string, defaultVal uint) uint {
	if v, ok := os.LookupEnv(key); ok {
		if parsed, err := strconv.ParseUint(v, 10, 32); err == nil {
			return uint(parsed)
		}
	}
	return defaultVal
}

func parseDomainEnv(val string) []domainConfig {
	if val == "" {
		return nil
	}
	var domains []domainConfig
	for _, part := range strings.Split(val, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		zone, upstream, _ := strings.Cut(part, "=")
		if zone == "" {
			log.Fatalf("invalid domain %q in DECEPTION_DOMAINS", part)
		}
		domains = append(domains, domainConfig{
			zone:     dns.Fqdn(strings.ToLower(zone)),
			upstream: upstream,
		})
	}
	return domains
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

func readyHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

func metricsHandler(w http.ResponseWriter, r *http.Request) {
	queryMetrics.write(w)
}

func main() {
	listenAddr := flag.String("listen", envOrDefault("DECEPTION_LISTEN", ":5353"), "address to listen on (env: DECEPTION_LISTEN)")
	httpAddr := flag.String("http", envOrDefault("DECEPTION_HTTP", ":8080"), "HTTP listen address for /healthz and /readyz (env: DECEPTION_HTTP)")
	defaultUpstream := flag.String("upstream", envOrDefault("DECEPTION_UPSTREAM", "1.1.1.1:53"), "default upstream resolver/authoritative server, used for --domain entries without their own upstream (env: DECEPTION_UPSTREAM)")
	keyHex := flag.String("key", "", "hex-encoded secret key (insecure fallback, prefer the "+secretKeyEnvVar+" env var)")
	ttl := flag.Uint("ttl", uintEnvOrDefault("DECEPTION_TTL", 60), "TTL for synthesized records (env: DECEPTION_TTL)")
	var domainList domainFlag
	domainList = parseDomainEnv(os.Getenv("DECEPTION_DOMAINS"))
	flag.Var(&domainList, "domain", "zone this server handles, optionally with its own upstream: zone[=upstream_host:port] (repeatable, at least one required; env: DECEPTION_DOMAINS comma-separated)")
	flag.Parse()

	if len(domainList) == 0 {
		log.Fatal("at least one --domain is required, e.g. --domain example.com=127.0.0.1:5301")
	}
	for i := range domainList {
		if domainList[i].upstream == "" {
			domainList[i].upstream = *defaultUpstream
		}
	}
	// Most specific zone (most labels) first, so a query matches its
	// narrowest configured zone rather than a broader parent one.
	sort.Slice(domainList, func(i, j int) bool {
		return len(dns.SplitDomainName(domainList[i].zone)) > len(dns.SplitDomainName(domainList[j].zone))
	})
	domains = domainList

	key, err := loadSecretKey(*keyHex)
	if err != nil {
		log.Fatal(err)
	}
	secretKey = key
	fakeTTL = uint32(*ttl)

	dns.HandleFunc(".", handleRequest)

	for _, d := range domains {
		log.Printf("handling zone %s (upstream=%s)", d.zone, d.upstream)
	}

	var wg sync.WaitGroup

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", healthHandler)
	mux.HandleFunc("/readyz", readyHandler)
	mux.HandleFunc("/metrics", metricsHandler)
	httpSrv := &http.Server{Addr: *httpAddr, Handler: mux}

	var dnsSrvs []*dns.Server
	for _, network := range []string{"udp", "tcp"} {
		srv := &dns.Server{Addr: *listenAddr, Net: network}
		dnsSrvs = append(dnsSrvs, srv)
		wg.Add(1)
		go func(s *dns.Server, net string) {
			defer wg.Done()
			log.Printf("deception server listening on %s/%s", s.Addr, net)
			if err := s.ListenAndServe(); err != nil {
				log.Printf("%s server error: %v", net, err)
			}
		}(srv, network)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Printf("HTTP server listening on %s", httpSrv.Addr)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("HTTP server error: %v", err)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	<-sig
	log.Print("shutting down...")

	for _, s := range dnsSrvs {
		s.Shutdown()
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	httpSrv.Shutdown(shutdownCtx)

	wg.Wait()
}
