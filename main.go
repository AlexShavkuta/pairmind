// pairmind spike (milestone 1)
//
// Two peers that share a secret find each other on the public IPFS DHT,
// punch through NAT (relay-assisted if needed), prove they both hold the
// secret, then chat over stdin/stdout.
//
// Usage:
//
//	pairmind keygen                       # make a strong shared secret
//	pairmind -secret <secret> -name alex  # run on both machines
//	pairmind -secret <s> -dial <multiaddr> # skip the DHT (local testing)
package main

import (
	"bufio"
	"context"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/event"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/routing"
	drouting "github.com/libp2p/go-libp2p/p2p/discovery/routing"
	dutil "github.com/libp2p/go-libp2p/p2p/discovery/util"
	ma "github.com/multiformats/go-multiaddr"
)

const protoID = "/pairmind/session/0.1.0"

// Set at release time by GoReleaser: -ldflags "-X main.version=1.2.3".
var version = "dev"

// ---------- key derivation ----------

type keys struct {
	rendezvous string // public: what we advertise on the DHT
	psk        []byte // private: used only for the HMAC handshake
}

func deriveKeys(secret string) (keys, error) {
	topic, err := hkdf.Key(sha256.New, []byte(secret), nil, "pairmind/topic/v1", 32)
	if err != nil {
		return keys{}, err
	}
	psk, err := hkdf.Key(sha256.New, []byte(secret), nil, "pairmind/psk/v1", 32)
	if err != nil {
		return keys{}, err
	}
	return keys{rendezvous: "pairmind/" + hex.EncodeToString(topic), psk: psk}, nil
}

func keygen() string {
	b := make([]byte, 20) // 160 bits
	if _, err := rand.Read(b); err != nil {
		log.Fatal(err)
	}
	s := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b))
	var parts []string
	for i := 0; i < len(s); i += 4 {
		parts = append(parts, s[i:min(i+4, len(s))])
	}
	return strings.Join(parts, "-")
}

// ---------- wire format ----------

type Envelope struct {
	V     int    `json:"v"`
	Type  string `json:"type"` // auth1 | auth2 | auth3 | ok | msg | end
	From  string `json:"from,omitempty"`
	Seq   int    `json:"seq,omitempty"`
	Body  string `json:"body,omitempty"`
	Nonce string `json:"nonce,omitempty"`
	MAC   string `json:"mac,omitempty"`
	TS    int64  `json:"ts,omitempty"`
}

type conn struct {
	s   network.Stream
	enc *json.Encoder
	dec *json.Decoder
	mu  sync.Mutex
}

func newConn(s network.Stream) *conn {
	return &conn{s: s, enc: json.NewEncoder(s), dec: json.NewDecoder(bufio.NewReader(s))}
}

func (c *conn) send(e Envelope) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	e.V = 1
	return c.enc.Encode(e)
}

func (c *conn) recv(timeout time.Duration) (Envelope, error) {
	var e Envelope
	if timeout > 0 {
		_ = c.s.SetReadDeadline(time.Now().Add(timeout))
		defer c.s.SetReadDeadline(time.Time{})
	}
	err := c.dec.Decode(&e)
	return e, err
}

// ---------- mutual HMAC handshake ----------
// The MAC binds role + the other side's nonce + both peer IDs, so a relay
// or eavesdropper can't replay it against a different peer.

func mac(psk []byte, role string, nonce []byte, self, other peer.ID) string {
	m := hmac.New(sha256.New, psk)
	m.Write([]byte(role))
	m.Write(nonce)
	m.Write([]byte(self))
	m.Write([]byte(other))
	return hex.EncodeToString(m.Sum(nil))
}

func nonce() []byte {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return b
}

var errAuth = errors.New("peer failed secret check")

func authInitiator(c *conn, psk []byte, self, other peer.ID) error {
	nA := nonce()
	if err := c.send(Envelope{Type: "auth1", Nonce: hex.EncodeToString(nA)}); err != nil {
		return err
	}
	r, err := c.recv(20 * time.Second)
	if err != nil {
		return err
	}
	if r.Type != "auth2" || !hmac.Equal([]byte(r.MAC), []byte(mac(psk, "R", nA, other, self))) {
		return errAuth
	}
	nB, err := hex.DecodeString(r.Nonce)
	if err != nil {
		return errAuth
	}
	if err := c.send(Envelope{Type: "auth3", MAC: mac(psk, "I", nB, self, other)}); err != nil {
		return err
	}
	ok, err := c.recv(20 * time.Second)
	if err != nil || ok.Type != "ok" {
		return errAuth
	}
	return nil
}

func authResponder(c *conn, psk []byte, self, other peer.ID) error {
	r, err := c.recv(20 * time.Second)
	if err != nil {
		return err
	}
	nA, err := hex.DecodeString(r.Nonce)
	if r.Type != "auth1" || err != nil {
		return errAuth
	}
	nB := nonce()
	if err := c.send(Envelope{Type: "auth2", Nonce: hex.EncodeToString(nB), MAC: mac(psk, "R", nA, self, other)}); err != nil {
		return err
	}
	r, err = c.recv(20 * time.Second)
	if err != nil {
		return err
	}
	if r.Type != "auth3" || !hmac.Equal([]byte(r.MAC), []byte(mac(psk, "I", nB, other, self))) {
		return errAuth
	}
	return c.send(Envelope{Type: "ok"})
}

// ---------- session (one peer at a time) ----------

type app struct {
	h    host.Host
	k    keys
	name string

	mu     sync.Mutex
	active *conn
	peer   peer.ID
	outbox chan string
}

func (a *app) claim(p peer.ID) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.active != nil || p == "" {
		return false
	}
	a.peer = p
	a.active = &conn{} // placeholder while handshaking
	return true
}

func (a *app) release() {
	a.mu.Lock()
	a.active, a.peer = nil, ""
	a.mu.Unlock()
}

func (a *app) run(c *conn, p peer.ID) {
	a.mu.Lock()
	a.active = c
	a.mu.Unlock()
	defer func() {
		c.s.Close()
		a.release()
		log.Printf("session with %s closed; looking for peer again", short(p))
	}()

	log.Printf("✅ authenticated %s via %s", short(p), connKind(a.h, p))
	fmt.Println("--- type a message and press enter (/quit to end) ---")
	go a.watchConn(p, c)

	errc := make(chan error, 1)
	go func() {
		for {
			e, err := c.recv(0)
			if err != nil {
				errc <- err
				return
			}
			switch e.Type {
			case "msg":
				fmt.Printf("[%s #%d] %s\n", e.From, e.Seq, e.Body)
			case "end":
				errc <- errors.New("peer ended session")
				return
			}
		}
	}()

	seq := 0
	for {
		select {
		case line := <-a.outbox:
			if line == "/quit" {
				_ = c.send(Envelope{Type: "end", From: a.name})
				return
			}
			seq++
			if err := c.send(Envelope{Type: "msg", From: a.name, Seq: seq, Body: line, TS: time.Now().Unix()}); err != nil {
				log.Printf("send failed: %v", err)
				return
			}
		case err := <-errc:
			log.Printf("stream ended: %v", err)
			return
		}
	}
}

// Report when a relayed connection upgrades to direct (hole punch worked)
// or stays relayed (relay v2 limits will cut it after ~2 min / 128 KiB).
func (a *app) watchConn(p peer.ID, c *conn) {
	last := ""
	start := time.Now()
	for {
		a.mu.Lock()
		still := a.active == c
		a.mu.Unlock()
		if !still {
			return
		}
		k := connKind(a.h, p)
		if k != last {
			log.Printf("connection to %s is now: %s (t+%s)", short(p), k, time.Since(start).Round(time.Second))
			last = k
		}
		time.Sleep(3 * time.Second)
	}
}

func connKind(h host.Host, p peer.ID) string {
	direct, relayed := 0, 0
	for _, c := range h.Network().ConnsToPeer(p) {
		if strings.Contains(c.RemoteMultiaddr().String(), "p2p-circuit") {
			relayed++
		} else {
			direct++
		}
	}
	switch {
	case direct > 0:
		return "DIRECT"
	case relayed > 0:
		return "RELAYED (hole punch not done yet)"
	default:
		return "none"
	}
}

func (a *app) handleStream(s network.Stream) {
	p := s.Conn().RemotePeer()
	if !a.claim(p) {
		s.Reset()
		return
	}
	c := newConn(s)
	if err := authResponder(c, a.k.psk, a.h.ID(), p); err != nil {
		log.Printf("rejected %s: %v", short(p), err)
		s.Reset()
		a.release()
		return
	}
	a.run(c, p)
}

func (a *app) dialAndAuth(ctx context.Context, p peer.ID) {
	if !a.claim(p) {
		return
	}
	// Allow opening the stream over a relayed (limited) connection; the
	// hole-punch upgrade happens in the background.
	sctx, cancel := context.WithTimeout(network.WithAllowLimitedConn(ctx, "pairmind"), 30*time.Second)
	defer cancel()
	s, err := a.h.NewStream(sctx, p, protoID)
	if err != nil {
		log.Printf("open stream to %s failed: %v", short(p), err)
		a.release()
		return
	}
	c := newConn(s)
	if err := authInitiator(c, a.k.psk, a.h.ID(), p); err != nil {
		log.Printf("auth with %s failed: %v", short(p), err)
		s.Reset()
		a.release()
		return
	}
	a.run(c, p)
}

// Lower peer ID initiates, so the two sides don't open duplicate sessions.
func (a *app) onFound(ctx context.Context, pi peer.AddrInfo) {
	if pi.ID == a.h.ID() || len(pi.Addrs) == 0 {
		return
	}
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	err := a.h.Connect(cctx, pi)
	cancel()
	if err != nil {
		log.Printf("found %s but connect failed: %v", short(pi.ID), err)
		return
	}
	if a.h.ID() < pi.ID {
		go a.dialAndAuth(ctx, pi.ID)
	}
}

// ---------- main ----------

func main() {
	log.SetFlags(log.Ltime)
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "keygen":
			fmt.Println(keygen())
			return
		case "version", "--version", "-version":
			fmt.Println("pairmind", version)
			return
		}
	}
	secret := flag.String("secret", "", "shared secret (use `pairmind keygen`)")
	name := flag.String("name", "", "display name")
	dial := flag.String("dial", "", "peer multiaddr to dial directly (skips DHT, for local tests)")
	flag.Parse()
	if *secret == "" {
		log.Fatal("missing -secret (generate one with: pairmind keygen)")
	}
	if len(*secret) < 20 {
		log.Println("⚠️  short secret: anyone who guesses it can talk to your agent. Use `pairmind keygen`.")
	}
	k, err := deriveKeys(*secret)
	if err != nil {
		log.Fatal(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	var idht *dht.IpfsDHT
	var h host.Host

	// AutoRelay needs candidate relays; pull them from the DHT routing table.
	peerSource := func(ctx context.Context, num int) <-chan peer.AddrInfo {
		ch := make(chan peer.AddrInfo)
		go func() {
			defer close(ch)
			if idht == nil || h == nil {
				return
			}
			for _, p := range idht.RoutingTable().ListPeers() {
				if num <= 0 {
					return
				}
				select {
				case ch <- peer.AddrInfo{ID: p, Addrs: h.Peerstore().Addrs(p)}:
					num--
				case <-ctx.Done():
					return
				}
			}
		}()
		return ch
	}

	h, err = libp2p.New(
		libp2p.ListenAddrStrings(
			"/ip4/0.0.0.0/tcp/0", "/ip4/0.0.0.0/udp/0/quic-v1",
			"/ip6/::/tcp/0", "/ip6/::/udp/0/quic-v1",
		),
		libp2p.NATPortMap(),
		libp2p.EnableHolePunching(),
		libp2p.EnableNATService(),
		libp2p.EnableAutoRelayWithPeerSource(peerSource),
		libp2p.Routing(func(hh host.Host) (routing.PeerRouting, error) {
			var err error
			// v0.43+: no ctx; the DHT lives until idht.Close().
			idht, err = dht.New(hh,
				dht.Mode(dht.ModeAuto),
				dht.BootstrapPeers(dht.GetDefaultBootstrapPeerAddrInfos()...))
			return idht, err
		}),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer h.Close()
	defer idht.Close() // runs before h.Close (defers are LIFO)

	if *name == "" {
		*name = short(h.ID())
	}
	a := &app{h: h, k: k, name: *name, outbox: make(chan string)}
	h.SetStreamHandler(protoID, a.handleStream)

	log.Printf("peer id: %s", h.ID())
	for _, addr := range h.Addrs() {
		log.Printf("listening: %s/p2p/%s", addr, h.ID())
	}

	if sub, err := h.EventBus().Subscribe(new(event.EvtLocalReachabilityChanged)); err == nil {
		go func() {
			for ev := range sub.Out() {
				log.Printf("NAT reachability: %s", ev.(event.EvtLocalReachabilityChanged).Reachability)
			}
		}()
	}

	// stdin -> outbox (only delivered when a session is active)
	go func() {
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			a.mu.Lock()
			live := a.active != nil && a.active.s != nil
			a.mu.Unlock()
			if !live {
				log.Println("(no peer yet, message dropped)")
				continue
			}
			a.outbox <- line
		}
	}()

	if *dial != "" {
		maddr, err := ma.NewMultiaddr(*dial)
		if err != nil {
			log.Fatal(err)
		}
		pi, err := peer.AddrInfoFromP2pAddr(maddr)
		if err != nil {
			log.Fatal(err)
		}
		if err := h.Connect(ctx, *pi); err != nil {
			log.Fatal(err)
		}
		go a.dialAndAuth(ctx, pi.ID) // explicit dial: we initiate regardless of ID order
		<-ctx.Done()
		return
	}

	log.Println("bootstrapping DHT…")
	if err := idht.Bootstrap(ctx); err != nil {
		log.Fatal(err)
	}
	for i := 0; i < 30 && idht.RoutingTable().Size() == 0; i++ {
		time.Sleep(time.Second)
	}
	log.Printf("DHT routing table: %d peers", idht.RoutingTable().Size())

	rd := drouting.NewRoutingDiscovery(idht)
	dutil.Advertise(ctx, rd, k.rendezvous)
	log.Println("advertising on rendezvous; searching for peer…")

	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()
	for {
		a.mu.Lock()
		busy := a.active != nil
		a.mu.Unlock()
		if !busy {
			peers, err := rd.FindPeers(ctx, k.rendezvous)
			if err != nil {
				log.Printf("find peers: %v", err)
			} else {
				for pi := range peers {
					a.onFound(ctx, pi)
				}
			}
		}
		select {
		case <-ctx.Done():
			log.Println("bye")
			return
		case <-tick.C:
		}
	}
}

func short(p peer.ID) string {
	s := p.String()
	if len(s) > 8 {
		return s[len(s)-8:]
	}
	return s
}
