package main

/*
#include <stdlib.h>
#include <stdint.h>
*/
import "C"

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	golog "github.com/gologme/log"
	"github.com/yggdrasil-network/yggdrasil-go/src/core"
	"github.com/yggdrasil-network/yggdrasil-go/src/ipv6rwc"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// ── Global registries ────────────────────────────────────────────────

var (
	nodeCounter     atomic.Uintptr
	listenerCounter atomic.Uintptr
	nodes           sync.Map // uintptr → *nodeEntry
	listeners       sync.Map // uintptr → *listenerEntry
)

type nodeEntry struct {
	core   *core.Core
	stack  *stack.Stack
	nic    *yggNIC
	cancel context.CancelFunc
}

type listenerEntry struct {
	listener net.Listener
}

// ── Yggdrasil → gVisor NIC adapter ──────────────────────────────────

type yggNIC struct {
	rwc        *ipv6rwc.ReadWriteCloser
	dispatcher stack.NetworkDispatcher
	readBuf    []byte
	writeBuf   []byte
	rstPackets chan *stack.PacketBuffer
}

func (e *yggNIC) Attach(dispatcher stack.NetworkDispatcher) { e.dispatcher = dispatcher }
func (e *yggNIC) IsAttached() bool                          { return e.dispatcher != nil }
func (e *yggNIC) MTU() uint32                               { return uint32(e.rwc.MTU()) }
func (e *yggNIC) SetMTU(uint32)                             {}
func (*yggNIC) Capabilities() stack.LinkEndpointCapabilities { return stack.CapabilityNone }
func (*yggNIC) MaxHeaderLength() uint16                     { return 40 }
func (*yggNIC) LinkAddress() tcpip.LinkAddress               { return "" }
func (*yggNIC) SetLinkAddress(tcpip.LinkAddress)             {}
func (*yggNIC) Wait()                                        {}
func (*yggNIC) ARPHardwareType() header.ARPHardwareType      { return header.ARPHardwareNone }
func (e *yggNIC) AddHeader(*stack.PacketBuffer)              {}
func (e *yggNIC) ParseHeader(*stack.PacketBuffer) bool       { return true }
func (e *yggNIC) SetOnCloseAction(func())                    {}

func (e *yggNIC) WriteRawPacket(*stack.PacketBuffer) tcpip.Error {
	panic("not implemented")
}

func (e *yggNIC) writePacket(pkt *stack.PacketBuffer) tcpip.Error {
	defer func() { recover() }() // ToView() can panic on empty payloads
	vv := pkt.ToView()
	n, err := vv.Read(e.writeBuf)
	if err != nil {
		return &tcpip.ErrAborted{}
	}
	_, err = e.rwc.Write(e.writeBuf[:n])
	if err != nil {
		return &tcpip.ErrAborted{}
	}
	return nil
}

func (e *yggNIC) WritePackets(list stack.PacketBufferList) (int, tcpip.Error) {
	var count int
	for _, pkt := range list.AsSlice() {
		// TCP RSTs without payload go through async channel to avoid deadlocks.
		if pkt.Data().Size() == 0 {
			if pkt.Network().TransportProtocol() == tcp.ProtocolNumber {
				tcpHdr := header.TCP(pkt.TransportHeader().Slice())
				if (tcpHdr.Flags() & header.TCPFlagRst) == header.TCPFlagRst {
					e.rstPackets <- pkt
					count++
					continue
				}
			}
		}
		if err := e.writePacket(pkt); err != nil {
			return count, err
		}
		count++
	}
	return count, nil
}

func (e *yggNIC) Close() {
	e.dispatcher = nil
}

// createNetstack builds a gVisor TCP/IP stack wired to the Yggdrasil
// core's packet layer via ipv6rwc. Returns the stack and NIC.
func createNetstack(yggCore *core.Core) (*stack.Stack, *yggNIC, error) {
	rwc := ipv6rwc.NewReadWriteCloser(yggCore)
	mtu := rwc.MTU()

	nic := &yggNIC{
		rwc:        rwc,
		readBuf:    make([]byte, mtu),
		writeBuf:   make([]byte, mtu),
		rstPackets: make(chan *stack.PacketBuffer, 100),
	}

	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol6},
		HandleLocal:        true,
	})
	if s.HandleLocal() {
		s.AllowICMPMessage()
	}

	if err := s.CreateNIC(1, nic); err != nil {
		return nil, nil, fmt.Errorf("CreateNIC: %s", err)
	}

	// Inbound: Yggdrasil packets → gVisor dispatcher
	go func() {
		for {
			rx, err := nic.rwc.Read(nic.readBuf)
			if err != nil {
				break
			}
			pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(nic.readBuf[:rx]),
			})
			nic.dispatcher.DeliverNetworkPacket(ipv6.ProtocolNumber, pkb)
		}
	}()

	// Async RST writer
	go func() {
		for pkt := range nic.rstPackets {
			if pkt != nil {
				nic.writePacket(pkt)
			}
		}
	}()

	// Route the Yggdrasil address space (0200::/7) through our NIC.
	_, snet, err := net.ParseCIDR("0200::/7")
	if err != nil {
		return nil, nil, fmt.Errorf("ParseCIDR: %w", err)
	}
	subnet, terr := tcpip.NewSubnet(
		tcpip.AddrFromSlice(snet.IP.To16()),
		tcpip.MaskFrom(string(snet.Mask)),
	)
	if terr != nil {
		return nil, nil, fmt.Errorf("NewSubnet: %s", terr)
	}
	s.AddRoute(tcpip.Route{
		Destination: subnet,
		NIC:         1,
	})

	// Assign our Yggdrasil address to the NIC.
	ip := yggCore.Address()
	if perr := s.AddProtocolAddress(
		1,
		tcpip.ProtocolAddress{
			Protocol:          ipv6.ProtocolNumber,
			AddressWithPrefix: tcpip.AddrFromSlice(ip.To16()).WithPrefix(),
		},
		stack.AddressProperties{},
	); perr != nil {
		return nil, nil, fmt.Errorf("AddProtocolAddress: %s", perr)
	}

	return s, nic, nil
}

// ── Helpers ──────────────────────────────────────────────────────────

// bridgeConn creates a Unix socketpair, spawns goroutines to pump data
// between a net.Conn and one end, and returns the other end's raw FD
// for Rust to use.
func bridgeConn(conn net.Conn) (int, error) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		conn.Close()
		return -1, fmt.Errorf("socketpair: %w", err)
	}

	goFile := os.NewFile(uintptr(fds[0]), "ygg-go")
	goConn, err := net.FileConn(goFile)
	goFile.Close()
	if err != nil {
		conn.Close()
		syscall.Close(fds[1])
		return -1, fmt.Errorf("FileConn: %w", err)
	}

	go func() {
		io.Copy(conn, goConn)
		conn.Close()
		goConn.Close()
	}()
	go func() {
		io.Copy(goConn, conn)
		conn.Close()
		goConn.Close()
	}()

	return fds[1], nil
}

func writeOutBuf(out *C.char, outLen C.int, msg string) {
	if out == nil || outLen <= 0 {
		return
	}
	buf := unsafe.Slice((*byte)(unsafe.Pointer(out)), int(outLen))
	n := copy(buf, msg)
	if n < int(outLen) {
		buf[n] = 0
	} else {
		buf[int(outLen)-1] = 0
	}
}

func makeTLSCert(privKey ed25519.PrivateKey) (*tls.Certificate, error) {
	pubKey := privKey.Public().(ed25519.PublicKey)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "yggdrasil"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour * 24 * 365 * 10),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pubKey, privKey)
	if err != nil {
		return nil, fmt.Errorf("x509.CreateCertificate: %w", err)
	}
	return &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  privKey,
	}, nil
}

// ── Exported FFI functions ───────────────────────────────────────────

//export ygg_init
func ygg_init(privateKeyHex *C.char, peersJSON *C.char, listenJSON *C.char) C.uintptr_t {
	keyHex := C.GoString(privateKeyHex)
	keyBytes, err := hex.DecodeString(keyHex)
	if err != nil || len(keyBytes) != ed25519.PrivateKeySize {
		fmt.Fprintf(os.Stderr, "[yggbridge] invalid private key: len=%d err=%v\n", len(keyBytes), err)
		return 0
	}
	privKey := ed25519.PrivateKey(keyBytes)

	cert, err := makeTLSCert(privKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[yggbridge] TLS cert generation failed: %v\n", err)
		return 0
	}

	var peers []string
	if peersJSON != nil {
		json.Unmarshal([]byte(C.GoString(peersJSON)), &peers)
	}
	var listenAddrs []string
	if listenJSON != nil {
		json.Unmarshal([]byte(C.GoString(listenJSON)), &listenAddrs)
	}

	var opts []core.SetupOption
	for _, peer := range peers {
		opts = append(opts, core.Peer{URI: peer})
	}
	for _, addr := range listenAddrs {
		opts = append(opts, core.ListenAddress(addr))
	}

	logger := golog.New(os.Stderr, "[yggdrasil] ", golog.Flags())
	logger.EnableLevel("info")
	logger.EnableLevel("warn")
	logger.EnableLevel("error")

	_, cancel := context.WithCancel(context.Background())

	yggCore, err := core.New(cert, logger, opts...)
	if err != nil {
		cancel()
		fmt.Fprintf(os.Stderr, "[yggbridge] core.New failed: %v\n", err)
		return 0
	}

	s, nic, err := createNetstack(yggCore)
	if err != nil {
		yggCore.Stop()
		cancel()
		fmt.Fprintf(os.Stderr, "[yggbridge] netstack failed: %v\n", err)
		return 0
	}

	handle := nodeCounter.Add(1)
	nodes.Store(handle, &nodeEntry{
		core:   yggCore,
		stack:  s,
		nic:    nic,
		cancel: cancel,
	})

	addr := yggCore.Address()
	fmt.Fprintf(os.Stderr, "[yggbridge] node started: handle=%d address=%s\n", handle, addr.String())

	return C.uintptr_t(handle)
}

//export ygg_address
func ygg_address(handle C.uintptr_t) *C.char {
	v, ok := nodes.Load(uintptr(handle))
	if !ok {
		return nil
	}
	entry := v.(*nodeEntry)
	addr := entry.core.Address()
	return C.CString(addr.String())
}

//export ygg_public_key
func ygg_public_key(handle C.uintptr_t) *C.char {
	v, ok := nodes.Load(uintptr(handle))
	if !ok {
		return nil
	}
	entry := v.(*nodeEntry)
	pubKey := entry.core.PublicKey()
	return C.CString(hex.EncodeToString(pubKey))
}

//export ygg_dial
func ygg_dial(handle C.uintptr_t, addr *C.char, port C.int, errOut *C.char, errOutLen C.int) C.int {
	v, ok := nodes.Load(uintptr(handle))
	if !ok {
		writeOutBuf(errOut, errOutLen, "invalid node handle")
		return -1
	}
	entry := v.(*nodeEntry)

	target := fmt.Sprintf("[%s]:%d", C.GoString(addr), int(port))
	conn, err := entry.dialTCP(target)
	if err != nil {
		writeOutBuf(errOut, errOutLen, fmt.Sprintf("dial %s: %v", target, err))
		return -1
	}

	fd, err := bridgeConn(conn)
	if err != nil {
		writeOutBuf(errOut, errOutLen, fmt.Sprintf("bridge: %v", err))
		return -1
	}

	return C.int(fd)
}

func (e *nodeEntry) dialTCP(address string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("SplitHostPort: %w", err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP: %s", host)
	}
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	fa, pn, err := convertToFullAddr(ip, port)
	if err != nil {
		return nil, err
	}
	return gonet.DialContextTCP(context.Background(), e.stack, fa, pn)
}

func convertToFullAddr(ip net.IP, port int) (tcpip.FullAddress, tcpip.NetworkProtocolNumber, error) {
	ip16 := ip.To16()
	if ip16 == nil {
		return tcpip.FullAddress{}, 0, fmt.Errorf("not an IPv6 address")
	}
	return tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFromSlice(ip16),
		Port: uint16(port),
	}, ipv6.ProtocolNumber, nil
}

//export ygg_listen
func ygg_listen(handle C.uintptr_t, port C.int) C.uintptr_t {
	v, ok := nodes.Load(uintptr(handle))
	if !ok {
		return 0
	}
	entry := v.(*nodeEntry)

	ip := entry.core.Address()
	fa, pn, err := convertToFullAddr(ip, int(port))
	if err != nil {
		fmt.Fprintf(os.Stderr, "[yggbridge] listen addr error: %v\n", err)
		return 0
	}

	listener, terr := gonet.ListenTCP(entry.stack, fa, pn)
	if terr != nil {
		fmt.Fprintf(os.Stderr, "[yggbridge] listen on port %d failed: %v\n", int(port), terr)
		return 0
	}

	lHandle := listenerCounter.Add(1)
	listeners.Store(lHandle, &listenerEntry{listener: listener})

	fmt.Fprintf(os.Stderr, "[yggbridge] listening on Ygg port %d (handle=%d)\n", int(port), lHandle)
	return C.uintptr_t(lHandle)
}

//export ygg_accept
func ygg_accept(listenerHandle C.uintptr_t, remoteOut *C.char, remoteOutLen C.int) C.int {
	v, ok := listeners.Load(uintptr(listenerHandle))
	if !ok {
		return -1
	}
	entry := v.(*listenerEntry)

	conn, err := entry.listener.Accept()
	if err != nil {
		return -1
	}

	if remoteOut != nil && remoteOutLen > 0 {
		remoteAddr := conn.RemoteAddr().String()
		if host, _, splitErr := net.SplitHostPort(remoteAddr); splitErr == nil {
			remoteAddr = host
		}
		writeOutBuf(remoteOut, remoteOutLen, remoteAddr)
	}

	fd, err := bridgeConn(conn)
	if err != nil {
		return -1
	}

	return C.int(fd)
}

//export ygg_peers_json
func ygg_peers_json(handle C.uintptr_t) *C.char {
	v, ok := nodes.Load(uintptr(handle))
	if !ok {
		return C.CString("[]")
	}
	entry := v.(*nodeEntry)

	peers := entry.core.GetPeers()

	type peerInfo struct {
		URI       string  `json:"uri"`
		Key       string  `json:"key"`
		Up        bool    `json:"up"`
		Inbound   bool    `json:"inbound"`
		TXBytes   uint64  `json:"tx_bytes"`
		RXBytes   uint64  `json:"rx_bytes"`
		Latency   float64 `json:"latency_ms"`
		Uptime    float64 `json:"uptime"`
		Priority  uint8   `json:"priority"`
	}

	var result []peerInfo
	for _, p := range peers {
		result = append(result, peerInfo{
			URI:      p.URI,
			Key:      hex.EncodeToString(p.Key),
			Up:       p.Up,
			Inbound:  p.Inbound,
			TXBytes:  p.TXBytes,
			RXBytes:  p.RXBytes,
			Latency:  float64(p.Latency) / float64(time.Millisecond),
			Uptime:   p.Uptime.Seconds(),
			Priority: p.Priority,
		})
	}

	data, _ := json.Marshal(result)
	return C.CString(string(data))
}

//export ygg_add_peer
func ygg_add_peer(handle C.uintptr_t, uri *C.char) C.int {
	v, ok := nodes.Load(uintptr(handle))
	if !ok {
		return -1
	}
	entry := v.(*nodeEntry)

	peerURI := C.GoString(uri)
	if err := entry.core.AddPeer(parseURI(peerURI), ""); err != nil {
		fmt.Fprintf(os.Stderr, "[yggbridge] add_peer %s failed: %v\n", peerURI, err)
		return -1
	}
	return 0
}

//export ygg_remove_peer
func ygg_remove_peer(handle C.uintptr_t, uri *C.char) C.int {
	v, ok := nodes.Load(uintptr(handle))
	if !ok {
		return -1
	}
	entry := v.(*nodeEntry)

	peerURI := C.GoString(uri)
	if err := entry.core.RemovePeer(parseURI(peerURI), ""); err != nil {
		fmt.Fprintf(os.Stderr, "[yggbridge] remove_peer %s failed: %v\n", peerURI, err)
		return -1
	}
	return 0
}

func parseURI(raw string) *url.URL {
	u, _ := url.Parse(raw)
	return u
}

//export ygg_shutdown
func ygg_shutdown(handle C.uintptr_t) {
	v, ok := nodes.LoadAndDelete(uintptr(handle))
	if !ok {
		return
	}
	entry := v.(*nodeEntry)
	entry.nic.Close()
	entry.stack.Close()
	entry.core.Stop()
	entry.cancel()
	fmt.Fprintf(os.Stderr, "[yggbridge] node %d shut down\n", handle)
}

//export ygg_free
func ygg_free(ptr *C.char) {
	C.free(unsafe.Pointer(ptr))
}

func main() {}
