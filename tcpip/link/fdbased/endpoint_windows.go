// Copyright 2016 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package fdbased provides the implemention of data-link layer endpoints
// backed by boundary-preserving file descriptors (e.g., TUN devices,
// seqpacket/datagram sockets).
//
// FD based endpoints can be used in the networking stack by calling New() to
// create a new endpoint, and then passing it as an argument to
// Stack.CreateNIC().
package fdbased

import (
	"github.com/FlowerWrong/netstack/tcpip"
	"github.com/FlowerWrong/netstack/tcpip/buffer"
	"github.com/FlowerWrong/netstack/tcpip/header"
	"github.com/FlowerWrong/netstack/tcpip/link/rawfile"
	"github.com/FlowerWrong/netstack/tcpip/stack"
	"github.com/FlowerWrong/water"
	"log"
)

// BufConfig defines the shape of the vectorised view used to read packets from the NIC.
var BufConfig = []int{128, 256, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768}

type endpoint struct {
	ifce *water.Interface
	// fd is the file descriptor used to send and receive packets.
	fd int

	// mtu (maximum transmission unit) is the maximum size of a packet.
	mtu uint32

	// closed is a function to be called when the FD's peer (if any) closes
	// its end of the communication pipe.
	closed func(*tcpip.Error)

	vv *buffer.VectorisedView
	// iovecs []syscall.Iovec
	views []buffer.View
}

// New creates a new fd-based endpoint.
func New(ifce *water.Interface, mtu uint32, closed func(*tcpip.Error)) tcpip.LinkEndpointID {
	e := &endpoint{
		ifce:   ifce,
		fd:     ifce.Fd(),
		mtu:    mtu,
		closed: closed,
		views:  make([]buffer.View, 1),
		// iovecs: make([]syscall.Iovec, 1),
	}
	vv := buffer.NewVectorisedView(0, e.views)
	e.vv = &vv
	return stack.RegisterLinkEndpoint(e)
}

// Attach launches the goroutine that reads packets from the file descriptor and
// dispatches them via the provided dispatcher.
func (e *endpoint) Attach(dispatcher stack.NetworkDispatcher) {
	go e.dispatchLoop(dispatcher)
}

// MTU implements stack.LinkEndpoint.MTU. It returns the value initialized
// during construction.
func (e *endpoint) MTU() uint32 {
	return e.mtu
}

// MaxHeaderLength returns the maximum size of the header. Given that it
// doesn't have a header, it just returns 0.
func (*endpoint) MaxHeaderLength() uint16 {
	return 0
}

// LinkAddress returns the link address of this endpoint.
func (*endpoint) LinkAddress() tcpip.LinkAddress {
	return ""
}

// WritePacket writes outbound packets to the file descriptor. If it is not
// currently writable, the packet is dropped.
func (e *endpoint) WritePacket(_ *stack.Route, hdr *buffer.Prependable, payload buffer.View, protocol tcpip.NetworkProtocolNumber) *tcpip.Error {
	if payload == nil {
		_, err := e.ifce.Write(hdr.UsedBytes())
		if err != nil {
			log.Fatal(err)
			return &tcpip.Error{}
		}
		return nil
	}

	p := append(hdr.UsedBytes(), payload...)
	_, err := e.ifce.Write(p)
	if err != nil {
		log.Fatal(err)
		return &tcpip.Error{}
	}
	return nil
}

func (e *endpoint) capViews(n int, buffers []int) int {
	c := 0
	for i, s := range buffers {
		c += s
		if c >= n {
			e.views[i].CapLength(s - (c - n))
			return i + 1
		}
	}
	return len(buffers)
}

func (e *endpoint) allocateViews(bufConfig []int) {
	for i, v := range e.views {
		if v != nil {
			break
		}
		b := buffer.NewView(bufConfig[i])
		e.views[i] = b
	}
}

// dispatch reads one packet from the file descriptor and dispatches it.
func (e *endpoint) dispatch(d stack.NetworkDispatcher, largeV buffer.View) (bool, *tcpip.Error) {
	customBufConfig := []int{int(e.MTU())}
	e.allocateViews(customBufConfig)

	packet := make([]byte, e.MTU())
	n, err := rawfile.Read(e.ifce, packet)
	if err != nil {
		log.Println(err)
		return false, err
	}

	if n <= 0 {
		return false, nil
	}

	e.views[0] = buffer.NewViewFromBytes(packet)
	e.vv.SetViews(e.views[:])
	e.vv.SetSize(n)

	// We don't get any indication of what the packet is, so try to guess
	// if it's an IPv4 or IPv6 packet.
	var p tcpip.NetworkProtocolNumber
	switch header.IPVersion(packet) {
	case header.IPv4Version:
		p = header.IPv4ProtocolNumber
	case header.IPv6Version:
		p = header.IPv6ProtocolNumber
	default:
		return true, nil
	}

	d.DeliverNetworkPacket(e, "", p, e.vv)

	return true, nil
}

// dispatchLoop reads packets from the file descriptor in a loop and dispatches
// them to the network stack.
func (e *endpoint) dispatchLoop(d stack.NetworkDispatcher) *tcpip.Error {
	v := buffer.NewView(header.MaxIPPacketSize)
	for {
		cont, err := e.dispatch(d, v)
		if err != nil || !cont {
			if e.closed != nil {
				e.closed(err)
			}
			return err
		}
	}
}

// InjectableEndpoint is an injectable fd-based endpoint. The endpoint writes
// to the FD, but does not read from it. All reads come from injected packets.
type InjectableEndpoint struct {
	endpoint

	dispatcher stack.NetworkDispatcher
}

// Attach saves the stack network-layer dispatcher for use later when packets
// are injected.
func (e *InjectableEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.dispatcher = dispatcher
}

// Inject injects an inbound packet.
func (e *InjectableEndpoint) Inject(protocol tcpip.NetworkProtocolNumber, vv *buffer.VectorisedView) {
	uu := vv.Clone(nil)
	e.dispatcher.DeliverNetworkPacket(e, "", protocol, &uu)
}

// NewInjectable creates a new fd-based InjectableEndpoint.
func NewInjectable(fd int, mtu uint32) (tcpip.LinkEndpointID, *InjectableEndpoint) {
	e := &InjectableEndpoint{endpoint: endpoint{
		fd:  fd,
		mtu: mtu,
	}}

	return stack.RegisterLinkEndpoint(e), e
}
