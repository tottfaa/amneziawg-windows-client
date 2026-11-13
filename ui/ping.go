/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2022 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/amnezia-vpn/amneziawg-windows-client/l18n"
	"github.com/amnezia-vpn/amneziawg-windows-client/manager"
)

const (
	pingTimeout         = 2 * time.Second
	pingAttempts        = 3
	pingParallelism     = 8
	pingPayloadSize     = 32
	pingReplyBufferSize = 256
	icmpStatusOffset    = 4
	icmpRoundTripOffset = 8
	icmpStatusSuccess   = 0
)

var (
	iphlpapi            = windows.NewLazySystemDLL("iphlpapi.dll")
	procIcmpCreateFile  = iphlpapi.NewProc("IcmpCreateFile")
	procIcmpCloseHandle = iphlpapi.NewProc("IcmpCloseHandle")
	procIcmpSendEcho    = iphlpapi.NewProc("IcmpSendEcho")
)

var (
	errNoEndpoint = errors.New("tunnel has no endpoint")
	errNoIPv4     = errors.New("endpoint has no IPv4 address")
	errNoReply    = errors.New("no echo reply")
)

type pingResult struct {
	roundTrip time.Duration
	err       error
}

func (r pingResult) String() string {
	switch {
	case errors.Is(r.err, errNoReply):
		return l18n.Sprintf("timeout")
	case r.err != nil:
		return l18n.Sprintf("n/a")
	case r.roundTrip < time.Millisecond:
		return "<1 ms"
	}
	return fmt.Sprintf("%d ms", r.roundTrip.Milliseconds())
}

func resolveIPv4(host string) (net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			return ip4, nil
		}
		return nil, errNoIPv4
	}
	ctx, cancel := context.WithTimeout(context.Background(), pingTimeout)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	for _, addr := range addrs {
		if ip4 := addr.IP.To4(); ip4 != nil {
			return ip4, nil
		}
	}
	return nil, errNoIPv4
}

func echoRoundTrip(host string) pingResult {
	ip, err := resolveIPv4(host)
	if err != nil {
		return pingResult{err: err}
	}

	handle, _, callErr := procIcmpCreateFile.Call()
	if handle == uintptr(windows.InvalidHandle) {
		return pingResult{err: callErr}
	}
	defer procIcmpCloseHandle.Call(handle)

	var payload [pingPayloadSize]byte
	var reply [pingReplyBufferSize]byte
	destination := uintptr(binary.LittleEndian.Uint32(ip))
	for attempt := 0; attempt < pingAttempts; attempt++ {
		replies, _, _ := procIcmpSendEcho.Call(
			handle,
			destination,
			uintptr(unsafe.Pointer(&payload[0])),
			uintptr(len(payload)),
			0,
			uintptr(unsafe.Pointer(&reply[0])),
			uintptr(len(reply)),
			uintptr(pingTimeout/time.Millisecond),
		)
		if replies == 0 || binary.LittleEndian.Uint32(reply[icmpStatusOffset:]) != icmpStatusSuccess {
			continue
		}
		milliseconds := binary.LittleEndian.Uint32(reply[icmpRoundTripOffset:])
		return pingResult{roundTrip: time.Duration(milliseconds) * time.Millisecond}
	}
	return pingResult{err: errNoReply}
}

func endpointHost(tunnel manager.Tunnel) (string, error) {
	config, err := tunnel.StoredConfig()
	if err != nil {
		return "", err
	}
	for _, peer := range config.Peers {
		if !peer.Endpoint.IsEmpty() {
			return peer.Endpoint.Host, nil
		}
	}
	return "", errNoEndpoint
}

func pingTunnel(tunnel manager.Tunnel) pingResult {
	host, err := endpointHost(tunnel)
	if err != nil {
		return pingResult{err: err}
	}
	return echoRoundTrip(host)
}

func pingTunnels(tunnels []manager.Tunnel, report func(manager.Tunnel, pingResult)) {
	slots := make(chan struct{}, pingParallelism)
	var wg sync.WaitGroup
	for _, tunnel := range tunnels {
		wg.Add(1)
		slots <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-slots }()
			report(tunnel, pingTunnel(tunnel))
		}()
	}
	wg.Wait()
}
