package fingerprint

import (
	"bytes"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	device          string = "any"
	snapshotLen     int32  = 1024
	promiscuous     bool   = false
	err             error
	timeout         time.Duration = 30 * time.Second
	Protocol_DHCPv4 uint8         = 1
	Protocol_DHCPv6 uint8         = 2
	DHCPv6OptVendor uint16        = 16
)

type DhcpFprint struct {
	ProtocolType uint8 //1:DHCPv4, 2:DHCPv6
	MessageType  byte
	TTL          uint8
	Opts         []byte //client->server options
	OptType      byte
	OptData      []byte
	Vendor       []byte
	OsName       string
}

var g_dhcpFprint []*DhcpFprint
var g_RwMutex sync.RWMutex

func formatMAC(mac []byte) string {
	var m []string
	for i := 0; i < len(mac); i++ {
		m = append(m, fmt.Sprintf("%02x", mac[i]))
	}
	return strings.Join(m, ":")
}

func LoadFingerprint(fingerprint *DhcpFprint) {
	g_RwMutex.Lock()
	defer g_RwMutex.Unlock()
	g_dhcpFprint = append(g_dhcpFprint, fingerprint)
}

func CollectSysNameByFingerprint() {
	go handleFingerprintDHCPv4()
	go handleFingerprintDHCPv6()
}

func handleFingerprintDHCPv4() {
	handle, err := pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
	if err != nil {
		handle, err = pcap.OpenOffline(device)
	}
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	var filter string = "src port 68 and dst port 67"
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		parsePacketDHCPv4(packet)
	}
}

func handleFingerprintDHCPv6() {
	handle, err := pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
	if err != nil {
		handle, err = pcap.OpenOffline(device)
	}
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	var filter string = "src port 546 and dst port 547"
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		parsePacketDHCPv6(packet)
	}
}

func parsePacketDHCPv4(packet gopacket.Packet) {
	var TTL uint8 = 0
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		TTL = uint8(ip.TTL)
	}

	dpcpv4Layer := packet.Layer(layers.LayerTypeDHCPv4)
	if dpcpv4Layer != nil {
		dhcpv4, _ := dpcpv4Layer.(*layers.DHCPv4)
		macAddr := formatMAC(dhcpv4.ClientHWAddr)
		sysName := matchFingerprintDHCPv4(TTL, dhcpv4.Options)
		//output to syslog
		if sysName != "" {
			log.Println("mac addr:", macAddr, "system name:", sysName)
		}
	}
}

func parsePacketDHCPv6(packet gopacket.Packet) {
	var TTL uint8 = 0
	ipLayer := packet.Layer(layers.LayerTypeIPv6)
	if ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv6)
		TTL = ip.HopLimit
	}

	dpcpv6Layer := packet.Layer(layers.LayerTypeDHCPv6)
	if dpcpv6Layer != nil {
		dhcpv6, _ := dpcpv6Layer.(*layers.DHCPv6)
		macAddr := getMacForDHCPv6Option(dhcpv6.Options)
		sysName := matchFingerprintDHCPv6(TTL, byte(dhcpv6.MsgType), dhcpv6.Options)
		//output to syslog
		if sysName != "" {
			log.Println("mac addr:", macAddr, "system name:", sysName)
		}
	}
}

func matchFingerprintDHCPv4(ttl uint8, packetOpts layers.DHCPOptions) string {
	g_RwMutex.RLock()
	defer g_RwMutex.RUnlock()

	for i := 0; i < len(g_dhcpFprint); i++ {
		if g_dhcpFprint[i].ProtocolType == Protocol_DHCPv6 {
			continue
		}
		var msgType []byte
		msgType = append(msgType, g_dhcpFprint[i].MessageType)
		if (isOptEqual(byte(layers.DHCPOptMessageType), msgType, packetOpts)) &&
			(ttl == g_dhcpFprint[i].TTL || g_dhcpFprint[i].TTL == 0) &&
			(isOptsEqual(g_dhcpFprint[i].Opts, packetOpts) || g_dhcpFprint[i].Opts[0] == 0) &&
			(isOptEqual(g_dhcpFprint[i].OptType, g_dhcpFprint[i].OptData, packetOpts) || g_dhcpFprint[i].OptType == 0) &&
			(isOptEqual(byte(layers.DHCPOptClassID), g_dhcpFprint[i].Vendor, packetOpts) || string(g_dhcpFprint[i].Vendor) == "*") {
			return g_dhcpFprint[i].OsName
		}
	}

	return ""
}

func matchFingerprintDHCPv6(ttl uint8, msgType byte, packetOpts layers.DHCPv6Options) string {
	g_RwMutex.RLock()
	defer g_RwMutex.RUnlock()

	for i := 0; i < len(g_dhcpFprint); i++ {
		if g_dhcpFprint[i].ProtocolType == Protocol_DHCPv4 {
			continue
		}

		if (g_dhcpFprint[i].MessageType == msgType) &&
			(ttl == g_dhcpFprint[i].TTL || g_dhcpFprint[i].TTL == 0) &&
			(isOptsEqualDHCPv6(g_dhcpFprint[i].Opts, packetOpts) || g_dhcpFprint[i].Opts[0] == 0) &&
			(isOptEqualDHCPv6(uint16(g_dhcpFprint[i].OptType), g_dhcpFprint[i].OptData, packetOpts) || g_dhcpFprint[i].OptType == 0) &&
			(isOptEqualDHCPv6(DHCPv6OptVendor, g_dhcpFprint[i].Vendor, packetOpts) || string(g_dhcpFprint[i].Vendor) == "*") {
			return g_dhcpFprint[i].OsName
		}
	}

	return ""
}

func isOptExist(optType byte, packetOpts layers.DHCPOptions) bool {
	for i := 0; i < len(packetOpts); i++ {
		if optType == byte(packetOpts[i].Type) {
			return true
		}
	}

	return false
}

func isOptExistDHCPv6(optType byte, packetOpts layers.DHCPv6Options) bool {
	code := uint16(optType)
	for i := 0; i < len(packetOpts); i++ {
		if code == uint16(packetOpts[i].Code) {
			return true
		}
	}

	return false
}

func isOptsEqual(opts []byte, packetOpts layers.DHCPOptions) bool {
	for i := 0; i < len(opts); i++ {
		if isOptExist(opts[i], packetOpts) == false {
			return false
		}
	}
	return true
}

func isOptsEqualDHCPv6(opts []byte, packetOpts layers.DHCPv6Options) bool {
	for i := 0; i < len(opts); i++ {
		if isOptExistDHCPv6(opts[i], packetOpts) == false {
			return false
		}
	}

	return true
}

func isOptEqual(optType byte, optValue []byte, packetOpts layers.DHCPOptions) bool {
	for i := 0; i < len(packetOpts); i++ {
		if optType == byte(packetOpts[i].Type) && bytes.Equal(optValue, packetOpts[i].Data) {
			return true
		}
	}

	return false
}

func isOptEqualDHCPv6(code uint16, optValue []byte, packetOpts layers.DHCPv6Options) bool {
	for i := 0; i < len(packetOpts); i++ {
		if code == uint16(packetOpts[i].Code) && bytes.Equal(optValue, packetOpts[i].Data) {
			return true
		}
	}

	return false
}

func getMacForDHCPv6Option(packetOpts layers.DHCPv6Options) string {
	for i := 0; i < len(packetOpts); i++ {
		if layers.DHCPv6OptClientID == packetOpts[i].Code {
			tmpLen := packetOpts[i].Length - 6
			mac := packetOpts[i].Data[tmpLen:]
			return formatMAC(mac)
		}
	}

	return ""
}
