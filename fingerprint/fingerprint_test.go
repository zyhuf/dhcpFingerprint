package fingerprint_test

import (
	"bytes"
	"encoding/binary"
	"testing"

	"reyzar.com/fingerprint"
)

func Uint16ToBytes(x uint16) []byte {
	bytesBuffer := bytes.NewBuffer([]byte{})
	binary.Write(bytesBuffer, binary.BigEndian, x)

	return bytesBuffer.Bytes()
}

func TestFingerprint(t *testing.T) {
	fprint := new(fingerprint.DhcpFprint)

	fprint.ProtocolType = 1
	fprint.MessageType = 1 //1:dhcp discover 3:dhcp request 8: dhcp inform
	fprint.TTL = 128

	var opts []byte
	opts = append(opts, 53)
	opts = append(opts, 55)
	fprint.Opts = append(fprint.Opts, opts...)

	fprint.OptType = 55
	fprint.OptData = append(fprint.OptData, 1)
	fprint.OptData = append(fprint.OptData, 28)
	fprint.OptData = append(fprint.OptData, 2)
	fprint.OptData = append(fprint.OptData, 3)
	fprint.OptData = append(fprint.OptData, 15)
	fprint.OptData = append(fprint.OptData, 6)
	fprint.OptData = append(fprint.OptData, 12)

	fprint.Vendor = []byte("*")
	fprint.OsName = "Huawei honor"
	fingerprint.LoadFingerprint(fprint)

	fprint = new(fingerprint.DhcpFprint)
	fprint.ProtocolType = 2
	fprint.MessageType = 1 //1:dhcp Solicit 3:dhcp request
	fprint.TTL = 1
	fprint.Opts = append(fprint.Opts, 1)
	fprint.Opts = append(fprint.Opts, 6)
	fprint.Opts = append(fprint.Opts, 8)
	fprint.Opts = append(fprint.Opts, 3)
	fprint.OptType = 6
	//hexStr := "00010001260c7de1000c29abbe11"
	//data, _ := hex.DecodeString(hexStr)
	fprint.OptData = append(fprint.OptData, Uint16ToBytes(23)...)
	fprint.OptData = append(fprint.OptData, Uint16ToBytes(24)...)
	fprint.Vendor = []byte("*")
	fprint.OsName = "xiaoMi 10"
	fingerprint.LoadFingerprint(fprint)

	fingerprint.CollectSysNameByFingerprint()

	select {}
}
