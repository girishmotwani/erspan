package main

import (
	"flag"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.int.brkt.net/brkt/wildling/lib/erspan"
	"log"
)

/*
func HandlePacket(pkt gopacket.Packet) ([]byte, error) {

	if ipLayer := pkt.Layer(layers.LayerTypeIPv4); ipLayer != nil {

		//ether, _ := ethLayer.(*layers.Ethernet)
		ip, _ := ipLayer.(*layers.IPv4)
		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{}

		//ether.SerializeTo(buf, opts)
		ip.SerializeTo(buf, opts)

		return buf.Bytes(), nil
	}
	return nil, errors.New("No ethernet header in packet")
}
*/


func main() {
	device := flag.String("device", "", "Device to monitor traffic on")
	bpf := flag.String("filter", "", "BPF to apply to instance traffic")
	destIp := flag.String("ipAddress", "", "IP address of tap reciever")
	flag.Parse()

	if len(*device) == 0 {
		log.Fatal("No device configured, exiting...\n")
	}

	tap := erspan.NewErspanEncap(*destIp, 0, 1)
	tap.Connect()

	// Open Device
	handle, err := pcap.OpenLive(*device, 16*1024, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Set filter
	if len(*bpf) != 0 {
		err = handle.SetBPFFilter(*bpf)
		if err != nil {
			log.Fatal(err)
		}
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		/*
		pktData, err := HandlePacket(packet)
		if err != nil {
			log.Printf("%s\n", err)

		}
		*/
		tap.Send(packet.Metadata().CaptureInfo, packet.Data())
	}
}
