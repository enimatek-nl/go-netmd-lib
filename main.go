package main

import (
	"fmt"
	"github.com/google/gousb"
	"github.com/google/gousb/usbid"
	"gomd/netmd"
	"log"
)

func main() {

	ctx := gousb.NewContext()
	defer ctx.Close()

	devs, err := ctx.OpenDevices(func(desc *gousb.DeviceDesc) bool {
		// TODO: add logic to only identify correct devices
		fmt.Printf("%03d.%03d %s:%s %s\n", desc.Bus, desc.Address, desc.Vendor, desc.Product, usbid.Describe(desc))
		return true
	})

	defer func() {
		for _, d := range devs {
			d.Close()
		}
	}()

	if err != nil {
		log.Fatalf("list: %s", err)
	}

	if len(devs) > 0 {
		md, _ := netmd.NewNetMD(devs[0], true)

		disk, _ := md.RequestStatus()
		if disk {

			header, _ := md.RequestDiscHeader()
			log.Println(header)

			recorded, total, available, _ := md.RequestDiscCapacity()
			log.Println(recorded, total, available)

			//encoding, _, _ := md.RecordingParameters()

			//name := "big.wav"
			//name := "demo.wav"

			//track, err := md.NewTrack(name, netmd.WfPCM, netmd.DfStereoSP)
			//if err != nil {
			//	log.Fatal(err)
			//}
			//log.Printf("Prepared Track; frameSize: %d frames: %d padding: %d packets: %d", netmd.FrameSize[track.Format], track.Frames, track.Padding, len(track.Packets))
			//
			//err = md.Send(track)
			//if err != nil {
			//	log.Fatal(err)
			//}

			//z, _ := md.RequestTrackLength(2)
			t,_:=md.RequestTrackTitle(2)
			log.Println(t)

		}
	}
}
