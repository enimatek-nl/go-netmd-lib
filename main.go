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

			encoding, _, _ := md.RecordingParameters()
			switch encoding {
			case netmd.ATRACSP:
				log.Println("ATRAC SP")
			case netmd.ATRAC3LP2:
				log.Println("ATRAC3 LP2")
			case netmd.ATRAC3LP4:
				log.Println("ATRAC3 LP4")
			}

			md.PrepareSend()
		}
	}
}
