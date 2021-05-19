package main

import (
	"gomd/netmd"
	"log"
)

func main() {

	md, err := netmd.NewNetMD(0, true)
	if err != nil {
		log.Fatal(err)
	}
	defer md.Close()

	disk, _ := md.RequestStatus()
	if disk {

		header, _ := md.RequestDiscHeader()
		log.Println(header)

		recorded, total, available, _ := md.RequestDiscCapacity()
		log.Println(recorded, total, available)

		//encoding, _, _ := md.RecordingParameters()

		//name := "big.wav"
		fn := "demo.wav"

		track, err := md.NewTrack("My New Track", fn, netmd.WfPCM, netmd.DfStereoSP)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("Prepared Track; frameSize: %d frames: %d padding: %d packets: %d", netmd.FrameSize[track.Format], track.Frames, track.Padding, len(track.Packets))
		//
		err = md.Send(track)
		if err != nil {
			log.Fatal(err)
		}

		//z, _ := md.RequestTrackLength(2)
		//md.SetTrackTitle(2, "poep in je schoen")
		//t, _ := md.RequestTrackTitle(2)
		//log.Println(t)
	}

}
