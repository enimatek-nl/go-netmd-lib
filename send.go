package netmd

import (
	"errors"
	"log"
	"time"
)

type TransferType string

type Transfer struct {
	Type        TransferType
	Track       int
	Transferred int
	Error       error
}

const (
	TtSetup TransferType = "setup"
	TtSend  TransferType = "send"
	TtPoll  TransferType = "poll"
	TtTrack TransferType = "track"
)

// Send will transmit the Track data encrypted (concurrent) to the NetMD
// the Transfer channel will receive different TransferType's so the process can be followed closely from a different process
func (md *NetMD) Send(trk *Track, c chan Transfer) {
	if c == nil {
		return
	}

	// housekeeping
	md.forgetSecureKey()
	md.leaveSecureSession()

	c <- Transfer{
		Type: TtSetup,
	}

	// set up the secure session
	md.acquire()
	md.trackProtection(0x01) // fails on sharp?
	md.enterSecureSession()
	md.sendKeyData()
	md.sessionKeyExchange()
	sessionKey, _ := md.ekb.RetailMAC() // build the local sessionKey
	md.kekExchange(sessionKey)          // (data) key encryption key

	err := md.initSecureSend(trk.Format, trk.DiscFormat, trk.Frames, trk.TotalBytes())
	if err != nil {
		c <- Transfer{
			Error: err,
		}
		return
	}

	key, _ := DESDecrypt(trk.key, md.ekb.kek)
	dataCounter := 0

	c <- Transfer{
		Type:        TtSend,
		Transferred: dataCounter,
	}

	for i, p := range trk.Packets {
		s := make([]byte, 0)
		if p.first {
			s = append(s, intToHex64(int64(trk.Frames*FrameSize[trk.Format]))...)
			s = append(s, key...)
			s = append(s, md.ekb.iv...)
		}
		s = append(s, p.data...)
		t, err := md.out.Write(s)
		if err != nil {
			c <- Transfer{
				Error: err,
			}
			close(c)
			return
		}
		dataCounter += t
		c <- Transfer{
			Type:        TtSend,
			Transferred: dataCounter,
		}
		if md.debug {
			log.Printf("Packet %d / %d Transmitted: %d bytes", i, len(trk.Packets), dataCounter)
		}
	}

	if md.debug {
		log.Println("Waiting for MD to finish data write...")
	}
	i := -1
	for t := 0; t < 99; t++ {
		i = md.poll()
		if i != -1 {
			break
		}
		c <- Transfer{
			Type: TtPoll,
		}
		time.Sleep(time.Millisecond * 250)
	}
	if i == -1 {
		c <- Transfer{
			Error: errors.New("data write never finished"),
		}
		return
	}

	r, err := md.receive(i)
	if err != nil {
		return
	}
	if md.debug {
		log.Printf("Encrypted Reply: % x", r) // why decode this? it's not really used...
	}

	j := hexToInt16(r[17:19])
	trackNr := int(j)
	if md.debug {
		log.Printf("track %d committed", trackNr)
	}

	c <- Transfer{
		Type:  TtTrack,
		Track: trackNr,
	}

	err = md.cacheTOC()
	if err != nil {
		return
	}

	err = md.SetTrackTitle(trackNr, trk.Title, true)
	if err != nil {
		return
	}

	err = md.syncTOC()
	if err != nil {
		return
	}
	err = md.commitTrack(trackNr, sessionKey)
	if err != nil {
		return
	}

	md.forgetSecureKey()
	md.leaveSecureSession()
	md.release()

	close(c)
	return
}
