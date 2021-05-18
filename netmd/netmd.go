package netmd

import (
	"errors"
	"github.com/google/gousb"
	"log"
	"time"
)

type NetMD struct {
	debug bool
	dev   *gousb.Device
	out   *gousb.OutEndpoint
	ekb   *EKB
}

type Encoding byte

type Channels byte

const (
	encSP  Encoding = 0x90
	encLP2 Encoding = 0x92
	encLP4 Encoding = 0x93

	chanStereo Channels = 0x00
	chanMono   Channels = 0x01
)

var (
	ByteArr16 = []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
)

func NewNetMD(dev *gousb.Device, debug bool) (md *NetMD, err error) {
	md = &NetMD{
		dev:   dev,
		debug: debug,
		ekb:   NewEKB(),
	}
	for num := range md.dev.Desc.Configs {
		config, _ := md.dev.Config(num)
		for _, desc := range config.Desc.Interfaces {
			intf, _ := config.Interface(desc.Number, 0)
			for _, endpointDesc := range intf.Setting.Endpoints {
				if endpointDesc.Direction == gousb.EndpointDirectionOut {
					if md.out, err = intf.OutEndpoint(endpointDesc.Number); err != nil {
						return
					}
					if md.debug {
						log.Printf("%s", endpointDesc)
					}
				}
			}
			config.Close()
		}
	}
	return
}

func (md *NetMD) Send(trk *Track) (err error) {
	// housekeeping
	md.forgetSecureKey()
	md.leaveSecureSession()

	// set up the secure session
	md.acquire()
	md.trackProtection(0x01) // fails on sharp?
	md.enterSecureSession()
	md.sendKeyData()
	md.sessionKeyExchange()
	sessionKey, _ := md.ekb.RetailMAC() // build the local sessionKey
	md.kekExchange(sessionKey)          // (data) key encryption key

	totalBytes := (trk.Frames * FrameSize[trk.Format]) + 24
	if md.debug {
		log.Printf("calculated a total bytes of %d", totalBytes)
	}
	err = md.initSecureSend(trk.Format, trk.discFormat, trk.Frames, totalBytes)
	if err != nil {
		return
	}

	key, err := DESDecrypt(trk.key, md.ekb.kek)
	if err != nil {
		return
	}

	dataCounter := 0
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
			log.Fatal(err)
		}
		dataCounter += t
		log.Printf("Packet %d / %d Transmitted: %d bytes", i, len(trk.Packets), dataCounter)
	}
	
	log.Println("waiting for MD to finish data write")
	i := -1
	for t := 0; t < 99; t++ {
		i = md.poll()
		if i != -1 {
			break
		}
		time.Sleep(time.Millisecond * 250)
	}

	r, err := md.receive(i)
	if err != nil {
		log.Fatal(err)
	}
	if md.debug {
		log.Printf("Encrypted Reply: % x", r)
	}

	trackNr := hexToInt16(r[17:19])
	if md.debug {
		log.Printf("track %d to committed", trackNr)
	}

	//decoderBlock, err := des.NewCipher(sessionKey)
	//decoder := cipher.NewCBCDecrypter(decoderBlock, ByteArr16)
	//decoder.CryptBlocks()
	//													  __ __ .. .. .. .. .. .. .. .. .. .. ..  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32
	// 09 18 00 08 00 46 f0 03 01 03 28 00 00 01 00 10 01 00 00 00 00 06 00 00 01 ed 00 0f 68 18 44 4d 5f f2 38 6c 6b 89 8b 67 97 3d 67 5c c5 be e1 ec ca 0a 50 12 1b 66 82 20 1e 3a 7e c7 5c ba 09 18 00 08 00 46 f0 03 01 03 28 00 00 01 00 10 01 00 00 00 00 06 00 00 01 ed 00 0f 68 18 44 4d 5f f2 38 6c 6b 89 8b 67 97 3d 67 5c c5 be e1 ec ca 0a 50 12 1b 66 82 20 1e 3a 7e c7 5c ba

	err = md.CacheTOC()
	if err != nil {
		return
	}

	// TODO: set trackname?

	err = md.SyncTOC()
	if err != nil {
		return
	}
	err = md.commitTrack(int(trackNr), sessionKey)
	if err != nil {
		return
	}

	md.forgetSecureKey()
	md.leaveSecureSession()
	md.release()

	return
}

func (md *NetMD) RequestDiscCapacity() (recorded uint64, total uint64, available uint64, err error) {
	r, err := md.call([]byte{0x00, 0x18, 0x06, 0x02, 0x10, 0x10, 0x00, 0x30, 0x80, 0x03, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00})
	if err != nil {
		return
	}
	recorded = (hexToInt(r[29]) * 3600) + (hexToInt(r[30]) * 60) + hexToInt(r[31])
	total = (hexToInt(r[35]) * 3600) + (hexToInt(r[36]) * 60) + hexToInt(r[37])
	available = (hexToInt(r[42]) * 3600) + (hexToInt(r[43]) * 60) + hexToInt(r[44])
	return
}

func (md *NetMD) SetDiscHeader(t string) error {
	o, err := md.RequestDiscHeader()
	if err != nil {
		return err
	}
	j := len(o) // length of old title
	h := len(t) // length of new title
	c := []byte{0x00, 0x18, 0x07, 0x02, 0x20, 0x18, 0x01, 0x00, 0x00, 0x30, 0x00, 0x0a, 0x00, 0x50, 0x00, 0x00, byte(h) & 0xff, 0x00, 0x00, 0x00, byte(j) & 0xff}
	c = append(c, []byte(t)...) // append actual title data
	_, err = md.call(c)
	if err != nil {
		return err
	}
	return nil
}

func (md *NetMD) RequestDiscHeader() (string, error) {
	r, err := md.call([]byte{0x00, 0x18, 0x06, 0x02, 0x20, 0x18, 0x01, 0x00, 0x00, 0x30, 0x00, 0x0a, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00})
	if err != nil {
		return "", err
	}
	return string(r[25:]), nil
}

func (md *NetMD) RequestTrackTitle(trk int) (t string, err error) {
	r, err := md.call([]byte{0x00, 0x18, 0x06, 0x02, 0x20, 0x18, 0x01, 0x00, byte(trk) & 0xff, 0x30, 0x00, 0x0a, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00})
	if err != nil {
		return
	}
	t = string(r[0:])
	return
}

func (md *NetMD) RecordingParameters() (encoding Encoding, channels Channels, err error) {
	r, err := md.call([]byte{0x00, 0x18, 0x09, 0x80, 0x01, 0x03, 0x30, 0x88, 0x01, 0x00, 0x30, 0x88, 0x05, 0x00, 0x30, 0x88, 0x07, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00})
	if err != nil {
		return
	}
	encoding = Encoding(r[34])
	channels = Channels(r[35])
	return
}

func (md *NetMD) RequestStatus() (disk bool, err error) {
	r, err := md.call([]byte{0x00, 0x18, 0x09, 0x80, 0x01, 0x02, 0x30, 0x88, 0x00, 0x00, 0x30, 0x88, 0x04, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00})
	if err != nil {
		return
	}
	disk = r[26] == 0x40 // 0x80 no disk
	return
}

func (md *NetMD) SyncTOC() error {
	_, err := md.call([]byte{0x00, 0x18, 0x08, 0x10, 0x18, 0x02, 0x00, 0x00})
	if err != nil {
		return err
	}
	return nil
}

func (md *NetMD) CacheTOC() error {
	_, err := md.call([]byte{0x00, 0x18, 0x08, 0x10, 0x18, 0x02, 0x03, 0x00})
	if err != nil {
		return err
	}
	return nil
}

func (md *NetMD) EraseTrack(trk int) {

}

func (md *NetMD) MoveTrack(trk, to int) {

}

func (md *NetMD) RequestTrackLength(trk int) {

}

func (md *NetMD) RequestTrackEncoding(trk int) {

}

func (md *NetMD) call(i []byte) ([]byte, error) {
	md.poll()
	if _, err := md.dev.Control(gousb.ControlOut|gousb.ControlVendor|gousb.ControlInterface, 0x80, 0, 0, i); err != nil {
		return nil, err
	}
	if md.debug {
		log.Printf("md.call send <- % x", i)
	}

	for tries := 0; tries < 4; tries++ {
		if h := md.poll(); h != -1 {
			b, err := md.receive(h)
			if err != nil {
				return nil, err
			}
			return b, nil
		}
		time.Sleep(time.Millisecond * 100)
	}

	return nil, errors.New("poll failed")
}

func (md *NetMD) receive(s int) ([]byte, error) {
	buf := make([]byte, s)
	if _, err := md.dev.Control(gousb.ControlIn|gousb.ControlVendor|gousb.ControlInterface, 0x81, 0, 0, buf); err != nil {
		return nil, err
	}
	if md.debug {
		if buf[0] == 0x0a {
			return nil, errors.New("controlIn was rejected")
		} else if buf[0] == 0x09 {
			log.Print(" -> Accepted.")
		} else if buf[0] == 0x0f {
			log.Printf(" -> Interm...")
		}
	}
	return buf, nil
}

func (md *NetMD) poll() int {
	buf := make([]byte, 4)
	md.dev.Control(gousb.ControlIn|gousb.ControlVendor|gousb.ControlInterface, 0x01, 0, 0, buf)
	if buf[0] == 0x01 && buf[1] == 0x81 {
		return int(buf[2])
	}
	return -1
}
