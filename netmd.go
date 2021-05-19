package gomd

import (
	"errors"
	"github.com/google/gousb"
	"log"
	"time"
)

type NetMD struct {
	debug bool
	index int
	devs  []*gousb.Device
	ctx   *gousb.Context
	out   *gousb.OutEndpoint
	ekb   *EKB
}

type Encoding byte

type Channels byte

const (
	EncSP  Encoding = 0x90
	EncLP2 Encoding = 0x92
	EncLP4 Encoding = 0x93

	ChanStereo Channels = 0x00
	ChanMono   Channels = 0x01
)

var (
	ByteArr16 = []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
)

func NewNetMD(index int, debug bool) (md *NetMD, err error) {
	md = &NetMD{
		index: index,
		debug: debug,
		ekb:   NewEKB(),
	}

	md.ctx = gousb.NewContext()
	md.devs, err = md.ctx.OpenDevices(func(desc *gousb.DeviceDesc) bool {
		for _, d := range Devices {
			if d.deviceId == desc.Product && d.vendorId == desc.Vendor {
				if md.debug {
					log.Printf("Found %s", d.name)
				}
				return true
			}
		}
		return false
	})

	if err != nil {
		return
	}

	if len(md.devs) == 0 || len(md.devs) <= md.index {
		err = errors.New("no compatible netmd device found or incorrect index")
		return
	}

	for num := range md.devs[md.index].Desc.Configs {
		config, _ := md.devs[md.index].Config(num)
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

func (md *NetMD) Close() {
	for _, d := range md.devs {
		d.Close()
	}
	md.ctx.Close()
}

// Send will transmit the Track data encrypted to the NetMD
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
	err = md.initSecureSend(trk.Format, trk.DiscFormat, trk.Frames, totalBytes)
	if err != nil {
		return
	}

	key, _ := DESDecrypt(trk.key, md.ekb.kek)
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
		if md.debug {
			log.Printf("Packet %d / %d Transmitted: %d bytes", i, len(trk.Packets), dataCounter)
		}
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
		return
	}
	if md.debug {
		log.Printf("Encrypted Reply: % x", r) // why decode this? it's not really used...
	}

	trackNr := hexToInt16(r[17:19])
	if md.debug {
		log.Printf("track %d committed", trackNr)
	}

	err = md.cacheTOC()
	if err != nil {
		return
	}

	err = md.SetTrackTitle(int(trackNr), trk.Title, true)
	if err != nil {
		return
	}

	err = md.syncTOC()
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

// RequestDiscCapacity returns the totals in seconds
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

// SetDiscHeader will write  a raw title to the disc
func (md *NetMD) SetDiscHeader(t string) error {
	o, err := md.RequestDiscHeader()
	if err != nil {
		return err
	}
	j := len(o) // length of old title
	h := len(t) // length of new title
	c := []byte{0x00, 0x18, 0x07, 0x02, 0x20, 0x18, 0x01, 0x00, 0x00, 0x30, 0x00, 0x0a, 0x00, 0x50, 0x00}
	c = append(c, intToHex16(int16(h))...)
	c = append(c, 0x00, 0x00)
	c = append(c, intToHex16(int16(j))...)
	c = append(c, []byte(t)...)
	_, err = md.call(c)
	if err != nil {
		return err
	}
	return nil
}

// RequestDiscHeader returns the raw title of the disc
func (md *NetMD) RequestDiscHeader() (string, error) {
	r, err := md.call([]byte{0x00, 0x18, 0x06, 0x02, 0x20, 0x18, 0x01, 0x00, 0x00, 0x30, 0x00, 0x0a, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00})
	if err != nil {
		return "", err
	}
	return string(r[25:]), nil
}

// RecordingParameters current default recording parameters set on the NetMD
func (md *NetMD) RecordingParameters() (encoding Encoding, channels Channels, err error) {
	r, err := md.call([]byte{0x00, 0x18, 0x09, 0x80, 0x01, 0x03, 0x30, 0x88, 0x01, 0x00, 0x30, 0x88, 0x05, 0x00, 0x30, 0x88, 0x07, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00})
	if err != nil {
		return
	}
	encoding = Encoding(r[34])
	channels = Channels(r[35])
	return
}

// RequestStatus returns known status flags
func (md *NetMD) RequestStatus() (disk bool, err error) {
	r, err := md.call([]byte{0x00, 0x18, 0x09, 0x80, 0x01, 0x02, 0x30, 0x88, 0x00, 0x00, 0x30, 0x88, 0x04, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00})
	if err != nil {
		return
	}
	disk = r[26] == 0x40 // 0x80 no disk
	return
}

// RequestTrackTitle returns the raw title of the trk number starting from 0
func (md *NetMD) RequestTrackTitle(trk int) (t string, err error) {
	r, err := md.call([]byte{0x00, 0x18, 0x06, 0x02, 0x20, 0x18, byte(2) & 0xff, 0x00, byte(trk) & 0xff, 0x30, 0x00, 0x0a, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00})
	if err != nil {
		return
	}
	t = string(r[25:])
	return
}

// SetTrackTitle set the title of the trk number starting from 0, isNew can be be true if it's a newadded track
func (md *NetMD) SetTrackTitle(trk int, t string, isNew bool) (err error) {
	j := 0
	if !isNew {
		o, err := md.RequestTrackTitle(trk)
		if err != nil {
			return err
		}
		j = len(o) // length of old title
	}
	h := len(t) // length of new title
	s := []byte{0x00, 0x18, 0x07, 0x02, 0x20, 0x18, byte(2) & 0xff, 0x00, byte(trk) & 0xff, 0x30, 0x00, 0x0a, 0x00, 0x50, 0x00}
	s = append(s, intToHex16(int16(h))...)
	s = append(s, 0x00, 0x00)
	s = append(s, intToHex16(int16(j))...)
	s = append(s, []byte(t)...)
	_, err = md.call(s)
	if err != nil {
		return
	}
	return
}

// EraseTrack will erase the trk number starting from 0
func (md *NetMD) EraseTrack(trk int) error {
	s := []byte{0x00, 0x18, 0x40, 0xff, 0x01, 0x00, 0x20, 0x10, 0x01}
	s = append(s, intToHex16(int16(trk))...)
	_, err := md.call(s)
	if err != nil {
		return err
	}
	return nil
}

// MoveTrack will move the trk number to a new position
func (md *NetMD) MoveTrack(trk, to int) error {
	s := []byte{0x00, 0x18, 0x43, 0xff, 0x00, 0x00, 0x20, 0x10, 0x01}
	s = append(s, intToHex16(int16(trk))...)
	s = append(s, 0x20, 0x10, 0x01)
	s = append(s, intToHex16(int16(to))...)
	_, err := md.call(s)
	if err != nil {
		return err
	}
	return nil
}

// RequestTrackLength returns the duration in seconds of the trk starting from 0
func (md *NetMD) RequestTrackLength(trk int) (duration uint64, err error) {
	s := []byte{0x00, 0x18, 0x06, 0x02, 0x20, 0x10, 0x01}
	s = append(s, intToHex16(int16(trk))...)
	s = append(s, 0x30, 0x00, 0x01, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00)
	r, err := md.call(s)
	if err != nil {
		return
	}
	duration = (hexToInt(r[27]) * 3600) + (hexToInt(r[28]) * 60) + hexToInt(r[29])
	return
}

// RequestTrackEncoding returns the Encoding of the trk starting from 0
func (md *NetMD) RequestTrackEncoding(trk int) (encoding Encoding, err error) {
	s := []byte{0x00, 0x18, 0x06, 0x02, 0x20, 0x10, 0x01}
	s = append(s, intToHex16(int16(trk))...)
	s = append(s, 0x30, 0x80, 0x07, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00)
	r, err := md.call(s)
	if err != nil {
		return
	}
	return Encoding(r[len(r)-2]), nil
}

func (md *NetMD) call(i []byte) ([]byte, error) {
	md.poll()
	if _, err := md.devs[md.index].Control(gousb.ControlOut|gousb.ControlVendor|gousb.ControlInterface, 0x80, 0, 0, i); err != nil {
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
	if _, err := md.devs[md.index].Control(gousb.ControlIn|gousb.ControlVendor|gousb.ControlInterface, 0x81, 0, 0, buf); err != nil {
		return nil, err
	}
	if md.debug {
		if buf[0] == 0x0a {
			return nil, errors.New("controlIn was rejected")
		} else if buf[0] == 0x09 {
			log.Print(" -> Accepted.")
		} else if buf[0] == 0x0f {
			log.Printf(" -> Interim <-")
		}
	}
	return buf, nil
}

func (md *NetMD) poll() int {
	buf := make([]byte, 4)
	md.devs[md.index].Control(gousb.ControlIn|gousb.ControlVendor|gousb.ControlInterface, 0x01, 0, 0, buf)
	if buf[0] == 0x01 && buf[1] == 0x81 {
		return int(buf[2])
	}
	return -1
}
