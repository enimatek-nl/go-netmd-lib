package netmd

import (
	"crypto/cipher"
	"crypto/des"
	"errors"
	"github.com/google/gousb"
	"log"
	"os"
	"time"
)

type NetMD struct {
	debug bool
	dev   *gousb.Device
	in    *gousb.InEndpoint
	out   *gousb.OutEndpoint
	maxIn int
}

type Encoding byte

type Channels byte

type WireFormat int

const (
	ATRACSP   Encoding = 0x90
	ATRAC3LP2 Encoding = 0x92
	ATRAC3LP4 Encoding = 0x93

	Stereo Channels = 0x00
	Mono   Channels = 0x01

	PCM WireFormat = 2048
	LP2 WireFormat = 192
	LP4 WireFormat = 96
)

func NewNetMD(dev *gousb.Device, debug bool) (md *NetMD, err error) {
	md = &NetMD{
		dev:   dev,
		debug: debug,
	}
	for num := range md.dev.Desc.Configs {
		config, _ := md.dev.Config(num)
		for _, desc := range config.Desc.Interfaces {
			intf, _ := config.Interface(desc.Number, 0)
			for _, endpointDesc := range intf.Setting.Endpoints {
				if endpointDesc.Direction == gousb.EndpointDirectionIn {
					if md.in, err = intf.InEndpoint(endpointDesc.Number); err != nil {
						return
					}
					md.maxIn = endpointDesc.MaxPacketSize
					if md.debug {
						log.Printf("%s", endpointDesc)
					}
				}
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

func (md *NetMD) Acquire() error {
	_, err := md.call([]byte{0x00, 0xff, 0x01, 0x0c, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	if err != nil {
		return err
	}
	return nil
}

func (md *NetMD) Release() error {
	_, err := md.call([]byte{0x00, 0xff, 0x01, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	if err != nil {
		return err
	}
	return nil
}

func (md *NetMD) PrepareSend() {
	md.ForgetSecureKey()
	md.LeaveSecureSession()

	md.Acquire()
	md.NewTrackProtection(0x01) // fails on sharp?
	md.EnterSecureSession()

	ekb := NewEKB()
	md.SendKeyData(ekb)

	nonce := NewNonce()
	md.SessionKeyExchange(nonce)

	sessionKey, _ := ekb.RetailMAC(nonce)
	md.RequestDownload(ekb, sessionKey)

	file, err := os.Open("demo.wav")
	if err != nil {
		log.Fatal(err)
	}
	stat, err := file.Stat()
	if err != nil {
		log.Fatal(err)
	}

	dataSize := stat.Size()

	defaultChunkSize := int64(0x00100000)
	chunkSize := defaultChunkSize
	var padding int64 = 0
	var offset int64 = 44
	packetCount := 0
	iv := ekb.FirstIV

	key, err := ekb.CreateKey()
	blk, err := des.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}

	// loop through offsets and create the 'packets'.
	if md.debug {
		log.Printf("file size %d chunk size %d", stat.Size(), chunkSize)
	}

	for offset < dataSize {

		chunkSize = defaultChunkSize
		if packetCount == 0 {
			chunkSize -= 24
		}

		if offset+chunkSize >= dataSize {
			padding = (offset + chunkSize) - dataSize
		}

		crypted := make([]byte, chunkSize)
		data := make([]byte, chunkSize-padding)
		_, err := file.ReadAt(data, offset)
		if err != nil {
			log.Fatal(err)
		}
		if padding > 0 {
			p := make([]byte, padding)
			data = append(data, p...)
		}
		encryptor := cipher.NewCBCEncrypter(blk, iv)
		encryptor.CryptBlocks(crypted, data)

		format := 0
		discFormat := 6
		frames := len(crypted) / int(PCM)
		totalBytes := len(crypted) + 24

		if md.debug {
			log.Printf("totalBytes: %d frames: %d", totalBytes, frames)
		}

		d := []byte{0x00, 0x18, 0x00, 0x08, 0x00, 0x46, 0xf0, 0x03, 0x01, 0x03, 0x28, 0xff, 0x00, 0x01, 0x00, 0x10, 0x01, 0xff, 0xff, 0x00, byte(format) & 0xff, byte(discFormat) & 0xff}
		d = append(d, intToHex32(int32(frames))...)
		d = append(d, intToHex32(int32(totalBytes))...)
		_, err = md.call(d)
		if err != nil {
			log.Fatal(err)
		}

		// if packetCount > 0 only add the data.. first chunk will be resized by -24
		s := []byte{0x00, 0x00, 0x00, 0x00}
		s = append(s, intToHex32(int32(len(crypted)))...)
		s = append(s, key...)
		s = append(s, ekb.FirstIV...)
		s = append(s, crypted...)

		// return data through chan?
		c, err := md.out.Write(s)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("done sending: %d", c)

		r, err := md.read()
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("% x", r)

		//r := make([]byte, md.maxIn)
		//_, err = md.in.Read(r)
		//if err != nil {
		//	log.Fatal(err)
		//}
		//log.Printf("% x", r)

		iv = crypted[len(crypted)-8:]
		offset += chunkSize
		packetCount++
	}

	// packets == encrypt wav data (per frame?) -> datakey, iv, encrypted(data)
	// totalbytes = wireformat (2048) * frames + (packets * 24)
	// send query:  1800 080046 f0030103 28 ff 000100 1001 ffff 00 ...
	// key, iv, data in packets -> md.out: 'len data?' + key + iv + data
	// read reply and des decrypt + get track name / number

	// ^^^
	// netmd_prepare_packets (calc frame length packets)
	// netmd_secure_send_track (session key track details

	// netmd_secure_commit_track
	// netmd_secure_session_key_forget

	md.LeaveSecureSession()
	md.Release()
}

func (md *NetMD) CommitTrack(trk int, sessionKey []byte) error {
	auth, err := DESEncrypt([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, sessionKey)
	if err != nil {
		return err
	}
	s := []byte{0x00, 0x18, 0x00, 0x08, 0x00, 0x46, 0xf0, 0x03, 0x01, 0x03, 0x48, 0xff, 0x00, 0x10, 0x01}
	s = append(s, intToHex16(int16(trk))...)
	s = append(s, auth...)
	_, err = md.call(s)
	if err != nil {
		return err
	}
	return nil
}

func (md *NetMD) SendKeyData(ekb *EKB) error {
	if len(ekb.Signature) != 24 {
		return errors.New("signature needs to be 24")
	}
	if len(ekb.Chain) != 32 {
		return errors.New("chain needs to be 2 * 16 (32)")
	}

	size := byte(16 + 32 + 24)

	s := []byte{0x00, 0x18, 0x00, 0x08, 0x00, 0x46, 0xf0, 0x03, 0x01, 0x03, 0x12, 0xff, 0x00, size & 0xff, 0x00, 0x00, 0x00, size & 0xff, 0x00, 0x00, 0x00, byte(len(ekb.Chain)/16) & 0xff, 0x00, 0x00, 0x00, byte(ekb.Depth) & 0xff}
	s = append(s, ekb.Id...)
	s = append(s, 0x00, 0x00, 0x00, 0x00)
	s = append(s, ekb.Chain...)
	s = append(s, ekb.Signature...)

	md.call(s)

	return nil
}

func (md *NetMD) SessionKeyExchange(nonce *Nonce) error {
	s := []byte{0x00, 0x18, 0x00, 0x08, 0x00, 0x46, 0xf0, 0x03, 0x01, 0x03, 0x20, 0xff, 0x00, 0x00, 0x00}
	s = append(s, nonce.Host...)
	r, err := md.call(s)
	if err != nil {
		return err
	}
	nonce.Dev = r[15:]
	return nil
}

func (md *NetMD) RequestDownload(ekb *EKB, sessionKey []byte) error {
	if len(ekb.ContentId) != 20 {
		return errors.New("supplied contentId length wrong")
	}
	if len(ekb.Kek) != 8 {
		return errors.New("supplied kek length wrong")
	}
	if len(sessionKey) != 8 {
		return errors.New("supplied sessionKey length wrong")
	}
	blk, err := des.NewCipher(sessionKey)
	if err != nil {
		return err
	}

	d := []byte{0x01, 0x01, 0x01, 0x01}
	d = append(d, ekb.ContentId...)
	d = append(d, ekb.Kek...)

	blkMode := cipher.NewCBCEncrypter(blk, ekb.IV)
	crypted := make([]byte, len(d))
	blkMode.CryptBlocks(crypted, d)

	s := []byte{0x00, 0x18, 0x00, 0x08, 0x00, 0x46, 0xf0, 0x03, 0x01, 0x03, 0x22, 0xff, 0x00, 0x00}
	s = append(s, crypted...)

	_, err = md.call(s)

	if err != nil {
		return err
	}

	return nil
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

func (md *NetMD) ForgetSecureKey() error {
	_, err := md.call([]byte{0x00, 0x18, 0x00, 0x08, 0x00, 0x46, 0xf0, 0x03, 0x01, 0x03, 0x21, 0xff, 0x00, 0x00, 0x00})
	if err != nil {
		return err
	}
	return nil
}

func (md *NetMD) LeaveSecureSession() error {
	_, err := md.call([]byte{0x00, 0x18, 0x00, 0x08, 0x00, 0x46, 0xf0, 0x03, 0x01, 0x03, 0x81, 0xff})
	if err != nil {
		return err
	}
	return nil
}

func (md *NetMD) EnterSecureSession() error {
	_, err := md.call([]byte{0x00, 0x18, 0x00, 0x08, 0x00, 0x46, 0xf0, 0x03, 0x01, 0x03, 0x80, 0xff})
	if err != nil {
		return err
	}
	return nil
}

func (md *NetMD) NewTrackProtection(i int16) error {
	// 0 - enabled
	// 1 - disabled
	s := []byte{0x00, 0x18, 0x00, 0x08, 0x00, 0x46, 0xf0, 0x03, 0x01, 0x03, 0x2b, 0xff}
	s = append(s, intToHex16(i)...)
	_, err := md.call(s)
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
	b, err := md.read()
	if err != nil {
		return nil, err
	}
	return b, nil
}

func (md *NetMD) read() ([]byte, error) {
	for tries := 0; tries < 4; tries++ {
		if h := md.poll(); h != -1 {
			buf := make([]byte, h)
			if _, err := md.dev.Control(gousb.ControlIn|gousb.ControlVendor|gousb.ControlInterface, 0x81, 0, 0, buf); err != nil {
				return nil, err
			}
			if md.debug {
				if buf[0] == 0x0a {
					return nil, errors.New("md.call got rejected")
				} else if buf[0] == 0x09 {
					log.Printf("md.call accepted -> % x", buf)
				}
			}
			return buf, nil
		}
		time.Sleep(time.Millisecond * 100)
	}
	return nil, errors.New("poll failed")
}

func (md *NetMD) poll() int {
	buf := make([]byte, 4)
	md.dev.Control(gousb.ControlIn|gousb.ControlVendor|gousb.ControlInterface, 0x01, 0, 0, buf)
	//log.Printf("raw-poll: % x", buf)
	if buf[0] == 0x01 && buf[1] == 0x81 {
		return int(buf[2])
	}
	return -1
}
