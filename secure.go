package netmd

import (
	"crypto/cipher"
	"crypto/des"
)

func (md *NetMD) syncTOC() error {
	//_, err := md.securePoll([]byte{0x00, 0x18, 0x08, 0x10, 0x18, 0x02}, 0x00, []byte{0x00})
	_, err := md.submit(ControlAccepted, []byte{0x18, 0x08, 0x10, 0x18, 0x02, 0x00}, []byte{0x00})
	if err != nil {
		return err
	}
	return nil
}

func (md *NetMD) cacheTOC() error {
	_, err := md.submit(ControlAccepted, []byte{0x18, 0x08, 0x10, 0x18, 0x02, 0x03}, []byte{0x00})
	if err != nil {
		return err
	}
	return nil
}

func (md *NetMD) forgetSecureKey() error {
	_, err := md.submit(ControlAccepted, []byte{0x18, 0x00, 0x08, 0x00, 0x46, 0xf0, 0x03, 0x01, 0x03, 0x21}, []byte{0xff, 0x00, 0x00, 0x00})
	if err != nil {
		return err
	}
	return nil
}

func (md *NetMD) enterSecureSession() error {
	_, err := md.submit(ControlAccepted, []byte{0x18, 0x00, 0x08, 0x00, 0x46, 0xf0, 0x03, 0x01, 0x03, 0x80}, []byte{0xff})
	if err != nil {
		return err
	}
	return nil
}

func (md *NetMD) leaveSecureSession() error {
	_, err := md.submit(ControlAccepted, []byte{0x18, 0x00, 0x08, 0x00, 0x46, 0xf0, 0x03, 0x01, 0x03, 0x81}, []byte{0xff})
	if err != nil {
		return err
	}
	return nil
}

func (md *NetMD) trackProtection(i int16) error {
	// 0 - enabled
	// 1 - disabled
	s := []byte{0xff}
	s = append(s, intToHex16(i)...)
	_, err := md.submit(ControlAccepted, []byte{0x18, 0x00, 0x08, 0x00, 0x46, 0xf0, 0x03, 0x01, 0x03, 0x2b}, s)
	if err != nil {
		return err
	}
	return nil
}

func (md *NetMD) sendKeyData() error {
	size := byte(16 + 32 + 24)
	s := []byte{0xff, 0x00, size & 0xff, 0x00, 0x00, 0x00, size & 0xff, 0x00, 0x00, 0x00, byte(len(md.ekb.chain)/16) & 0xff, 0x00, 0x00, 0x00, byte(md.ekb.depth) & 0xff}
	s = append(s, intToHex32(int32(md.ekb.id))...)
	s = append(s, 0x00, 0x00, 0x00, 0x00)
	s = append(s, md.ekb.chain...)
	s = append(s, md.ekb.signature...)
	md.submit(ControlAccepted, []byte{0x18, 0x00, 0x08, 0x00, 0x46, 0xf0, 0x03, 0x01, 0x03, 0x12}, s)
	return nil
}

func (md *NetMD) sessionKeyExchange() error {
	s := []byte{0xff, 0x00, 0x00, 0x00}
	s = append(s, md.ekb.nonce.Host...)
	r, err := md.submit(ControlAccepted, []byte{0x18, 0x00, 0x08, 0x00, 0x46, 0xf0, 0x03, 0x01, 0x03, 0x20}, s)
	if err != nil {
		return err
	}
	md.ekb.nonce.Dev = r[15:]
	return nil
}

func (md *NetMD) kekExchange(sessionKey []byte) error {
	blk, err := des.NewCipher(sessionKey)
	if err != nil {
		return err
	}
	blkMode := cipher.NewCBCEncrypter(blk, md.ekb.iv)

	d := []byte{0x01, 0x01, 0x01, 0x01}
	d = append(d, md.ekb.contentId...)
	d = append(d, md.ekb.kek...)

	encKek := make([]byte, len(d))
	blkMode.CryptBlocks(encKek, d)

	s := []byte{0xff, 0x00, 0x00}
	s = append(s, encKek...)

	_, err = md.submit(ControlAccepted, []byte{0x18, 0x00, 0x08, 0x00, 0x46, 0xf0, 0x03, 0x01, 0x03, 0x22}, s)
	if err != nil {
		return err
	}

	return nil
}

// initSecureSend will put the netmd into 'rec' mode and reads from the bulk in until the total bytes was reached, it will process the data based on the wire and disc format
func (md *NetMD) startSecureSend(format WireFormat, discFormat DiscFormat, frames, totalBytes int) error {
	d := []byte{0xff, 0x00, 0x01, 0x00, 0x10, 0x01, 0xff, 0xff, 0x00, byte(format) & 0xff, byte(discFormat) & 0xff}
	d = append(d, intToHex32(int32(frames))...)
	d = append(d, intToHex32(int32(totalBytes))...)
	_, err := md.submit(ControlInterim, []byte{0x18, 0x00, 0x08, 0x00, 0x46, 0xf0, 0x03, 0x01, 0x03, 0x28}, d)
	if err != nil {
		return err
	}
	return nil
}

func (md *NetMD) finishSecureSend(c chan Transfer) ([]byte, error) {
	return md.receive(ControlAccepted, []byte{0x18, 0x00, 0x08, 0x00, 0x46, 0xf0, 0x03, 0x01, 0x03, 0x28}, c)
}

func (md *NetMD) commitTrack(trk int, sessionKey []byte) error {
	auth, err := DESEncrypt(ByteArr16[:8], sessionKey[:8])
	if err != nil {
		return err
	}
	s := []byte{0xff, 0x00, 0x10, 0x01}
	s = append(s, intToHex16(int16(trk))...)
	s = append(s, auth[:8]...)
	md.Wait()
	_, err = md.submit(ControlAccepted, []byte{0x18, 0x00, 0x08, 0x00, 0x46, 0xf0, 0x03, 0x01, 0x03, 0x48}, s)
	if err != nil {
		return err
	}
	md.Wait()
	return nil
}

// acquire is part of SHARP NetMD protocols and probably do nothing on Sony devices
func (md *NetMD) acquire() error {
	_, err := md.submit(ControlAccepted, []byte{0xff, 0x01}, []byte{0x0c, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	if err != nil {
		return err
	}
	return nil
}

// release is part of the acquire lifecycle
func (md *NetMD) release() error {
	_, err := md.submit(ControlAccepted, []byte{0xff, 0x01}, []byte{0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	if err != nil {
		return err
	}
	return nil
}
