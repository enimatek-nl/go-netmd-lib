package gonetmd

import (
	"crypto/cipher"
	"crypto/des"
)

// acquire is part of SHARP NetMD protocols and probably do nothing on Sony devices
func (md *NetMD) acquire() error {
	_, err := md.call([]byte{0x00, 0xff, 0x01, 0x0c, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	if err != nil {
		return err
	}
	return nil
}

// release is part of the acquire lifecycle
func (md *NetMD) release() error {
	_, err := md.call([]byte{0x00, 0xff, 0x01, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	if err != nil {
		return err
	}
	return nil
}

func (md *NetMD) syncTOC() error {
	_, err := md.call([]byte{0x00, 0x18, 0x08, 0x10, 0x18, 0x02, 0x00, 0x00})
	if err != nil {
		return err
	}
	return nil
}

func (md *NetMD) cacheTOC() error {
	_, err := md.call([]byte{0x00, 0x18, 0x08, 0x10, 0x18, 0x02, 0x03, 0x00})
	if err != nil {
		return err
	}
	return nil
}

func (md *NetMD) forgetSecureKey() error {
	_, err := md.call([]byte{0x00, 0x18, 0x00, 0x08, 0x00, 0x46, 0xf0, 0x03, 0x01, 0x03, 0x21, 0xff, 0x00, 0x00, 0x00})
	if err != nil {
		return err
	}
	return nil
}

func (md *NetMD) enterSecureSession() error {
	_, err := md.call([]byte{0x00, 0x18, 0x00, 0x08, 0x00, 0x46, 0xf0, 0x03, 0x01, 0x03, 0x80, 0xff})
	if err != nil {
		return err
	}
	return nil
}

func (md *NetMD) leaveSecureSession() error {
	_, err := md.call([]byte{0x00, 0x18, 0x00, 0x08, 0x00, 0x46, 0xf0, 0x03, 0x01, 0x03, 0x81, 0xff})
	if err != nil {
		return err
	}
	return nil
}

func (md *NetMD) trackProtection(i int16) error {
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

func (md *NetMD) sendKeyData() error {
	size := byte(16 + 32 + 24)
	s := []byte{0x00, 0x18, 0x00, 0x08, 0x00, 0x46, 0xf0, 0x03, 0x01, 0x03, 0x12, 0xff, 0x00, size & 0xff, 0x00, 0x00, 0x00, size & 0xff, 0x00, 0x00, 0x00, byte(len(md.ekb.chain)/16) & 0xff, 0x00, 0x00, 0x00, byte(md.ekb.depth) & 0xff}
	s = append(s, intToHex32(int32(md.ekb.id))...)
	s = append(s, 0x00, 0x00, 0x00, 0x00)
	s = append(s, md.ekb.chain...)
	s = append(s, md.ekb.signature...)
	md.call(s)
	return nil
}

func (md *NetMD) sessionKeyExchange() error {
	s := []byte{0x00, 0x18, 0x00, 0x08, 0x00, 0x46, 0xf0, 0x03, 0x01, 0x03, 0x20, 0xff, 0x00, 0x00, 0x00}
	s = append(s, md.ekb.nonce.Host...)
	r, err := md.call(s)
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

	s := []byte{0x00, 0x18, 0x00, 0x08, 0x00, 0x46, 0xf0, 0x03, 0x01, 0x03, 0x22, 0xff, 0x00, 0x00}
	s = append(s, encKek...)

	_, err = md.call(s)
	if err != nil {
		return err
	}

	return nil
}

// initSecureSend will put the netmd into 'rec' mode and reads from the bulk in until the total bytes was reached, it will process the data based on the wire and disc format
func (md *NetMD) initSecureSend(format WireFormat, discFormat DiscFormat, frames, totalBytes int) error {
	d := []byte{0x00, 0x18, 0x00, 0x08, 0x00, 0x46, 0xf0, 0x03, 0x01, 0x03, 0x28, 0xff, 0x00, 0x01, 0x00, 0x10, 0x01, 0xff, 0xff, 0x00, byte(format) & 0xff, byte(discFormat) & 0xff}
	d = append(d, intToHex32(int32(frames))...)
	d = append(d, intToHex32(int32(totalBytes))...)
	_, err := md.call(d)
	if err != nil {
		return err
	}
	return nil
}

func (md *NetMD) commitTrack(trk int, sessionKey []byte) error {
	auth, err := DESEncrypt(ByteArr16, sessionKey)
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
