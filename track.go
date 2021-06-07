package netmd

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"errors"
	"log"
	"os"
)

type Track struct {
	Title      string
	Format     WireFormat
	DiscFormat DiscFormat
	Frames     int
	Padding    int
	Packets    []*Packet
	position   int
	key        []byte
}

type Packet struct {
	first bool
	data  []byte
}

type WireFormat byte

type DiscFormat int

const (
	WfPCM      WireFormat = 0x00
	WfLP2      WireFormat = 0x94
	WfLP4      WireFormat = 0xa8
	DfLP4      DiscFormat = 0
	DfLP2      DiscFormat = 2
	DfMonoSP   DiscFormat = 4
	DfStereoSP DiscFormat = 6
)

var (
	FrameSize = map[WireFormat]int{
		WfPCM: 2048,
		WfLP2: 192,
		WfLP4: 96,
	}
)

func (trk *Track) TotalBytes() int {
	return (trk.Frames * FrameSize[trk.Format]) + 24
}

func (md *NetMD) NewTrack(title string, fileName string) (trk *Track, err error) {
	trk = &Track{
		Format:     WfPCM,
		DiscFormat: DfStereoSP,
		Title:      title,
		key:        md.ekb.CreateKey(),
	}

	file, err := os.Open(fileName)
	defer file.Close()
	if err != nil {
		return
	}
	stat, err := file.Stat()
	if err != nil {
		return
	}
	audioData := make([]byte, stat.Size())
	_, err = file.Read(audioData)
	if err != nil {
		return
	}

	if !bytes.Equal(audioData[0:4], []byte("RIFF")) {
		return nil, errors.New("wav: riff header not found")
	}
	size := int64(audioData[4]) | int64(audioData[5])<<8 | int64(audioData[6])<<16 | int64(audioData[7])<<24
	if size < 16 {
		return nil, errors.New("wav: header size too small < 16")
	}

	format := int(audioData[20]) | int(audioData[21])<<8 // 1 = linear PCM
	sampleRate := int64(audioData[24]) | int64(audioData[25])<<8 | int64(audioData[26])<<16 | int64(audioData[27])<<24
	bitsPerSample := int(audioData[34]) | int(audioData[35])<<8
	channelNum := int(audioData[22]) | int(audioData[23])<<8

	switch format {
	case 624:
		bitsPerSample = int(hexToInt16LE(audioData[32:34]))
		if bitsPerSample == 384 {
			trk.Format = WfLP2
			trk.DiscFormat = DfLP2
		} else {
			return nil, errors.New("atrac3: block size not supported")
		}
	case 1:
		if sampleRate != 44100 || bitsPerSample != 16 {
			return nil, errors.New("pcm: sample rate must be 44100 @ 16 bits")
		}
		if channelNum != 1 {
			trk.DiscFormat = DfMonoSP
		}
	default:
		return nil, errors.New("wav: must be linear pcm (1) or atrac3 (624)")
	}

	// search for wav 'data' header
	max := len(audioData) - 4
	c := 0
	s := audioData[c : c+4]
	for string(s) != "data" {
		c += 1
		if c >= max {
			break
		}
		s = audioData[c : c+4]
	}
	if string(s) != "data" {
		return nil, errors.New("corrupt wav container")
	}
	audioData = audioData[c+8:] // cut header

	// filter metadata if available
	max = len(audioData) - 4
	inf := c
	s = audioData[inf : inf+4]
	for string(s) != "LIST" {
		inf += 1
		if inf >= max {
			break
		}
		s = audioData[inf : inf+4]
	}
	if string(s) == "LIST" {
		if md.debug {
			log.Printf("!! found leading metadata starting @ %d - cutting.", inf)
		}
		audioData = audioData[:inf-1]
	}

	switch trk.Format {
	case WfPCM:
		// byte-swap the little-endian audio data, NetMD expects big-endian
		for i := 0; i < len(audioData); i += 2 {
			first := audioData[i]
			audioData[i] = audioData[i+1]
			audioData[i+1] = first
		}
	case WfLP2:
		break
	case WfLP4:
		return nil, errors.New("WireFormat LP4 is currently not supported")
	}

	// add padding when data length does not fit the frame size
	if len(audioData)%FrameSize[trk.Format] != 0 {
		trk.Padding = FrameSize[trk.Format] - (len(audioData) % FrameSize[trk.Format])
		audioData = append(audioData, make([]byte, trk.Padding)...)
	}

	trk.Frames = len(audioData) / FrameSize[trk.Format]

	cipherBlock, err := des.NewCipher(trk.key)
	if err != nil {
		return
	}

	trk.position = 0
	iv := md.ekb.iv // first iv doesn't matter

	for trk.position < len(audioData) {

		chunkSize := 0x80000 //0x00100000
		if trk.position == 0 {
			chunkSize -= 24
		}

		// the last (or only) packet ?
		if (len(audioData) - trk.position) < chunkSize {
			chunkSize = len(audioData) - trk.position // resize
		}

		packet := &Packet{
			first: trk.position == 0,
			data:  make([]byte, chunkSize),
		}

		encryptor := cipher.NewCBCEncrypter(cipherBlock, iv)
		encryptor.CryptBlocks(packet.data, audioData[trk.position:trk.position+chunkSize])

		iv = packet.data[chunkSize-8:]
		trk.position += chunkSize
		trk.Packets = append(trk.Packets, packet)
	}

	return
}
