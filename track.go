package netmd

import (
	"crypto/cipher"
	"crypto/des"
	"errors"
	"fmt"
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

	if string(audioData[0:4]) != "RIFF" {
		return nil, errors.New("not a valid wav container")
	}

	if audioData[20] == 0x70 && audioData[21] == 0x02 {
		bs := hexToInt16LE(audioData[32:34])
		if bs == 384 {
			trk.Format = WfLP2
			trk.DiscFormat = DfLP2
		} else {
			return nil, errors.New(fmt.Sprintf("ATRAC3 block size %d not supported", bs))
		}
	}

	// search for wav 'data' header
	c := 0
	s := audioData[c : c+4]
	for string(s) != "data" {
		c += 1
		s = audioData[c : c+4]
	}
	if string(s) != "data" {
		return nil, errors.New("corrupt wav container")
	}
	audioData = audioData[c+8:] // cut header

	switch trk.Format {
	case WfPCM:
		// byte-swap the audio data (need source on 'why the swap?')
		for i := 0; i < len(audioData); i += 2 {
			first := audioData[i]
			audioData[i] = audioData[i+1]
			audioData[i+1] = first
		}
	case WfLP2:
		break
	case WfLP4:
		return nil, errors.New("LP4 is currently not supported")
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
