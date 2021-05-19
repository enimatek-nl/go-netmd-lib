package gomd

import (
	"crypto/cipher"
	"crypto/des"
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

func (md *NetMD) NewTrack(title string, fileName string, wf WireFormat, df DiscFormat) (trk *Track, err error) {
	trk = &Track{
		Title:      title,
		Format:     wf,
		DiscFormat: df,
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

	// some housekeeping on pcm wav data
	if trk.Format == WfPCM {
		// search for wav 'data' header
		c := 0
		s := audioData[c : c+4]
		for string(s) != "data" {
			c += 1
			s = audioData[c : c+4]
		}
		audioData = audioData[c+8:] // cut header & byte-swap the audio data (need source on 'why the swap?')
		for i := 0; i < len(audioData); i += 2 {
			first := audioData[i]
			audioData[i] = audioData[i+1]
			audioData[i+1] = first
		}
	}

	// add padding when data length does not fit the frame size
	if len(audioData)%FrameSize[trk.Format] != 0 {
		trk.Padding = FrameSize[trk.Format] - (len(audioData) % FrameSize[trk.Format])
		audioData = append(audioData, make([]byte, trk.Padding)...)
	}

	trk.Frames = len(audioData) / FrameSize[wf]

	cipherBlock, err := des.NewCipher(trk.key)
	if err != nil {
		return
	}

	trk.position = 0
	iv := md.ekb.iv // first iv doesn't matter

	for trk.position < len(audioData) {

		chunkSize := 0x00100000
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
