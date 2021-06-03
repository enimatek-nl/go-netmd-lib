# go-netmd library

This is a study and re-implementation library of the [linux-minidisc](https://github.com/vuori/linux-minidisc) and the [netmd-js](https://github.com/cybercase/netmd-js/) project in to go language.

I tried to simplify most code in a 'go' manner so understanding the NetMD protocol will be a bit easier for the next person who will try and do the same :-) 

## Usage

`go get github.com/enimatek-nl/go-netmd-lib`

## Example
In this example we send a stereo pcm file to the NetMD device concurrently.
```go
md, err := netmd.NewNetMD(0, false)
if err != nil {
    log.Fatal(err)
}
defer md.Close()

track, err := md.NewTrack("My Song", "song.wav")
if err != nil {
    log.Fatal(err)
}

switch track.Format {
case netmd.WfPCM:
    log.Println("PCM detected")
case netmd.WfLP2:
    log.Println("LP2 detected")
}

c := make(chan netmd.Transfer)
go md.Send(track, c)

for{
    res, ok := <-c
    if !ok {
        break
    }
    if res.Error != nil {
        log.Fatal(res.Error)
    }
    switch res.Type {
    case netmd.TtSend:
        log.Printf("Transferred %d of %d bytes", res.Transferred, track.TotalBytes())
    case netmd.TtTrack:
        log.Printf("Created a new track # %d ", res.Track)
    }
}
```

## TODO
The library has only been tested with my Sony MZ-NH600 and the Sharp IM-DR420.

Some functions (eg. groups parsing of titles) are not implemented yet.
