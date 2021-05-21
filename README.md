# go-netmd library

This is a study and re-implementation library of the [linux-minidisc](https://github.com/vuori/linux-minidisc) and the [netmd-js](https://github.com/cybercase/netmd-js/) project in to go language.

I tried to simplify most code in a 'go' manner so understanding the NetMD protocol will be a bit easier for the next person who will try and do the same :-) 

## usage

`go get github.com/enimatek-nl/go-netmd-lib`

## example
In this example we send a stereo pcm file to the NetMD device concurrent.
```go
md, err := netmd.NewNetMD(0, false)
if err != nil {
    log.Fatal(err)
}
defer md.Close()

track, err := md.NewTrack("My Song", "song.wav", netmd.WfPCM, netmd.DfStereoSP)
if err != nil {
    log.Fatal(err)
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

## todo
The library has only been tested with my Sony NH600.

Some functions (sending LP2/LP4 and title/group/parsing) are not implemented yet.
