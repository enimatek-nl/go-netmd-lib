# go-netmd library

This is a study and re-implementation library of the [linux-minidisc](https://github.com/vuori/linux-minidisc) and the [netmd-js](https://github.com/cybercase/netmd-js/) project in to go language.

I tried to simplify most code in a 'go' manner so understanding the NetMD protocol will be a bit easier for the next person who will try and do the same :-) 

## usage

`go get github.com/enimatek-nl/go-netmd-lib`

## example
In this example we send a wav file to the NetMD device and give the new track a name.
```go
md, err := gonetmd.NewNetMD(0, true)
if err != nil {
    log.Fatal(err)
}
defer md.Close()

track, err := md.NewTrack("My Song", "song.wav", gonetmd.WfPCM, gonetmd.DfStereoSP)
if err != nil {
    log.Fatal(err)
}

err = md.Send(track)
if err != nil {
    log.Fatal(err)
}

```

## todo
The library has only been tested with my Sony NH600.

Some functions (sending LP2/LP4 and title/group/parsing) are not implemented yet.