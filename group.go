package netmd

import (
	"fmt"
	"strconv"
	"strings"
)

type Root struct {
	Title  string
	Groups []*Group
}

type Group struct {
	Title string
	Start int
	End   int
}

func NewRoot(raw string) (fs *Root) {
	if strings.HasSuffix(raw, "//") {
		parts := strings.Split(raw, "//")
		title := ""
		var folders []*Group
		for i := 0; i < len(parts); i++ {
			if i == 0 && strings.HasPrefix(parts[i], "0;") {
				title = parts[i][2:]
			} else {
				if s := strings.Index(parts[i], ";"); s != -1 {
					folder := &Group{
						Title: parts[i][s+1:],
					}
					fromTo := strings.Split(parts[i][0:s], "-")
					folder.Start, _ = strconv.Atoi(fromTo[0])
					folder.End, _ = strconv.Atoi(fromTo[1])
					folders = append(folders, folder)
				}
			}
		}
		fs = &Root{
			Title:  title,
			Groups: folders,
		}
	} else {
		fs = &Root{
			Title: raw,
		}
	}
	return
}

func (fs *Root) ToString() string {
	t := "0;"
	t += fs.Title
	t += "//"
	for i := 0; i < len(fs.Groups); i++ {
		t += fmt.Sprintf("%d", fs.Groups[i].Start)
		t += "-"
		t += fmt.Sprintf("%d", fs.Groups[i].End)
		t += ";"
		t += fs.Groups[i].Title
		t += "//"
	}
	return t
}

func (fs *Root) AddGroup(title string, start, end int) *Group {
	grp := &Group{
		Title: title,
		Start: start,
		End:   end,
	}
	fs.Groups = append(fs.Groups, grp)
	return grp
}

// SearchGroup will return the group of the trk number starting from 0 it belongs to or nil if none matched.
// the Group will contain non-zero based indexes of the tracks (0->1)
func (fs *Root) SearchGroup(trk int) *Group {
	for _, t := range fs.Groups {
		if trk+1 >= t.Start && trk+1 <= t.End {
			return t
		}
	}
	return nil
}
