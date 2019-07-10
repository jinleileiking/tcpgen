package tcpgen

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func TestMain(t *testing.T) {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	data := []byte{0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0x14, 0x00, 0x00, 0x00, 0x00}

	var b bytes.Buffer

	// if w, err := NewWriter(os.Stdout); err != nil {
	if w, err := NewWriter(&b); err != nil {
		panic(err.Error())
	} else {
		if err := w.writeTCP(data); err != nil {
			panic(err)
		}

		tmpfile, err := ioutil.TempFile("", "TestPcap")
		if err != nil {
			panic(err)
		}

		// defer os.Remove(tmpfile.Name()) // clean up

		if _, err := tmpfile.Write(b.Bytes()); err != nil {
			panic(err)
		}

		spew.Dump(tmpfile.Name())
		if handle, err := pcap.OpenOffline(tmpfile.Name()); err != nil {
			panic(err)
		} else {
			defer handle.Close()

			// Loop through packets in file
			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
			for packet := range packetSource.Packets() {
				fmt.Println(packet)
			}

		}

		if err := tmpfile.Close(); err != nil {
			panic(err)
		}
	}

}

func TestTCPGen(t *testing.T) {
	data := []byte{0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0x14, 0x00, 0x00, 0x00, 0x00}

	var b bytes.Buffer
	var err error
	var w *Writer

	if w, err = NewWriter(&b); err != nil {
		panic(err.Error())
	}

	spew.Dump(w.genTCPPayload(data))

}
