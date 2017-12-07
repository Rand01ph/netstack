package rawfile

import (
	"github.com/FlowerWrong/netstack/tcpip"
	"github.com/FlowerWrong/water"
	"log"
)

// 兼容各个操作系统的tun设备
func Read(ifce *water.Interface, b []byte) (int, *tcpip.Error) {
	for {
		n, err := ifce.Read(b)
		if err != nil {
			log.Fatal(err)
			return 0, &tcpip.Error{}
		}
		return n, nil
	}
}
