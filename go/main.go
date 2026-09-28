// lanscan-go: gemelo Go del escáner de red local. Solo tu LAN, educativo.
//
//	Uso:
//	  lanscan-go mynet
//	  lanscan-go sweep --net 192.168.12.0/24
//	  lanscan-go arp
//	  lanscan-go vendor --mac 18:0c:7a:ea:b1:e1
//	  lanscan-go report --net 192.168.12.0/24
//	  lanscan-go menu
package main

import (
	"encoding/json"
	"fmt"
	"os"
)

func emitJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	enc.Encode(v)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "uso: lanscan-go <mynet|sweep|arp|vendor|report|menu|version>")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "mynet":
		cmdMyNet(os.Args[2:])
	case "sweep":
		cmdSweep(os.Args[2:])
	case "arp":
		cmdARP(os.Args[2:])
	case "vendor":
		cmdVendor(os.Args[2:])
	case "report":
		cmdReport(os.Args[2:])
	case "menu":
		runMenu()
	case "version":
		fmt.Println("lanscan-go v1.1.0")
	default:
		fmt.Fprintln(os.Stderr, "subcomando desconocido:", os.Args[1])
		os.Exit(2)
	}
}
