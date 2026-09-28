// menu.go: menú interactivo lanscan-go en español.
package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

const (
	nc   = "\033[38;2;0;255;234m"
	np   = "\033[38;2;255;0;255m"
	ng   = "\033[38;2;57;255;20m"
	ny   = "\033[38;2;255;255;0m"
	nv   = "\033[38;2;176;38;255m"
	dim  = "\033[2m"
	bold = "\033[1m"
	end  = "\033[0m"
)

var reader = bufio.NewReader(os.Stdin)

func ask(prompt string) string {
	fmt.Printf(" %s%s>%s %s:%s ", nc, bold, end, prompt, end)
	s, _ := reader.ReadString('\n')
	return strings.TrimSpace(s)
}

func runMenu() {
	fmt.Println()
	fmt.Println(nc + bold + "  Escáner de red local" + end + "  " + np + bold + "v1.1.0 (Go)" + end)
	fmt.Println("  Solo tu propia red. Fines educativos.\n")
	for {
		fmt.Printf(" %s%s+-- MENU --+%s\n", nv, bold, end)
		fmt.Printf("  %s[1]%s > Escanear (reporte)\n", nc, end)
		fmt.Printf("  %s[2]%s > Mi red\n", nc, end)
		fmt.Printf("  %s[0]%s < Salir\n", dim, end)
		switch ask("Elige") {
		case "0":
			fmt.Println("\n  Adiós.\n")
			return
		case "1":
			fmt.Println("  Escaneando tu red, espera...")
			cmdReport([]string{"--net", ""})
			fmt.Println("  Listo. Abre reportes/index.html")
		case "2":
			cmdMyNet([]string{})
		default:
			fmt.Println("  Opción no válida")
		}
		fmt.Print("  Enter para continuar...")
		reader.ReadString('\n')
	}
}
