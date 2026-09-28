// report.go: escaneo completo + reporte HTML/TXT/CSV en reportes/.
package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"html"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type device struct {
	IP      string `json:"ip"`
	MAC     string `json:"mac"`
	Vendor  string `json:"vendor"`
	Nombre  string `json:"nombre"`
	Puertos []int  `json:"puertos"`
}

func quickPorts(ip string) []int {
	var out []int
	var mu = make(chan int, 8)
	done := make(chan bool)
	go func() {
		for _, p := range []int{80, 443, 22, 8080} {
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, p), 600*time.Millisecond)
			if err == nil {
				conn.Close()
				mu <- p
			}
		}
		done <- true
	}()
	go func() {
		<-done
		close(mu)
	}()
	for p := range mu {
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}

func reverseName(ip string) string {
	if names, err := net.LookupAddr(ip); err == nil && len(names) > 0 {
		return strings.TrimSuffix(names[0], ".")
	}
	return "-"
}

func cmdReport(args []string) {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	network := fs.String("net", "", "red CIDR")
	outdir := fs.String("outdir", "", "carpeta salida")
	fs.Parse(args)
	myip := myIP()
	if *network == "" {
		if myip == "" {
			fmt.Fprintln(os.Stderr, "no se detectó red; usa --net 192.168.12.0/24")
			os.Exit(2)
		}
		*network = strings.Join(append(strings.Split(myip, ".")[:3], "0"), ".") + "/24"
	}
	_, ipnet, err := net.ParseCIDR(*network)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Red no válida:", err)
		os.Exit(2)
	}
	var hosts []string
	for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
		dup := make(net.IP, len(ip))
		copy(dup, ip)
		hosts = append(hosts, dup.String())
	}
	if len(hosts) >= 2 {
		hosts = hosts[1 : len(hosts)-1]
	}
	// sweep rápido
	var mu sync.Mutex
	var alive []string
	var wg sync.WaitGroup
	sem := make(chan struct{}, 64)
	for _, h := range hosts {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if pingOne(h, 400) {
				mu.Lock()
				alive = append(alive, h)
				mu.Unlock()
			}
		}(h)
	}
	wg.Wait()
	arp := arpTable()
	var devs []device
	for _, ip := range alive {
		mac := arp[ip]
		if mac == "" {
			mac = "-"
		}
		vendor := "-"
		if mac != "-" {
			vendor = vendorOf(mac)
		}
		devs = append(devs, device{ip, mac, vendor, reverseName(ip), quickPorts(ip)})
	}
	sort.Slice(devs, func(i, j int) bool { return ipLess(devs[i].IP, devs[j].IP) })

	dir := *outdir
	if dir == "" {
		if exe, err := os.Executable(); err == nil {
			dir = filepath.Join(filepath.Dir(exe), "..", "reportes")
		} else {
			dir = "reportes"
		}
	}
	os.MkdirAll(dir, 0755)
	ts := time.Now().Format("20060102_150405")
	fecha := time.Now().Format("2006-01-02 15:04:05")
	red := strings.ReplaceAll(*network, "/", "-")
	tag := red + "_" + ts

	var tb strings.Builder
	tb.WriteString("============================================================\n SCAN RED LOCAL (lanscan-go)\n============================================================\n")
	fmt.Fprintf(&tb, "Fecha: %s\nRed: %s | Tu IP: %s | Equipos: %d\n\n", fecha, *network, myip, len(devs))
	for _, d := range devs {
		ports := "-"
		if len(d.Puertos) > 0 {
			var ps []string
			for _, p := range d.Puertos {
				ps = append(ps, fmt.Sprintf("%d", p))
			}
			ports = strings.Join(ps, ",")
		}
		fmt.Fprintf(&tb, "%-16s %-18s puertos:%-8s %-26s %s\n", d.IP, d.MAC, ports, d.Vendor, d.Nombre)
	}
	txt := filepath.Join(dir, "scan_"+tag+".txt")
	os.WriteFile(txt, []byte(tb.String()), 0644)

	csvp := filepath.Join(dir, "scan_"+tag+".csv")
	cf, _ := os.Create(csvp)
	cw := csv.NewWriter(cf)
	cw.Write([]string{"ip", "mac", "puertos", "fabricante", "nombre"})
	for _, d := range devs {
		var ps []string
		for _, p := range d.Puertos {
			ps = append(ps, fmt.Sprintf("%d", p))
		}
		cw.Write([]string{d.IP, d.MAC, strings.Join(ps, ";"), d.Vendor, d.Nombre})
	}
	cw.Flush()
	cf.Close()

	var rows strings.Builder
	for _, d := range devs {
		var ps []string
		for _, p := range d.Puertos {
			ps = append(ps, fmt.Sprintf("%d", p))
		}
		ports := strings.Join(ps, ",")
		if ports == "" {
			ports = "-"
		}
		fmt.Fprintf(&rows, "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>",
			html.EscapeString(d.IP), html.EscapeString(d.MAC), html.EscapeString(ports),
			html.EscapeString(d.Vendor), html.EscapeString(d.Nombre))
	}
	page := `<!DOCTYPE html><html lang="es"><head><meta charset="utf-8">
<title>Scan ` + html.EscapeString(*network) + `</title>
<style>body{font-family:Segoe UI,Arial;background:#0a0a14;color:#eee;margin:0}
header{padding:28px;text-align:center;background:linear-gradient(135deg,#00ffea,#ff00ff)}
h1{margin:0;color:#000}table{width:94%;margin:20px auto;border-collapse:collapse;background:#14142b;font-size:.9em}
th,td{padding:8px 10px;border-bottom:1px solid #ffffff18;text-align:left}th{color:#00ffea}</style></head>
<body><header><h1>SCAN RED LOCAL (GO)</h1><p>` + html.EscapeString(fecha) + ` · ` + html.EscapeString(*network) + ` · ` + fmt.Sprintf("%d", len(devs)) + ` equipos</p></header>
<table><tr><th>IP</th><th>MAC</th><th>Puertos</th><th>Fabricante</th><th>Nombre</th></tr>` + rows.String() + `</table></body></html>`
	htm := filepath.Join(dir, "scan_"+tag+".html")
	os.WriteFile(htm, []byte(page), 0644)
	updateIndex(dir)
	emitJSON(map[string]string{"html": htm, "txt": txt, "csv": csvp})
}

func updateIndex(dir string) {
	entries, _ := os.ReadDir(dir)
	var items []string
	for _, e := range entries {
		n := e.Name()
		if strings.HasPrefix(n, "scan_") && strings.HasSuffix(n, ".html") {
			items = append(items, `<li><a href="`+html.EscapeString(n)+`">`+html.EscapeString(n)+`</a></li>`)
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(items)))
	body := strings.Join(items, "")
	if body == "" {
		body = "<li>Sin escaneos.</li>"
	}
	page := `<!DOCTYPE html><html lang="es"><head><meta charset="utf-8"><title>Scans LAN</title>
<style>body{font-family:Segoe UI,Arial;background:#0a0a14;color:#eee;margin:0}
header{padding:26px;text-align:center;background:linear-gradient(135deg,#00ffea,#ff00ff)}
h1{margin:0;color:#000}ul{max-width:700px;margin:20px auto;list-style:none;padding:0}
li{background:#14142b;margin:8px;padding:12px;border-radius:10px}a{color:#00ffea}</style></head>
<body><header><h1>SCANS DE RED LOCAL</h1></header><ul>` + body + `</ul></body></html>`
	os.WriteFile(filepath.Join(dir, "index.html"), []byte(page), 0644)
}
