// net.go: red local, ping sweep concurrente y tabla ARP.
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

func myIP() string {
	conn, err := net.DialTimeout("udp", "8.8.8.8:80", 3*time.Second)
	if err != nil {
		return ""
	}
	defer conn.Close()
	if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		return addr.IP.String()
	}
	return ""
}

func gatewayOf(myip string) string {
	if runtime.GOOS == "windows" {
		out, err := exec.Command("powershell", "-NoProfile", "-Command",
			"(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1).NextHop").Output()
		if err == nil {
			if gw := strings.Fields(string(out)); len(gw) > 0 && net.ParseIP(gw[0]) != nil {
				return gw[0]
			}
		}
	}
	if parts := strings.Split(myip, "."); len(parts) == 4 {
		return strings.Join(parts[:3], ".") + ".1"
	}
	return "?"
}

func cmdMyNet(args []string) {
	fs := flag.NewFlagSet("mynet", flag.ExitOnError)
	fs.Parse(args)
	ip := myIP()
	if ip == "" {
		emitJSON(map[string]string{"error": "No se pudo detectar tu IP"})
		os.Exit(1)
	}
	_, ipnet, err := net.ParseCIDR(ip + "/24")
	if err != nil {
		emitJSON(map[string]string{"error": err.Error()})
		os.Exit(1)
	}
	ones, _ := ipnet.Mask.Size()
	emitJSON(map[string]any{
		"ip": ip, "red": ipnet.String(), "gateway": gatewayOf(ip),
		"prefix": ones, "total_hosts": (1 << (32 - ones)) - 2,
	})
}

func pingOne(ip string, timeoutMs int) bool {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("ping", "-n", "1", "-w", strconv.Itoa(timeoutMs), ip)
	} else {
		cmd = exec.Command("ping", "-c", "1", "-W", strconv.Itoa(max(timeoutMs/1000, 1)), ip)
	}
	return cmd.Run() == nil
}

func cmdSweep(args []string) {
	fs := flag.NewFlagSet("sweep", flag.ExitOnError)
	network := fs.String("net", "", "red CIDR (ej. 192.168.12.0/24)")
	timeout := fs.Int("timeout", 400, "ms por host")
	workers := fs.Int("workers", 64, "pings simultáneos")
	fs.Parse(args)
	if *network == "" {
		fmt.Fprintln(os.Stderr, "uso: lanscan-go sweep --net 192.168.12.0/24")
		os.Exit(2)
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
	// quita red y broadcast
	if len(hosts) >= 2 {
		hosts = hosts[1 : len(hosts)-1]
	}
	jobs := make(chan string)
	var mu sync.Mutex
	var alive []string
	var wg sync.WaitGroup
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for h := range jobs {
				if pingOne(h, *timeout) {
					mu.Lock()
					alive = append(alive, h)
					mu.Unlock()
				}
			}
		}()
	}
	go func() {
		for _, h := range hosts {
			jobs <- h
		}
		close(jobs)
	}()
	wg.Wait()
	sort.Slice(alive, func(i, j int) bool { return ipLess(alive[i], alive[j]) })
	emitJSON(map[string]any{"red": *network, "vivos": alive, "total": len(alive)})
}

func incIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

func ipLess(a, b string) bool {
	pa, pb := net.ParseIP(a).To4(), net.ParseIP(b).To4()
	if pa == nil || pb == nil {
		return a < b
	}
	for i := 0; i < 4; i++ {
		if pa[i] != pb[i] {
			return pa[i] < pb[i]
		}
	}
	return false
}

func arpTable() map[string]string {
	t := map[string]string{}
	var out []byte
	var err error
	if runtime.GOOS == "windows" {
		out, err = exec.Command("arp", "-a").Output()
	} else {
		out, err = exec.Command("ip", "neigh").Output()
	}
	if err != nil {
		return t
	}
	reWin := regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})`)
	reLin := regexp.MustCompile(`^(\S+).*?lladdr\s+([0-9a-fA-F:]{17})`)
	for _, line := range strings.Split(string(out), "\n") {
		if runtime.GOOS == "windows" {
			if m := reWin.FindStringSubmatch(line); m != nil {
				t[m[1]] = strings.ToLower(strings.ReplaceAll(m[2], "-", ":"))
			}
		} else if m := reLin.FindStringSubmatch(line); m != nil {
			t[m[1]] = strings.ToLower(m[2])
		}
	}
	return t
}

func cmdARP(args []string) {
	fs := flag.NewFlagSet("arp", flag.ExitOnError)
	fs.Parse(args)
	emitJSON(arpTable())
}
