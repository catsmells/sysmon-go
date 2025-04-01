package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"runtime"

	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/host"
	"github.com/shirou/gopsutil/mem"
	"github.com/shirou/gopsutil/net"
)

type SystemInfo struct {
	OS       string         `json:"os"`
	Arch     string         `json:"arch"`
	Hostname string         `json:"hostname"`
	Uptime   string         `json:"uptime"`
	CPU      string         `json:"cpu"`
	MemTotal string         `json:"mem_total"`
	MemUsed  string         `json:"mem_used"`
	MemFree  string         `json:"mem_free"`
	Network  []NetworkStats `json:"network"`
}

type NetworkStats struct {
	Name      string `json:"name"`
	BytesSent uint64 `json:"bytes_sent"`
	BytesRecv uint64 `json:"bytes_recv"`
}

func getSystemInfo() (*SystemInfo, error) {
	hostInfo, err := host.Info()
	if err != nil {
		return nil, err
	}

	cpuInfo, err := cpu.Info()
	if err != nil {
		return nil, err
	}

	memInfo, err := mem.VirtualMemory()
	if err != nil {
		return nil, err
	}

	netInfo, err := net.IOCounters(true)
	if err != nil {
		return nil, err
	}

	var networkStats []NetworkStats
	for _, iface := range netInfo {
		networkStats = append(networkStats, NetworkStats{
			Name:      iface.Name,
			BytesSent: iface.BytesSent,
			BytesRecv: iface.BytesRecv,
		})
	}

	sysInfo := &SystemInfo{
		OS:       hostInfo.OS,
		Arch:     runtime.GOARCH,
		Hostname: hostInfo.Hostname,
		Uptime:   fmt.Sprintf("%v hours", hostInfo.Uptime/3600),
		CPU:      cpuInfo[0].ModelName,
		MemTotal: fmt.Sprintf("%.2f GB", float64(memInfo.Total)/1024/1024/1024),
		MemUsed:  fmt.Sprintf("%.2f GB", float64(memInfo.Used)/1024/1024/1024),
		MemFree:  fmt.Sprintf("%.2f GB", float64(memInfo.Free)/1024/1024/1024),
		Network:  networkStats,
	}

	return sysInfo, nil
}

func systemInfoHandler(w http.ResponseWriter, r *http.Request) {
	info, err := getSystemInfo()
	if err != nil {
		http.Error(w, "Error fetching system info", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(info)
}

func main() {
	http.HandleFunc("/api/systeminfo", systemInfoHandler)

	fs := http.FileServer(http.Dir("./static"))
	http.Handle("/", fs)

	fmt.Println("Server is running on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
