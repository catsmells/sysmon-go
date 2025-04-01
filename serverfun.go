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
	"github.com/shirou/gopsutil/process"
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
	Interface  string `json:"interface"`
	BytesSent  uint64 `json:"bytes_sent"`
	BytesRecv  uint64 `json:"bytes_recv"`
}
type ProcessInfo struct {
	PID  int32  `json:"pid"`
	Name string `json:"name"`
	CPU  string `json:"cpu"`
	Mem  string `json:"mem"`
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
	netStats, err := net.IOCounters(true)
	if err != nil {
		return nil, err
	}
	var networkData []NetworkStats
	for _, net := range netStats {
		networkData = append(networkData, NetworkStats{
			Interface: net.Name,
			BytesSent: net.BytesSent,
			BytesRecv: net.BytesRecv,
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
		Network:  networkData,
	}
	return sysInfo, nil
}
func getProcessList() ([]ProcessInfo, error) {
	processes, err := process.Processes()
	if err != nil {
		return nil, err
	}
	var procList []ProcessInfo
	for _, p := range processes {
		name, _ := p.Name()
		cpuPercent, _ := p.CPUPercent()
		memInfo, _ := p.MemoryInfo()
		procList = append(procList, ProcessInfo{
			PID:  p.Pid,
			Name: name,
			CPU:  fmt.Sprintf("%.2f%%", cpuPercent),
			Mem:  fmt.Sprintf("%.2f MB", float64(memInfo.RSS)/1024/1024),
		})
		if len(procList) >= 10 {
			break
		}
	}
	return procList, nil
}
func apiHandler(w http.ResponseWriter, r *http.Request) {
	sysInfo, err := getSystemInfo()
	if err != nil {
		http.Error(w, "Error retrieving system info.", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(sysInfo)
}
func processHandler(w http.ResponseWriter, r *http.Request) {
	procList, err := getProcessList()
	if err != nil {
		http.Error(w, "Error retrieving process list.", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(procList)
}
func handler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "index.html")
}
func main() {
	http.HandleFunc("/api/systeminfo", apiHandler)
	http.HandleFunc("/api/processes", processHandler)
	http.HandleFunc("/", handler)
	log.Println("Server started at http://localhost:8080.")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
