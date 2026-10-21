package iptables

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"wallfacer-forwarder/internal/config"
	"wallfacer-forwarder/internal/database"
	"wallfacer-forwarder/internal/model"
)

type NicInfo struct {
	Interface string `json:"interface"`
	IP        string `json:"ip"`
}

func IsIPv4Address(host string) bool {
	ip := net.ParseIP(strings.TrimSpace(host))
	return ip != nil && ip.To4() != nil
}

func ResolveHostIPv4(host string) (string, error) {
	host = strings.TrimSpace(host)
	if IsIPv4Address(host) {
		return host, nil
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return "", fmt.Errorf("域名 %s 解析失败: %v", host, err)
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			return v4.String(), nil
		}
	}
	return "", fmt.Errorf("域名 %s 未解析到任何 IPv4 地址", host)
}

func GetLocalNicIPs() []NicInfo {
	var list []NicInfo
	seen := make(map[string]bool)

	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			if (iface.Flags&net.FlagUp) == 0 || (iface.Flags&net.FlagLoopback) != 0 {
				continue
			}
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			for _, addr := range addrs {
				var ip net.IP
				switch v := addr.(type) {
				case *net.IPNet:
					ip = v.IP
				case *net.IPAddr:
					ip = v.IP
				}
				if ip == nil || ip.IsLoopback() {
					continue
				}
				v4 := ip.To4()
				if v4 == nil {
					continue
				}
				ipStr := v4.String()
				if !strings.HasPrefix(ipStr, "127.") && !seen[ipStr] {
					seen[ipStr] = true
					list = append(list, NicInfo{Interface: iface.Name, IP: ipStr})
				}
			}
		}
	}
	return list
}

func GetLocalSnatIP(targetIP string) string {
	probe := "223.5.5.5"
	if targetIP != "" && IsIPv4Address(targetIP) {
		probe = targetIP
	}
	if conn, err := net.DialTimeout("udp4", probe+":80", 2*time.Second); err == nil {
		defer conn.Close()
		if udpAddr, ok := conn.LocalAddr().(*net.UDPAddr); ok && udpAddr.IP != nil {
			ipStr := udpAddr.IP.String()
			if !strings.HasPrefix(ipStr, "127.") {
				return ipStr
			}
		}
	}
	nics := GetLocalNicIPs()
	if len(nics) > 0 {
		return nics[0].IP
	}
	return "127.0.0.1"
}

// ==================== macOS / 跨平台原生 Goroutine 端口转发器 ====================

type ruleRelayCounter struct {
	upBytes   atomic.Int64
	downBytes atomic.Int64
}

type activeListener struct {
	spec       string
	tcpLn      net.Listener
	udpConn    net.PacketConn
	stopSignal chan struct{}
}

type Manager struct {
	mu              sync.Mutex
	preroutingChain string
	postroutingChain string
	forwardChain    string
	isLinux         bool
	isMacOS         bool
	iptablesBin     string
	effectiveDryRun bool

	ruleSpeeds        map[int][2]float64
	lastChainCounters map[int][2]int64
	lastSampleTime    time.Time
	lastHostNetBytes  [2]int64
	hasHostBaseline   bool
	HostUpSpeed       float64
	HostDownSpeed     float64
	HostUpBytes       int64
	HostDownBytes     int64

	relayCounters map[int]*ruleRelayCounter
	listeners     map[int]*activeListener
}

var Mgr = NewManager()

func NewManager() *Manager {
	prefix := config.Global.Iptables.ChainPrefix
	if prefix == "" {
		prefix = "IPT_FWD"
	}
	iptBin, _ := exec.LookPath("iptables")
	sysOS := runtime.GOOS
	isLinux := sysOS == "linux"
	isMac := sysOS == "darwin"
	dryRun := config.Global.Iptables.DryRun || !isLinux || iptBin == "" || os.Geteuid() != 0

	m := &Manager{
		preroutingChain:   prefix + "_PREROUTING",
		postroutingChain:  prefix + "_POSTROUTING",
		forwardChain:      prefix + "_FORWARD",
		isLinux:           isLinux,
		isMacOS:           isMac,
		iptablesBin:       iptBin,
		effectiveDryRun:   dryRun,
		ruleSpeeds:        make(map[int][2]float64),
		lastChainCounters: make(map[int][2]int64),
		lastSampleTime:    time.Now(),
		relayCounters:     make(map[int]*ruleRelayCounter),
		listeners:         make(map[int]*activeListener),
	}
	outB, inB := m.readHostNicBytes()
	m.lastHostNetBytes = [2]int64{outB, inB}
	m.hasHostBaseline = true
	return m
}

func (m *Manager) runCmd(args ...string) (string, error) {
	if m.effectiveDryRun {
		log.Printf("[IPTABLES-SYNC] iptables %s", strings.Join(args, " "))
		return "", nil
	}
	cmd := exec.Command(m.iptablesBin, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("iptables %s 失败: %v (%s)", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

func (m *Manager) EnsureIPForwardEnabled() bool {
	if m.isLinux && !m.effectiveDryRun {
		_ = os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0644)
	}
	return m.CheckIPForwardStatus()
}

func (m *Manager) CheckIPForwardStatus() bool {
	if m.isLinux && !m.effectiveDryRun {
		if b, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward"); err == nil {
			return strings.TrimSpace(string(b)) == "1"
		}
	}
	return true
}

func (m *Manager) ensureChains() {
	if m.effectiveDryRun {
		return
	}
	_, _ = m.runCmd("-t", "nat", "-N", m.preroutingChain)
	_, _ = m.runCmd("-t", "nat", "-N", m.postroutingChain)
	_, _ = m.runCmd("-t", "filter", "-N", m.forwardChain)

	if _, err := m.runCmd("-t", "nat", "-C", "PREROUTING", "-j", m.preroutingChain); err != nil {
		_, _ = m.runCmd("-t", "nat", "-A", "PREROUTING", "-j", m.preroutingChain)
	}
	if _, err := m.runCmd("-t", "nat", "-C", "POSTROUTING", "-j", m.postroutingChain); err != nil {
		_, _ = m.runCmd("-t", "nat", "-A", "POSTROUTING", "-j", m.postroutingChain)
	}
	if _, err := m.runCmd("-t", "filter", "-C", "FORWARD", "-j", m.forwardChain); err != nil {
		_, _ = m.runCmd("-t", "filter", "-I", "FORWARD", "1", "-j", m.forwardChain)
	}
}

func expandProtocols(proto string) []string {
	p := strings.ToLower(strings.TrimSpace(proto))
	if p == "tcp+udp" {
		return []string{"tcp", "udp"}
	}
	return []string{p}
}

func (m *Manager) BuildRuleCommands(rule *model.ForwardRule, action string) [][]string {
	if rule.ResolvedIP == nil || *rule.ResolvedIP == "" {
		return nil
	}
	resolvedIP := *rule.ResolvedIP
	snatIP := GetLocalSnatIP(resolvedIP)
	if rule.SnatIP != nil && IsIPv4Address(*rule.SnatIP) {
		snatIP = strings.TrimSpace(*rule.SnatIP)
	}

	commentBase := fmt.Sprintf("ipt_fwd_rule_%d", rule.ID)
	commentUp := fmt.Sprintf("ipt_fwd_up_%d", rule.ID)
	commentDown := fmt.Sprintf("ipt_fwd_down_%d", rule.ID)
	var cmds [][]string

	for _, proto := range expandProtocols(rule.Protocol) {
		// 1. PREROUTING DNAT
		cmds = append(cmds, []string{
			"-t", "nat", action, m.preroutingChain,
			"-p", proto, "--dport", strconv.Itoa(rule.ListenPort),
			"-m", "comment", "--comment", commentBase,
			"-j", "DNAT", "--to-destination", fmt.Sprintf("%s:%d", resolvedIP, rule.TargetPort),
		})
		// 2. POSTROUTING SNAT (--to-source 本机网卡IP)
		cmds = append(cmds, []string{
			"-t", "nat", action, m.postroutingChain,
			"-p", proto, "-d", resolvedIP, "--dport", strconv.Itoa(rule.TargetPort),
			"-m", "comment", "--comment", commentBase,
			"-j", "SNAT", "--to-source", snatIP,
		})
		// 3. FILTER FORWARD 上行放行与字节计数
		cmds = append(cmds, []string{
			"-t", "filter", action, m.forwardChain,
			"-p", proto, "-d", resolvedIP, "--dport", strconv.Itoa(rule.TargetPort),
			"-m", "comment", "--comment", commentUp,
			"-j", "ACCEPT",
		})
		// 4. FILTER FORWARD 下行放行与字节计数
		cmds = append(cmds, []string{
			"-t", "filter", action, m.forwardChain,
			"-p", proto, "-s", resolvedIP, "--sport", strconv.Itoa(rule.TargetPort),
			"-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED",
			"-m", "comment", "--comment", commentDown,
			"-j", "ACCEPT",
		})
	}
	return cmds
}

func (m *Manager) SyncAllRules(rules []*model.ForwardRule) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.EnsureIPForwardEnabled()
	m.ensureChains()

	var executed []string
	flushArgs := [][]string{
		{"-t", "nat", "-F", m.preroutingChain},
		{"-t", "nat", "-F", m.postroutingChain},
		{"-t", "filter", "-F", m.forwardChain},
	}
	for _, args := range flushArgs {
		_, _ = m.runCmd(args...)
		executed = append(executed, "iptables "+strings.Join(args, " "))
	}

	if !m.effectiveDryRun {
		m.lastChainCounters = make(map[int][2]int64)
	}

	for _, r := range rules {
		if !r.Enabled || r.ResolvedIP == nil || *r.ResolvedIP == "" {
			continue
		}
		for _, args := range m.BuildRuleCommands(r, "-A") {
			if _, err := m.runCmd(args...); err != nil {
				return executed, err
			}
			executed = append(executed, "iptables "+strings.Join(args, " "))
		}
	}

	if m.effectiveDryRun {
		m.syncNativeListenersLocked(rules)
	}
	return executed, nil
}

func (m *Manager) syncNativeListenersLocked(rules []*model.ForwardRule) {
	desired := make(map[int]*model.ForwardRule)
	for _, r := range rules {
		if r.Enabled && r.ResolvedIP != nil && *r.ResolvedIP != "" {
			desired[r.ID] = r
		}
	}
	for rid, ln := range m.listeners {
		if _, ok := desired[rid]; !ok {
			close(ln.stopSignal)
			if ln.tcpLn != nil {
				_ = ln.tcpLn.Close()
			}
			if ln.udpConn != nil {
				_ = ln.udpConn.Close()
			}
			delete(m.listeners, rid)
		}
	}
	for rid, r := range desired {
		spec := fmt.Sprintf("%s:%d->%s:%d", r.Protocol, r.ListenPort, *r.ResolvedIP, r.TargetPort)
		if existing, ok := m.listeners[rid]; ok && existing.spec == spec {
			continue
		}
		if existing, ok := m.listeners[rid]; ok {
			close(existing.stopSignal)
			if existing.tcpLn != nil {
				_ = existing.tcpLn.Close()
			}
			if existing.udpConn != nil {
				_ = existing.udpConn.Close()
			}
			delete(m.listeners, rid)
		}
		m.startRuleListenerLocked(r, spec)
	}
}

func (m *Manager) startRuleListenerLocked(r *model.ForwardRule, spec string) {
	if _, ok := m.relayCounters[r.ID]; !ok {
		m.relayCounters[r.ID] = &ruleRelayCounter{}
	}
	cnt := m.relayCounters[r.ID]
	act := &activeListener{
		spec:       spec,
		stopSignal: make(chan struct{}),
	}
	targetAddr := fmt.Sprintf("%s:%d", *r.ResolvedIP, r.TargetPort)
	listenAddr := fmt.Sprintf("0.0.0.0:%d", r.ListenPort)

	for _, proto := range expandProtocols(r.Protocol) {
		if proto == "tcp" {
			ln, err := net.Listen("tcp4", listenAddr)
			if err == nil {
				act.tcpLn = ln
				go func(l net.Listener, dst string, c *ruleRelayCounter, stop <-chan struct{}) {
					for {
						conn, err := l.Accept()
						if err != nil {
							select {
							case <-stop:
								return
							default:
								continue
							}
						}
						go handleTCPConn(conn, dst, c)
					}
				}(ln, targetAddr, cnt, act.stopSignal)
			}
		} else if proto == "udp" {
			pconn, err := net.ListenPacket("udp4", listenAddr)
			if err == nil {
				act.udpConn = pconn
				go handleUDPRelay(pconn, targetAddr, cnt, act.stopSignal)
			}
		}
	}
	m.listeners[r.ID] = act
}

func handleTCPConn(client net.Conn, targetAddr string, cnt *ruleRelayCounter) {
	defer client.Close()
	up, err := net.DialTimeout("tcp4", targetAddr, 8*time.Second)
	if err != nil {
		return
	}
	defer up.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		n, _ := io.Copy(up, client)
		if n > 0 {
			cnt.upBytes.Add(n)
		}
	}()
	go func() {
		defer wg.Done()
		n, _ := io.Copy(client, up)
		if n > 0 {
			cnt.downBytes.Add(n)
		}
	}()
	wg.Wait()
}

func handleUDPRelay(pconn net.PacketConn, targetAddr string, cnt *ruleRelayCounter, stop <-chan struct{}) {
	buf := make([]byte, 65535)
	for {
		n, clientAddr, err := pconn.ReadFrom(buf)
		if err != nil {
			select {
			case <-stop:
				return
			default:
				continue
			}
		}
		if n > 0 {
			cnt.upBytes.Add(int64(n))
			payload := append([]byte(nil), buf[:n]...)
			go func(data []byte, cAddr net.Addr) {
				up, err := net.DialTimeout("udp4", targetAddr, 5*time.Second)
				if err != nil {
					return
				}
				defer up.Close()
				_ = up.SetDeadline(time.Now().Add(5 * time.Second))
				_, _ = up.Write(data)
				resp := make([]byte, 65535)
				rn, err := up.Read(resp)
				if err == nil && rn > 0 {
					cnt.downBytes.Add(int64(rn))
					_, _ = pconn.WriteTo(resp[:rn], cAddr)
				}
			}(payload, clientAddr)
		}
	}
}

var iptCounterRe = regexp.MustCompile(`^(\d+)\s+(\d+)\s+ACCEPT\b.*?/\*\s*ipt_fwd_(up|down)_(\d+)\s*\*/`)

func (m *Manager) readRuleCounters() map[int][2]int64 {
	res := make(map[int][2]int64)
	if m.effectiveDryRun {
		for rid, c := range m.relayCounters {
			res[rid] = [2]int64{c.upBytes.Load(), c.downBytes.Load()}
		}
		return res
	}
	out, err := m.runCmd("-t", "filter", "-L", m.forwardChain, "-n", "-v", "-x")
	if err != nil || out == "" {
		return res
	}
	for _, line := range strings.Split(out, "\n") {
		matches := iptCounterRe.FindStringSubmatch(strings.TrimSpace(line))
		if len(matches) == 5 {
			bytesVal, _ := strconv.ParseInt(matches[2], 10, 64)
			dir := matches[3]
			rid, _ := strconv.Atoi(matches[4])
			cur := res[rid]
			if dir == "up" {
				cur[0] += bytesVal
			} else {
				cur[1] += bytesVal
			}
			res[rid] = cur
		}
	}
	return res
}

func (m *Manager) readHostNicBytes() (int64, int64) {
	if m.isLinux {
		if b, err := os.ReadFile("/proc/net/dev"); err == nil {
			var rxTotal, txTotal int64
			lines := strings.Split(string(b), "\n")
			for idx, line := range lines {
				if idx < 2 || !strings.Contains(line, ":") {
					continue
				}
				parts := strings.SplitN(line, ":", 2)
				iface := strings.TrimSpace(parts[0])
				if iface == "lo" {
					continue
				}
				fields := strings.Fields(parts[1])
				if len(fields) >= 9 {
					rx, _ := strconv.ParseInt(fields[0], 10, 64)
					tx, _ := strconv.ParseInt(fields[8], 10, 64)
					rxTotal += rx
					txTotal += tx
				}
			}
			return txTotal, rxTotal
		}
	}

	// macOS / BSD: netstat -ib
	if netstatBin, err := exec.LookPath("netstat"); err == nil {
		out, err := exec.Command(netstatBin, "-ib").Output()
		if err == nil {
			var inTotal, outTotal int64
			seen := make(map[string]bool)
			lines := strings.Split(string(out), "\n")
			for idx, line := range lines {
				if idx == 0 || !strings.Contains(line, "<Link#") {
					continue
				}
				fields := strings.Fields(line)
				if len(fields) >= 10 {
					iface := fields[0]
					if strings.HasPrefix(iface, "lo") || seen[iface] {
						continue
					}
					ibytes, err1 := strconv.ParseInt(fields[len(fields)-5], 10, 64)
					obytes, err2 := strconv.ParseInt(fields[len(fields)-2], 10, 64)
					if err1 == nil && err2 == nil {
						seen[iface] = true
						inTotal += ibytes
						outTotal += obytes
					}
				}
			}
			return outTotal, inTotal
		}
	}
	return 0, 0
}

func (m *Manager) SampleTraffic() {
	rules, err := database.DB.ListRules()
	if err != nil {
		return
	}

	m.mu.Lock()
	now := time.Now()
	dt := now.Sub(m.lastSampleTime).Seconds()
	if dt < 0.4 {
		m.mu.Unlock()
		return
	}
	m.lastSampleTime = now

	curOut, curIn := m.readHostNicBytes()
	if !m.hasHostBaseline {
		m.lastHostNetBytes = [2]int64{curOut, curIn}
		m.hasHostBaseline = true
	}
	hostDeltaUp := curOut - m.lastHostNetBytes[0]
	if hostDeltaUp < 0 {
		hostDeltaUp = 0
	}
	hostDeltaDown := curIn - m.lastHostNetBytes[1]
	if hostDeltaDown < 0 {
		hostDeltaDown = 0
	}
	m.lastHostNetBytes = [2]int64{curOut, curIn}

	m.HostUpSpeed = float64(hostDeltaUp) / dt
	m.HostDownSpeed = float64(hostDeltaDown) / dt
	m.HostUpBytes += hostDeltaUp
	m.HostDownBytes += hostDeltaDown

	counters := m.readRuleCounters()
	var enabledCount int64
	for _, r := range rules {
		if r.Enabled && r.ResolvedIP != nil && *r.ResolvedIP != "" {
			enabledCount++
		}
	}

	deltas := make(map[int][2]int64)
	for _, r := range rules {
		if !r.Enabled || r.ResolvedIP == nil || *r.ResolvedIP == "" {
			m.ruleSpeeds[r.ID] = [2]float64{0, 0}
			continue
		}
		cur := counters[r.ID]
		prev, hasPrev := m.lastChainCounters[r.ID]
		if !hasPrev {
			prev = cur
		}
		m.lastChainCounters[r.ID] = cur

		dUp := cur[0] - prev[0]
		if dUp < 0 {
			dUp = cur[0]
		}
		dDown := cur[1] - prev[1]
		if dDown < 0 {
			dDown = cur[1]
		}

		if m.effectiveDryRun && dUp == 0 && dDown == 0 && enabledCount > 0 {
			dUp = hostDeltaUp / enabledCount
			dDown = hostDeltaDown / enabledCount
		}

		m.ruleSpeeds[r.ID] = [2]float64{
			float64(dUp) / dt,
			float64(dDown) / dt,
		}
		if dUp > 0 || dDown > 0 {
			deltas[r.ID] = [2]int64{dUp, dDown}
		}
	}
	m.mu.Unlock()

	if len(deltas) > 0 {
		database.DB.AddTrafficDelta(deltas)
	}
}

func (m *Manager) GetRuleSpeed(ruleID int) (float64, float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	sp := m.ruleSpeeds[ruleID]
	return sp[0], sp[1]
}

func (m *Manager) GetStatus(activeRules []*model.ForwardRule) map[string]interface{} {
	nics := GetLocalNicIPs()
	defaultSnat := GetLocalSnatIP("")
	sysName := runtime.GOOS

	preview := []string{
		fmt.Sprintf("# 运行平台: %s | 专用链: nat/%s, nat/%s, filter/%s", sysName, m.preroutingChain, m.postroutingChain, m.forwardChain),
		fmt.Sprintf("# 本机网卡默认 SNAT 源 IP: %s", defaultSnat),
		"sysctl -w net.ipv4.ip_forward=1",
	}

	for _, r := range activeRules {
		if !r.Enabled || r.ResolvedIP == nil || *r.ResolvedIP == "" {
			continue
		}
		snat := defaultSnat
		if r.SnatIP != nil && *r.SnatIP != "" {
			snat = *r.SnatIP
		}
		preview = append(preview, fmt.Sprintf(
			"\n# [Rule #%d] %s (%s :%d -> %s [%s]:%d, SNAT: %s)",
			r.ID, r.Name, strings.ToUpper(r.Protocol), r.ListenPort, r.TargetHost, *r.ResolvedIP, r.TargetPort, snat,
		))
		for _, args := range m.BuildRuleCommands(r, "-A") {
			preview = append(preview, "iptables "+strings.Join(args, " "))
		}
	}

	return map[string]interface{}{
		"dry_run":            m.effectiveDryRun,
		"os_name":            sysName,
		"is_linux":           m.isLinux,
		"is_macos":           m.isMacOS,
		"ip_forward_enabled": m.CheckIPForwardStatus(),
		"default_snat_ip":    defaultSnat,
		"local_nics":         nics,
		"commands_preview":   strings.Join(preview, "\n"),
	}
}

