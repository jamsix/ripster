package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const ver = "0.1"

// routeTable is central map of routes being advertised on each of the parentIPs
// Collector goroutines fill the routeTable with the entries
// Router goroutine advertises the routes in the routeTable
var routeTable map[string]map[string]RouteEntry

// routeTableMutex takes care only one Collector at a time can alter the routeTable
// and Router cannot read it while it is being altered
var routeTableMutex = &sync.RWMutex{}

type RouteEntry struct {
	Source   int // Collector that added the RouteEntry
	Time     time.Time
	ParentIP net.IP // IP address on which the route is advertised
	Route    net.IPNet
	Deleted  bool
}

const (
	sourceStatic         = iota
	sourceDockerIpvlanL3 = iota
)

var l = new(Log)

func main() {

	// Flags
	version := flag.Bool("v", false, "Prints out the version")
	staticRoutesString := flag.String("static-routes", "", "Comma separated list of static routes to be advertised")
	staticSourcesString := flag.String("static-sources", "", "Comma separated list of host IP addresses or networks from which the static routes will be advertised")
	staticSourcesExcludedString := flag.String("static-sources-excluded", "169.254.0.0/16,127.0.0.0/8", "Comma separated list of host IP addresses or networks that are excluded from route advertisement")
	dockerIpvlanEnable := flag.Bool("docker-ipvlan", false, "Enable advertisement of Docker IPVLAN L3 mode networks")
	dockerIpvlanRefreshFloat := flag.Float64("docker-ipvlan-refresh", 0.2, "Docker API network refresh rate in seconds")
	ripUpdateTimerFloat := flag.Float64("rip-update", 30, "How often the RIP process sends an unsolicited Response message containing the complete routing table")
	ripGCTimerFloat := flag.Float64("rip-gc", 120, "RIP Garbage-collection timer. When it expires, the route is deleted from the routing table.")
	ripUpdateDelayFloat := flag.Float64("rip-update-delay", 0.5, "RIP triggered update delay. RIP update is delayed if a previous update has been sent less than delay seconds ago.")
	ripDeclareUnreachableOnQuit := flag.Bool("rip-unreachable-on-quit", true, "Should process declare all routes unreachable before quitting?")
	flag.Parse()

	var staticRoutes []net.IPNet
	if *staticRoutesString != "" {
		staticRoutesStringSlice := strings.Split(strings.Replace(*staticRoutesString, " ", "", -1), ",")
		for _, route := range staticRoutesStringSlice {
			ip, ipNet, err := net.ParseCIDR(route)
			if ip.To4() == nil {
				l.Error("Static route configuration: %s is not an IPv4 address", ip.String())
			} else if err == nil {
				staticRoutes = append(staticRoutes, *ipNet)
			} else {
				l.Error("Static route configuration: %s", err.Error())
			}
		}
	}
	var staticSources []net.IPNet
	if *staticSourcesString != "" {
		staticSourcesStringSlice := strings.Split(strings.Replace(*staticSourcesString, " ", "", -1), ",")
		for _, sourceNetwork := range staticSourcesStringSlice {
			if strings.Index(sourceNetwork, "/") == -1 {
				sourceNetwork = sourceNetwork + "/32"
			}
			ip, ipNet, err := net.ParseCIDR(sourceNetwork)
			if ip.To4() == nil {
				l.Error("Static source configuration: %s is not an IPv4 address/network", ip.String())
			} else if err == nil {
				staticSources = append(staticSources, *ipNet)
			} else {
				l.Error("Static source configuration: %s", err.Error())
			}
		}
	}
	var staticSourcesExcluded []net.IPNet
	if *staticSourcesExcludedString != "" {
		staticSourcesExcludedStringSlice := strings.Split(strings.Replace(*staticSourcesExcludedString, " ", "", -1), ",")
		for _, sourceNetwork := range staticSourcesExcludedStringSlice {
			if strings.Index(sourceNetwork, "/") == -1 {
				sourceNetwork = sourceNetwork + "/32"
			}
			ip, ipNet, err := net.ParseCIDR(sourceNetwork)
			if ip.To4() == nil {
				l.Error("Static source exclude configuration: %s is not an IPv4 address/network", ip.String())
			} else if err == nil {
				staticSourcesExcluded = append(staticSourcesExcluded, *ipNet)
			} else {
				l.Error("Static source exclude configuration: %s", err.Error())
			}
		}
	}
	dockerIpvlanRefresh := time.Duration(int(*dockerIpvlanRefreshFloat*1000)) * time.Millisecond
	ripUpdateTimer := time.Duration(int(*ripUpdateTimerFloat*1000)) * time.Millisecond
	ripGCTimer := time.Duration(int(*ripGCTimerFloat*1000)) * time.Millisecond
	ripUpdateDelay := time.Duration(int(*ripUpdateDelayFloat*1000)) * time.Millisecond

	// Channels
	triggeredUpdate := make(chan bool)

	// Routetable
	routeTable = make(map[string]map[string]RouteEntry)

	if *version == true {
		fmt.Printf("RIPster v%s (%s/%s)\n\n", ver, runtime.GOOS, runtime.GOARCH)
		os.Exit(0)
	}

	// Gentlemen, start your Collectors
	if len(staticRoutes) > 0 {
		go staticCollector(staticRoutes, staticSources, staticSourcesExcluded, triggeredUpdate)
	}
	if *dockerIpvlanEnable {
		go dockerIpvlanL3Collector(dockerIpvlanRefresh, ripGCTimer, triggeredUpdate)
	}

	go ripRouter(ripUpdateTimer, ripUpdateDelay, ripGCTimer, triggeredUpdate)

	go handleSignals(*ripDeclareUnreachableOnQuit)

	// Engines do the magic, let's chill
	for {
		time.Sleep(time.Duration(1) * time.Second)
	}

}

// Runs in it's own Goroutine
// Adds preconfigured static routes to the routeTable once
func staticCollector(staticRoutes []net.IPNet, staticSources []net.IPNet, staticSourcesExcluded []net.IPNet, triggeredUpdate chan bool) {

	triggerUpdate := false
	var parentIPs []net.IP

	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		if iface.Name != "lo" {
			addrs, _ := iface.Addrs()
			for _, addr := range addrs {
				ip, _, err := net.ParseCIDR(addr.String())
				if err != nil {
					l.Error("Host interface IP %s", err.Error())
				} else if ip.To4() == nil {
					// This is not an IPv4 subnet
				} else {
					if staticSources == nil && staticSourcesExcluded == nil {
						parentIPs = append(parentIPs, ip.To4())
					} else if staticSourcesExcluded == nil {
						for _, ss := range staticSources {
							if ss.Contains(ip) {
								parentIPs = append(parentIPs, ip.To4())
								break
							}
						}
					} else if staticSources == nil {
						excluded := false
						for _, sse := range staticSourcesExcluded {
							if sse.Contains(ip) {
								excluded = true
							}
						}
						if excluded == false {
							parentIPs = append(parentIPs, ip.To4())
						}
					}
				}
			}
		}
	}

	routeTableMutex.Lock()
	for _, parentIP := range parentIPs {
		if _, exists := routeTable[parentIP.String()]; !exists {
			routeTable[parentIP.String()] = make(map[string]RouteEntry)
		}
		for _, route := range staticRoutes {
			routeEntry := new(RouteEntry)
			routeEntry.Source = sourceStatic
			routeEntry.Time = time.Now()
			routeEntry.ParentIP = parentIP
			routeEntry.Route = route
			routeTable[parentIP.String()][route.String()] = *routeEntry
			l.Info("Adding %s from %s (static)", route.String(), parentIP.String())
			triggerUpdate = true
		}
	}
	routeTableMutex.Unlock()

	if triggerUpdate == true {
		// triggeredUpdate is blocking!
		triggeredUpdate <- true
	}

}

// Runs in it's own Goroutine
// Polls Docker's /networks API every refresh time and updates routeTable accordingly.
// Triggers triggeredUpdate channel if there is a new or deleted route.
func dockerIpvlanL3Collector(refresh time.Duration, gcTimer time.Duration, triggeredUpdate chan bool) {

	for {
		startTime := time.Now()
		triggerUpdate := false

		newRouteEntries, err := getDockerIpvlanL3Networks()
		if err != nil {
			l.Error(err.Error())
			time.Sleep(refresh - time.Since(startTime))
			continue
		}

		routeTableMutex.Lock()
		// Add all newRouteEntries to routeTable
		for parentIp, routes := range newRouteEntries {
			if _, exists := routeTable[parentIp]; !exists {
				routeTable[parentIp] = make(map[string]RouteEntry)
			}
			for route, routeEntry := range routes {
				if _, exists := routeTable[parentIp][route]; !exists {
					l.Info("Adding %s from %s (Docker Ipvlan L3)", route, parentIp)
					triggerUpdate = true
				} else if routeTable[parentIp][route].Deleted == true {
					l.Info("Adding %s from %s (Docker Ipvlan L3)", route, parentIp)
					triggerUpdate = true
				}
				routeTable[parentIp][route] = routeEntry
			}
		}

		// routeTable entries that are not newRouteEntries are deleted.
		// Deleted routes are marked as deleted for 10 minutes and removed
		// after that.
		for parentIp, routes := range routeTable {
			for route, routeEntry := range routes {
				if routeEntry.Source == sourceDockerIpvlanL3 {
					if _, exists := newRouteEntries[parentIp][route]; !exists {
						if routeEntry.Deleted == false {
							routeEntry.Time = time.Now()
							routeEntry.Deleted = true
							routeTable[parentIp][route] = routeEntry
							l.Info("Setting %s from %s as deleted route (Docker Ipvlan L3)", route, parentIp)
							//fmt.Printf("\nN %#v\n", newRouteEntries)
							//fmt.Printf("\nR %#v\n", routeTable)
							triggerUpdate = true
						} else if time.Since(routeEntry.Time) > gcTimer {
							delete(routeTable[parentIp], route)
							l.Info("Removing %s from %s (Docker Ipvlan L3)", route, parentIp)
						}
					}
				}
			}
		}
		routeTableMutex.Unlock()

		if triggerUpdate == true {
			// triggeredUpdate is blocking!
			triggeredUpdate <- true
		}

		time.Sleep(refresh - time.Since(startTime))
	}

}

// Connects to Docker's API, GETs /networks, finds ipvlan L3 networks and populates
// the []RouteEntry with parent interface IP addresses, ipvlan networks and
// hosts with IP address in the ipvlan network
// Returns routeTable, error
func getDockerIpvlanL3Networks() (map[string]map[string]RouteEntry, error) {

	conn, err := net.Dial("unix", "/var/run/docker.sock")
	if err != nil {
		return nil, fmt.Errorf("Opening /var/run/docker.sock failed")
	}

	defer conn.Close()

	_, err = conn.Write([]byte("GET /networks HTTP/1.1\nHost:\n\n"))
	if err != nil {
		return nil, fmt.Errorf("GET /networks HTTP/1.1 failed")
	}

	reader := bufio.NewReader(conn)
	jsonStr := ""
	for i := 0; i < 20; i++ {
		line, _ := reader.ReadString('\n')
		if strings.Index(line, "HTTP/1.1") != -1 {
			httpCode := line[strings.Index(line, "HTTP/1.1")+9 : strings.Index(line, "HTTP/1.1")+12]
			if httpCode != "200" {
				return nil, fmt.Errorf("API returned HTTP code: %s", httpCode)
			}
		} else if strings.Index(line, "[{") != -1 {
			jsonStr = line[strings.Index(line, "[{") : strings.LastIndex(line, "}]")+2]
			break
		}
	}
	if jsonStr == "" {
		return nil, fmt.Errorf("API returned no JSON payload")
	}

	// We are not interested in all returned JSON structures, only in those that
	// will be mapped to the structures that follow
	type IPAMConfig struct {
		Gateway string
		Subnet  string
	}
	type IPAM struct {
		Config []IPAMConfig
	}
	type Options struct {
		Parent      string
		Ipvlan_mode string
	}
	type Network struct {
		Name       string
		Driver     string
		IPAM       IPAM
		Containers map[string]interface{}
		Options    Options
	}
	var networks []Network

	json.Unmarshal([]byte(jsonStr), &networks)
	//fmt.Printf("\n%#v\n", networks)
	dockerIpvlanL3RouteTable := make(map[string]map[string]RouteEntry)
	//fmt.Printf("\nThere is ipvlan:")
	for i := 0; i < len(networks); i++ {
		//fmt.Printf(" ! %i ! ", len(networks))
		if networks[i].Driver == "ipvlan" && networks[i].Options.Ipvlan_mode == "l3" {
			//fmt.Printf(" YES ")
			var parentIPs []net.IP
			var routes []net.IPNet

			// Each ipvlan network has a parent interface. Each interface can
			// have multiple IP addresses. Find out all the IP addresses of the
			// parent interface.
			parentInterface := networks[i].Options.Parent
			ifaces, _ := net.Interfaces()
			for _, iface := range ifaces {
				if iface.Name == parentInterface {
					addrs, _ := iface.Addrs()
					for _, addr := range addrs {
						ip, _, err := net.ParseCIDR(addr.String())
						if err != nil {
							l.Error("Docker Ipvlan L3 parent interface %s", err.Error())
						} else if ip.To4() == nil {
							// This is not an IPv4 subnet
						} else {
							parentIPs = append(parentIPs, ip.To4())
						}
					}
					break
				}
			}

			// Ipvlan network has 0 or more IPAM subnets configured. These
			// subnets will be advertised as routes.
			for j := 0; j < len(networks[i].IPAM.Config); j++ {
				ip, ipNet, err := net.ParseCIDR(networks[i].IPAM.Config[j].Subnet)
				if err != nil {
					l.Error("Docker Ipvlan L3 IPAM network %s", err.Error())
				} else if ip.To4() == nil {
					// This is not an IPv4 subnet
				} else {
					routes = append(routes, *ipNet)
				}
			}

			// Ipvlan network has 0 or more Containers with IP addresses. These
			// IP addresses will be advertised as /32 routes.
			var val interface{}
			for _, val = range networks[i].Containers {
				mp, _ := val.(map[string]interface{})
				ipStr, _ := mp["IPv4Address"].(string)
				ip, _, err := net.ParseCIDR(ipStr)
				if err != nil {
					l.Error("Docker Ipvlan L3 netork container %s", err.Error())
				} else if ip.To4() == nil {
					// This is not an IPv4 subnet
				} else {
					ipNet := new(net.IPNet)
					ipNet.IP = ip.To4()
					ipNet.Mask = net.CIDRMask(32, 32)
					routes = append(routes, *ipNet)
				}
			}

			// Each of the ipvlan networks will be advertised on each of the
			// parent interface IP addresses
			for _, parentIP := range parentIPs {
				if _, exists := dockerIpvlanL3RouteTable[parentIP.String()]; !exists {
					dockerIpvlanL3RouteTable[parentIP.String()] = make(map[string]RouteEntry)
				}
				for _, route := range routes {
					routeEntry := new(RouteEntry)
					routeEntry.Source = sourceDockerIpvlanL3
					routeEntry.Time = time.Now()
					routeEntry.ParentIP = parentIP
					routeEntry.Route = route
					dockerIpvlanL3RouteTable[parentIP.String()][route.String()] = *routeEntry
				}
			}
		}
	}

	return dockerIpvlanL3RouteTable, nil
}

// Runs in it's own Goroutine
// Advertises routes using RIPv2 every updateTimer or whenever there is a triggeredUpdate.
// Routes are advertised using the  Unsolicited routing update message, multicasted
// from each of the parentIP addreses from UDP 520 to UDP 520.
func ripRouter(updateTimer time.Duration, ripUpdateDelay time.Duration, gcTimer time.Duration, triggeredUpdate chan bool) {

	lastUpdate := time.Now().Add(-time.Hour)

	for {
		// All routeTable routes are advertised with regular updates every updateTimer
		// (defaults to 30s). Whenever there is a change in routeTable, a triggered
		// update is sent immediately, or, if an update has been just sent, after
		// a triggeredUpdateDelay
		select {
		case _ = <-triggeredUpdate:
			if lastUpdate.Add(ripUpdateDelay).After(time.Now()) {
				sleepDelay := ripUpdateDelay - time.Since(lastUpdate)
				l.Info("RIP update throttled, sleeping %f seconds", sleepDelay.Seconds())
				time.Sleep(sleepDelay)
			}
			l.Info("RIP triggered update")
		case <-time.After(updateTimer):
			l.Info("RIP regular update")
		}
		routeTableMutex.RLock()
		advertiseRIP(gcTimer)
		routeTableMutex.RUnlock()
		lastUpdate = time.Now()
	}

}

// Sends out the Unsolicited routing update message, multicasted from each of the parentIP
// addreses.
func advertiseRIP(gcTimer time.Duration) {

	// Structures that consist a RIP message, as per RFC2453, 4. Protocol Extensions
	type RIPHeader struct {
		Command uint8
		Version uint8
		Unused  uint16
	}
	type RIPRoute struct {
		AddressFamilyIdentifier uint16
		RouteTag                uint16
		IPAddress               uint32
		SubnetMask              uint32
		NextHop                 uint32
		Metric                  uint32
	}

	for parentIp, routes := range routeTable {

		localAddr, err := net.ResolveUDPAddr("udp", parentIp+":520")
		remoteEP := net.UDPAddr{IP: net.ParseIP("224.0.0.9"), Port: 520}
		conn, err := net.DialUDP("udp", localAddr, &remoteEP)
		if err != nil {
			l.Error("Connection error %v", err)
			return
		}
		ripHeader := new(RIPHeader)
		ripHeader.Command = 2
		ripHeader.Version = 2

		var buf bytes.Buffer
		binary.Write(&buf, binary.BigEndian, ripHeader)

		routeStr := ""
		for _, routeEntry := range routes {
			if (routeEntry.Deleted == true) && (time.Since(routeEntry.Time) > gcTimer) {
				// Deleted routes older than gcTimer are not advertised anymore
			} else {
				route := new(RIPRoute)
				route.AddressFamilyIdentifier = 2
				route.IPAddress = binary.BigEndian.Uint32(routeEntry.Route.IP)
				route.SubnetMask = binary.BigEndian.Uint32(routeEntry.Route.Mask)
				if routeEntry.Deleted == true {
					// Deleted routes younger than gcTimer are advertised with:
					route.Metric = 16
				} else {
					route.Metric = 1
				}
				// NextHop is left at 0.0.0.0. Receiving RIP router will use sender's
				// IP address as the NextHop.
				binary.Write(&buf, binary.BigEndian, route)
				maskOnes, _ := routeEntry.Route.Mask.Size()
				routeStr = routeStr + " " + routeEntry.Route.IP.String() + "/" + strconv.FormatUint(uint64(maskOnes), 10) + " (" + strconv.FormatUint(uint64(route.Metric), 10) + ")"
			}
		}

		conn.Write(buf.Bytes())
		conn.Close()

		l.Info("RIP advertising from " + parentIp + ":" + routeStr)

	}

}

func handleSignals(ripDeclareUnreachableOnQuit bool) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	for sig := range c {
		switch sig {
		case syscall.SIGINT, syscall.SIGTERM:
			if ripDeclareUnreachableOnQuit == true {
				l.Info("SIGINT/SIGTERM received. Declaring all routes unreachable, than quitting.")
				routeTableMutex.Lock()
				for parentIp, routes := range routeTable {
					for route, routeEntry := range routes {
						routeEntry.Time = time.Now()
						routeEntry.Deleted = true
						routeTable[parentIp][route] = routeEntry
					}
				}
				advertiseRIP(time.Hour)
				routeTableMutex.Unlock()
			} else {
				l.Info("SIGINT/SIGTERM received. Quitting.")
			}
			os.Exit(0)
		case syscall.SIGHUP:
			// Reload config. If only.
		}
	}
}

// Logger
type Log struct {
	width  int
	height int
}

func (log *Log) Info(format string, a ...interface{}) {
	fmt.Printf(time.Now().Format("2006-01-02 15:04:05 ")+" INFO   "+format+"\n", a...)
}
func (log *Log) Error(format string, a ...interface{}) {
	fmt.Printf(time.Now().Format("2006-01-02 15:04:05 ")+" ERROR  "+format+"\n", a...)
}
