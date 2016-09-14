package ripster

import (
	"bytes"
	"net"
	"strings"
	"time"
	"errors"
	"fmt"
	"encoding/json"
	"bufio"
)

type DockerIpvlanCollector struct {
	LogLevel uint
	// Log channel, all collector logs will be sent to this channel
	Log chan string
	enabled bool
	// Setings
	updateTimer time.Duration
	// RIP fields
	routeTable map[string]map[string]DockerIpvlanCollectorRoute
	// Routers that are updated with routes
	router RouterInterface
}

type DockerIpvlanCollectorRoute struct {
	Time     time.Time
	ParentIP net.IP // IP address on which the route is advertised
	Route    net.IPNet
}

const (
	// Default RIP settings
	DockerIpvlanCollectorDefaultUpdateTimer = 1.0  // in seconds
	DockerIpvlanCollectorMinUpdateTimer = 0.01 // in seconds
	DockerIpvlanCollectorMaxUpdateTimer = 60.0 // in seconds
)

var dockerIpvlanCollector DockerIpvlanCollector


func NewDockerIpvlanCollector(router RouterInterface) (*DockerIpvlanCollector, error) {

	// There can be only one DockerIpvlanCollector instance
	if dockerIpvlanCollector.enabled == true {
		return &dockerIpvlanCollector, errors.New("Docker Ipvlan L3 Collector is already running")
	}

	dockerIpvlanCollector.enabled = true
	dockerIpvlanCollector.updateTimer = time.Duration(int(DockerIpvlanCollectorDefaultUpdateTimer*1000)) * time.Millisecond
	dockerIpvlanCollector.routeTable = make(map[string]map[string]DockerIpvlanCollectorRoute)

	dockerIpvlanCollector.Log = make(chan string, 100)

	dockerIpvlanCollector.router = router

	go dockerIpvlanCollector.collector()

	return &dockerIpvlanCollector, nil

}


func (DockerIpvlanCollector *DockerIpvlanCollector) SetTimers(update float32) error {

	if update < DockerIpvlanCollectorMinUpdateTimer || update > DockerIpvlanCollectorMaxUpdateTimer {
		return errors.New(fmt.Sprintf("Docker Ipvlan L3 Collector update timer should be between %.f and %.f", DockerIpvlanCollectorMinUpdateTimer, DockerIpvlanCollectorMaxUpdateTimer))
	}

	dockerIpvlanCollector.updateTimer = time.Duration(int(update*1000)) * time.Millisecond

	return nil

}

func (DockerIpvlanCollector *DockerIpvlanCollector) AddRoute(route DockerIpvlanCollectorRoute) {

	parentIPStr := route.ParentIP.String()
	routeStr := route.Route.String()

		if _, exists := DockerIpvlanCollector.routeTable[parentIPStr]; !exists {
				DockerIpvlanCollector.routeTable[parentIPStr] = make(map[string]DockerIpvlanCollectorRoute)
		}
		if _, exists := DockerIpvlanCollector.routeTable[parentIPStr][routeStr]; exists {
			DockerIpvlanCollector.logDebug("Docker Ipvlan L3 Collector adding %s from %s, but it already exists?", routeStr, parentIPStr)
		}
		DockerIpvlanCollector.routeTable[parentIPStr][routeStr] = route
		DockerIpvlanCollector.logDebug("Docker Ipvlan L3 Collector adding %s from %s", routeStr, parentIPStr)

		err := DockerIpvlanCollector.router.AddRoute(Route{Route:route.Route.String(), NextHop:route.ParentIP.String(), Metric:1, AdministrativeDistance:AdministrativeDistanceDockerL3})
		if err != nil {
			DockerIpvlanCollector.logError("Docker Ipvlan L3 Collector error: %s", err.Error())
		}

}

func (DockerIpvlanCollector *DockerIpvlanCollector) RemoveRoute(route DockerIpvlanCollectorRoute) {

		parentIPStr := route.ParentIP.String()
		routeStr := route.Route.String()

		if _, exists := DockerIpvlanCollector.routeTable[parentIPStr]; !exists {
				DockerIpvlanCollector.logDebug("Docker Ipvlan L3 Collector removing %s from %s, but %s does not exist?", routeStr, parentIPStr, parentIPStr)
		}
		if _, exists := DockerIpvlanCollector.routeTable[parentIPStr][routeStr]; !exists {
			DockerIpvlanCollector.logDebug("Docker Ipvlan L3 Collector removing %s from %s, but %s does not exist?", routeStr, parentIPStr, routeStr)
		}
		delete(DockerIpvlanCollector.routeTable[parentIPStr], routeStr)
		DockerIpvlanCollector.logDebug("Docker Ipvlan L3 Collector removing %s from %s", routeStr, parentIPStr)

		err := DockerIpvlanCollector.router.RemoveRoute(Route{Route:route.Route.String(), NextHop:route.ParentIP.String(), AdministrativeDistance:AdministrativeDistanceDockerL3})
		if err != nil {
			DockerIpvlanCollector.logError("Docker Ipvlan L3 Collector error: %s", err.Error())
		}

}

func (DockerIpvlanCollector *DockerIpvlanCollector) Close() {

	DockerIpvlanCollector.enabled = false
	DockerIpvlanCollector.routeTable = make(map[string]map[string]DockerIpvlanCollectorRoute)

}

func (DockerIpvlanCollector *DockerIpvlanCollector) LogChan() *chan string {
	return &DockerIpvlanCollector.Log
}


func (DockerIpvlanCollector *DockerIpvlanCollector) collector() {

	DockerIpvlanCollector.logInfo("Docker Ipvlan L3 Collector starting")

	for {
		if DockerIpvlanCollector.enabled == false {
			return
		}
		startTime := time.Now()

		latestRouteEntries, err := DockerIpvlanCollector.getDockerIpvlanL3Networks()
		if err != nil {
			DockerIpvlanCollector.logError(err.Error())
			time.Sleep(DockerIpvlanCollector.updateTimer - time.Since(startTime))
			continue
		}

		// Latest routes, that are not yet in DockerIpvlanCollector.routeTable must be
		// added
		var routeMustBeAdded bool
		for parentIpStr, routes := range latestRouteEntries {
			routeMustBeAdded = false
			if _, exists := DockerIpvlanCollector.routeTable[parentIpStr]; !exists {
				routeMustBeAdded = true
			}
			for routeStr, route := range routes {
				if routeMustBeAdded == true {
					DockerIpvlanCollector.AddRoute(route)
				} else if _, exists := DockerIpvlanCollector.routeTable[parentIpStr][routeStr]; !exists {
					DockerIpvlanCollector.AddRoute(route)
				}
			}
		}

		// Routes that are in DockerIpvlanCollector.routeTable, but are not the latest
		// routes, must be removed
		var routeMustBeRemoved bool
		for parentIpStr, routes := range DockerIpvlanCollector.routeTable {
			routeMustBeRemoved = false
			if _, exists := latestRouteEntries[parentIpStr]; !exists {
				routeMustBeRemoved = true
			}
			for routeStr, route := range routes {
				if routeMustBeRemoved == true {
					DockerIpvlanCollector.RemoveRoute(route)
				} else if _, exists := latestRouteEntries[parentIpStr][routeStr]; !exists {
					DockerIpvlanCollector.RemoveRoute(route)
				}
			}
		}

		time.Sleep(DockerIpvlanCollector.updateTimer - time.Since(startTime))
	}

}

// Connects to Docker's API, GETs /networks, finds ipvlan L3 networks and populates
// the return map with parent interface IP addresses, ipvlan networks and
// hosts with IP address in the ipvlan network
// Returns routeTable, error
func (DockerIpvlanCollector *DockerIpvlanCollector) getDockerIpvlanL3Networks() (map[string]map[string]DockerIpvlanCollectorRoute, error) {

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
				return nil, fmt.Errorf("Docker Ipvlan L3 Collector, docker API returned HTTP code: %s", httpCode)
			}
		} else if strings.Index(line, "[{") != -1 {
			jsonStr = line[strings.Index(line, "[{") : strings.LastIndex(line, "}]")+2]
			break
		}
	}
	if jsonStr == "" {
		return nil, fmt.Errorf("Docker Ipvlan L3 Collector, docker API returned no JSON payload")
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

	dockerIpvlanL3RouteTable := make(map[string]map[string]DockerIpvlanCollectorRoute)
	//fmt.Printf("\nThere is ipvlan:")
	for i := 0; i < len(networks); i++ {
		//fmt.Printf(" ! %i ! ", len(networks))
		if networks[i].Driver == "ipvlan" && networks[i].Options.Ipvlan_mode == "l3" {
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
							DockerIpvlanCollector.logError("Docker Ipvlan L3 Collector parent interface error: %s", err.Error())
						} else if ip.To4() == nil {
							// This is not an IPv4 subnet
						} else {
							parentIPs = append(parentIPs, ip.To4())
						}
					}
					break
				}
			}

			if len(parentIPs) == 0 {
				DockerIpvlanCollector.logError("Docker Ipvlan L3 Collector sees no parent interfaces with valid IPv4 addresses")
			}

			// Ipvlan network has 0 or more IPAM subnets configured. These
			// subnets will be advertised as routes.
			for j := 0; j < len(networks[i].IPAM.Config); j++ {
				ip, ipNet, err := net.ParseCIDR(networks[i].IPAM.Config[j].Subnet)
				if err != nil {
					DockerIpvlanCollector.logError("Docker Ipvlan L3 Collector IPAM network error: %s", err.Error())
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
					DockerIpvlanCollector.logError("Docker Ipvlan L3 Collector container error: %s", err.Error())
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
					dockerIpvlanL3RouteTable[parentIP.String()] = make(map[string]DockerIpvlanCollectorRoute)
				}
				for _, route := range routes {
					routeEntry := new(DockerIpvlanCollectorRoute)
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

func (DockerIpvlanCollector DockerIpvlanCollector) isSameRoute(r1, r2 DockerIpvlanCollectorRoute) bool {
	if (r1.Route.Contains(r2.Route.IP) || r2.Route.Contains(r1.Route.IP)) &&
		bytes.Compare(r1.ParentIP.To16(), r2.ParentIP.To16()) == 0 {
		return true
	} else {
		return false
	}
}

func (DockerIpvlanCollector *DockerIpvlanCollector) log(msg string) {
	select {
	case DockerIpvlanCollector.Log <- msg+"\n":
  	default:
  }
}

func (DockerIpvlanCollector *DockerIpvlanCollector) logDebug(format string, a ...interface{}) {
	if DockerIpvlanCollector.LogLevel >= LogDebug {
		DockerIpvlanCollector.log(fmt.Sprintf("DEBUG "+format, a...))
	}
}
func (DockerIpvlanCollector *DockerIpvlanCollector) logInfo(format string, a ...interface{}) {
	if DockerIpvlanCollector.LogLevel >= LogInfo {
		DockerIpvlanCollector.log(fmt.Sprintf("INFO  "+format, a...))
	}
}
func (DockerIpvlanCollector *DockerIpvlanCollector) logWarn(format string, a ...interface{}) {
	if DockerIpvlanCollector.LogLevel >= LogWarning {
		DockerIpvlanCollector.log(fmt.Sprintf("WARN  "+format, a...))
	}
}
func (DockerIpvlanCollector *DockerIpvlanCollector) logError(format string, a ...interface{}) {
	if DockerIpvlanCollector.LogLevel >= LogError {
		DockerIpvlanCollector.log(fmt.Sprintf("ERROR "+format, a...))
	}
}
