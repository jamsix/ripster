package main

import (
	"ripster"
	"time"
	"fmt"
	"flag"
	"net"
	"strings"
	"runtime"
	"os"
	"os/signal"
	"syscall"
)

const (
	Ver		= "0.2"
	LogDebug = 4
	LogInfo = 3
	LogWarning = 2
	LogError = 1
	LogNone = 0
)

var logLevel uint
var l = new(Log)

func main() {

	// Flags
	version := flag.Bool("v", false, "Prints out the version")
	staticRoutesString := flag.String("static-routes", "", "Comma separated list of static routes to be advertised")
	staticSourcesString := flag.String("static-sources", "", "Comma separated list of host IP addresses or networks from which the static routes will be advertised")
	staticSourcesExcludedString := flag.String("static-sources-excluded", "169.254.0.0/16,127.0.0.0/8", "Comma separated list of host IP addresses or networks that are excluded from route advertisement")
	dockerIpvlanEnable := flag.Bool("docker-ipvlan", false, "Enable advertisement of Docker IPVLAN L3 mode networks")
	dockerIpvlanRefresh := flag.Float64("docker-ipvlan-refresh", 0.2, "Docker API network refresh rate in seconds")
	ripUpdateTimer := flag.Float64("rip-update", 30, "How often the RIP process sends an unsolicited Response message containing the complete routing table")
	ripGCTimer := flag.Float64("rip-gc", 120, "RIP Garbage-collection timer. When it expires, the route is deleted from the routing table.")
	ripUpdateDelay := flag.Float64("rip-update-delay", 0.5, "RIP triggered update delay. RIP update is delayed if a previous update has been sent less than delay seconds ago.")
	ripDeclareUnreachableOnQuit := flag.Bool("rip-unreachable-on-quit", true, "Should process declare all routes unreachable before quitting?")
	logLevelInt := flag.Uint("log-level", 3, "Log level (4 - Debug, 3 - Info, 2 - Warning, 1 - Error, 0 - None)")
	flag.Parse()

	if flag.NFlag() == 0 {
		fmt.Printf("\nRIPster v%s (%s/%s)\nhttps://github.com/jamsix/RIPster\n\n", Ver, runtime.GOOS, runtime.GOARCH)
		fmt.Printf("Help:\n")
		flag.PrintDefaults()
		fmt.Printf("\n")
		os.Exit(0)
	}

	if *version == true {
		fmt.Printf("RIPster v%s (%s/%s)\nhttps://github.com/jamsix/RIPster\n\n", Ver, runtime.GOOS, runtime.GOARCH)
		os.Exit(0)
	}

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
	if *logLevelInt >= 0 || *logLevelInt <= 4 {
		logLevel = *logLevelInt
	} else {
		l.Error("Log level should be between 0 and 4, setting to 3")
		logLevel = 3
	}

	ripv2, _ := ripster.NewRIPv2()
	ripv2.SetTimers(float32(*ripUpdateTimer), float32(*ripUpdateDelay), float32(*ripGCTimer))
	ripv2.LogLevel = logLevel
	go handleLogs(ripv2)

	// Gentlemen, start your Collectors
	if len(staticRoutes) > 0 {
		go addStaticRoutes(ripv2, staticRoutes, staticSources, staticSourcesExcluded)
	}
	if *dockerIpvlanEnable {
		dockerIpvlanCollector, _ := ripster.NewDockerIpvlanCollector(ripv2)
		dockerIpvlanCollector.SetTimers(float32(*dockerIpvlanRefresh))
		dockerIpvlanCollector.LogLevel = logLevel
		go handleLogs(dockerIpvlanCollector)
	}

	// Do nothing unless there is a SIGINT/SIGTERM
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	for sig := range c {
		switch sig {
		case syscall.SIGINT, syscall.SIGTERM:
			if *ripDeclareUnreachableOnQuit == true {
				l.Info("SIGINT/SIGTERM received. Declaring all routes unreachable, than quitting.")
				ripv2.KeepRoutesUponClosure = false
				ripv2.Close()
			} else {
				l.Info("SIGINT/SIGTERM received. Quitting.")
				ripv2.KeepRoutesUponClosure = true
				ripv2.Close()
			}
			os.Exit(0)
		case syscall.SIGHUP:
			// Reload config. If only.
		}
	}

}

// Runs in it's own Goroutine
// Adds preconfigured static routes routers
func addStaticRoutes(ripv2 *ripster.RIPv2, staticRoutes []net.IPNet, staticSources []net.IPNet, staticSourcesExcluded []net.IPNet) {

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

	for _, _ = range parentIPs {
		for _, route := range staticRoutes {
			err := ripv2.AddRoute(ripster.Route{Route:route.String(), AdministrativeDistance:ripster.AdministrativeDistanceStatic})
			if err != nil {
				l.Error(err.Error())
			} else {
				l.Debug("Adding %s (static)", route.String())
			}
		}
	}

}

func handleLogs (logGenerator ripster.LogGeneratorInterface) {
	for {
		logChan := logGenerator.LogChan()
		msg, channelOpen := <-*logChan
		if !channelOpen {
			return
		}
		fmt.Printf(time.Now().Format("2006-01-02 15:04:05 ")+msg)
	}
}

// Logger
type Log struct {
	width  int
	height int
}

func (log *Log) Debug(format string, a ...interface{}) {
	if logLevel >= LogDebug {
		fmt.Printf(time.Now().Format("2006-01-02 15:04:05 ")+"INFO  "+format+"\n", a...)
	}
}
func (log *Log) Info(format string, a ...interface{}) {
	if logLevel >= LogInfo {
		fmt.Printf(time.Now().Format("2006-01-02 15:04:05 ")+"INFO  "+format+"\n", a...)
	}
}
func (log *Log) Error(format string, a ...interface{}) {
	if logLevel >= LogError {
		fmt.Printf(time.Now().Format("2006-01-02 15:04:05 ")+"ERROR "+format+"\n", a...)
	}
}
