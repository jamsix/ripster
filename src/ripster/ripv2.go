package ripster

import (
	"bytes"
	"encoding/binary"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
	"errors"
	"fmt"
)

type RIPv2 struct {
	// When RIPv2 is .Close()ed, advertise all routes as deleted if set to false
	KeepRoutesUponClosure bool
	LogLevel uint
	// Log channel, all RIPv2 logs will be sent to this channel
	Log chan string
	enabled bool
	// Setings
	updateTimer time.Duration
	updateDelay time.Duration
	gcTimer     time.Duration
	// RIP fields
	routeTable RIPv2RouteTable
	// Route Updates are queued in a buffered channel until served by router
	routeUpdates chan RIPv2Route
}

type RIPv2RouteTable struct {
	sync.RWMutex
	Routes []RIPv2Route
}

type RIPv2Route struct {
	Updated time.Time
	Route   net.IPNet
	NextHop net.IP
	Metric int
	AddressFamilyIdentifier uint16
	RouteTag                uint16
	AdministrativeDistance  uint8
	Best bool
	Deleted bool
}

type Route struct {
	Route   string
	NextHop string
	Metric int
	AddressFamilyIdentifier uint16
	RouteTag                uint16
	AdministrativeDistance  uint8
}

const (
	RIPv2DefaultUpdateTimer = 30.0  // in seconds
	RIPv2DefaultUpdateDelay = 0.1 // in seconds
	RIPv2DefaultGCTimer     = 180.0 // in seconds
	RIPv2MinUpdateTimer = 0.1  // in seconds
	RIPv2MinUpdateDelay = 0.01 // in seconds
	RIPv2MinGCTimer     = 0.1 // in seconds
	RIPv2MaxUpdateTimer = 3600.0  // in seconds
	RIPv2MaxUpdateDelay = 3600.0 // in seconds
	RIPv2MaxGCTimer     = 3600.0 // in seconds
	RIPv2DefaultMetric      = 1
	RIPv2InfiniteMetric = 16
	RIPv2DefaultTag         = 0
	RIPv2DefaultAddressFamilyIdentifier = 2
	RIPv2DefaultAdministrativeDistance = 1
)

var ripv2 RIPv2

func NewRIPv2() (*RIPv2, error) {

	// There can be only one RIPv2 instance
	if ripv2.enabled == true {
		return &ripv2, errors.New("RIPv2 router is already running")
	}

	ripv2.enabled = true
	ripv2.updateTimer = time.Duration(int(RIPv2DefaultUpdateTimer*1000)) * time.Millisecond
	ripv2.updateDelay = time.Duration(int(RIPv2DefaultUpdateDelay*1000)) * time.Millisecond
	ripv2.gcTimer = time.Duration(int(RIPv2DefaultGCTimer*1000)) * time.Millisecond

	ripv2.routeUpdates = make(chan RIPv2Route, 100)

	ripv2.Log = make(chan string, 100)

	go ripv2.router()

	return &ripv2, nil

}

func (RIPv2 RIPv2) AddRoute(route interface{}) error {

		var ripv2route RIPv2Route

    _, ok := route.(Route)
		if ok {
			// Passed route parameter is of type Route
			_, ipNet, err := net.ParseCIDR(route.(Route).Route)
			if err == nil {
				ripv2route.Route = *ipNet
			} else {
				return errors.New(fmt.Sprintf("RIPv2 add route: route parameter must be in CIDR notation, i.e.: 10.10.10.0/24"))
			}
			if route.(Route).NextHop != "" {
				ip := net.ParseIP(route.(Route).NextHop)
				if ip != nil && ip.To4() != nil {
					ripv2route.NextHop = ip
				} else {
					return errors.New(fmt.Sprintf("RIPv2 add route: next hop parameter must be a valid IPv4 address, i.e.: 10.10.10.1"))
				}
			}
			if route.(Route).Metric != 0 {
				ripv2route.Metric = route.(Route).Metric
			} else {
				ripv2route.Metric = RIPv2DefaultMetric
			}
			if route.(Route).AddressFamilyIdentifier != 0 {
				ripv2route.AddressFamilyIdentifier = route.(Route).AddressFamilyIdentifier
			} else {
				ripv2route.AddressFamilyIdentifier = RIPv2DefaultAddressFamilyIdentifier
			}
			if route.(Route).RouteTag != 0 {
				ripv2route.RouteTag = route.(Route).RouteTag
			} else {
				ripv2route.RouteTag = RIPv2DefaultTag
			}
			if route.(Route).AdministrativeDistance != 0 {
				ripv2route.AdministrativeDistance = route.(Route).AdministrativeDistance
			} else {
				ripv2route.AdministrativeDistance = RIPv2DefaultAdministrativeDistance
			}
			ripv2route.Updated = time.Now()
		} else {
			_, ok = route.(string)
			if ok {
				// Passed route parameter is a string
				_, ipNet, err := net.ParseCIDR(route.(string))
				if err == nil {
					ripv2route.Route = *ipNet
					ripv2route.Metric = RIPv2DefaultMetric
					ripv2route.AddressFamilyIdentifier = RIPv2DefaultAddressFamilyIdentifier
					ripv2route.RouteTag = RIPv2DefaultTag
					ripv2route.AdministrativeDistance = RIPv2DefaultAdministrativeDistance
					ripv2route.Updated = time.Now()
				} else {
					return errors.New(fmt.Sprintf("RIPv2 add route: route parameter must be in CIDR notation, i.e.: 10.10.20.0/24"))
				}
			} else {
				return errors.New(fmt.Sprintf("RIPv2 add route: route parameter must be a Route struct or a string"))
			}
		}

		ripv2.routeUpdates <- ripv2route

		return nil

}

func (RIPv2 RIPv2) RemoveRoute(route interface{}) error {

		var ripv2route RIPv2Route

    _, ok := route.(Route)
		if ok {
			// Passed route parameter is of type Route
			_, ipNet, err := net.ParseCIDR(route.(Route).Route)
			if err == nil {
				ripv2route.Route = *ipNet
			} else {
				return errors.New(fmt.Sprintf("Route remove route: route parameter must be in CIDR notation, i.e.: 10.10.10.0/24"))
			}
			ip := net.ParseIP(route.(Route).NextHop)
			if ip != nil && ip.To4() != nil {
				ripv2route.NextHop = ip
			} else {
				return errors.New(fmt.Sprintf("RIPv2 remove route: next hop parameter must be a valid IPv4 address, i.e.: 10.10.10.1"))
			}
			ripv2route.Metric = RIPv2InfiniteMetric
			if route.(Route).AddressFamilyIdentifier != 0 {
				ripv2route.AddressFamilyIdentifier = route.(Route).AddressFamilyIdentifier
			} else {
				ripv2route.AddressFamilyIdentifier = RIPv2DefaultAddressFamilyIdentifier
			}
			if route.(Route).RouteTag != 0 {
				ripv2route.RouteTag = route.(Route).RouteTag
			} else {
				ripv2route.RouteTag = RIPv2DefaultTag
			}
			if route.(Route).AdministrativeDistance != 0 {
				ripv2route.AdministrativeDistance = route.(Route).AdministrativeDistance
			} else {
				ripv2route.AdministrativeDistance = RIPv2DefaultAdministrativeDistance
			}
			ripv2route.Updated = time.Now()
			ripv2route.Deleted = true
		} else {
			_, ok = route.(string)
			if ok {
				// Passed route parameter is a string
				_, ipNet, err := net.ParseCIDR(route.(string))
				if err == nil {
					ripv2route.Route = *ipNet
					ripv2route.Metric = RIPv2DefaultMetric
					ripv2route.AddressFamilyIdentifier = RIPv2DefaultAddressFamilyIdentifier
					ripv2route.RouteTag = RIPv2DefaultTag
					ripv2route.AdministrativeDistance = RIPv2DefaultAdministrativeDistance
					ripv2route.Updated = time.Now()
					ripv2route.Deleted = true
				} else {
					return errors.New(fmt.Sprintf("RIPv2 remove route: route parameter must be in CIDR notation, i.e.: 10.10.20.0/24"))
				}
			} else {
				return errors.New(fmt.Sprintf("RIPv2 remove route: route parameter must be a Route struct or a string"))
			}
		}

		ripv2.routeUpdates <- ripv2route

		return nil

}

func (RIPv2 *RIPv2) SetTimers(update, updateDelay, gc float32) error {

	if update < RIPv2MinUpdateTimer || update > RIPv2MaxUpdateTimer {
		return errors.New(fmt.Sprintf("RIPv2 Update timer should be between %.f and %.f", RIPv2MinUpdateTimer, RIPv2MaxUpdateTimer))
	} else if updateDelay < RIPv2MinUpdateDelay || updateDelay > RIPv2MaxUpdateDelay {
		return errors.New(fmt.Sprintf("RIPv2 Update delay timer should be between %.f and %.f", RIPv2MinUpdateDelay, RIPv2MaxUpdateDelay))
	} else if gc < RIPv2MinGCTimer || gc > RIPv2MaxGCTimer {
		return errors.New(fmt.Sprintf("RIPv2 GC timer should be between %.f and %.f", RIPv2MinGCTimer, RIPv2MaxGCTimer))
	}

	RIPv2.updateTimer = time.Duration(int(update*1000)) * time.Millisecond
	RIPv2.updateDelay = time.Duration(int(updateDelay*1000)) * time.Millisecond
	RIPv2.gcTimer = time.Duration(int(gc*1000)) * time.Millisecond

	return nil

}

func (RIPv2 *RIPv2) Close() {

		// Close routeUpdates channel. RIPv2.router() routine will quit upon channel closure.
		close(RIPv2.routeUpdates)

		// Advertise all remaining routes as deleted before quitting
		RIPv2.logInfo("RIPv2 stopping router")
		if !RIPv2.KeepRoutesUponClosure {
			RIPv2.routeTable.Lock()
			for key, _ := range RIPv2.routeTable.Routes {
				RIPv2.routeTable.Routes[key].Updated = time.Now()
				RIPv2.routeTable.Routes[key].Deleted = true
			}
			RIPv2.routeTable.Unlock()
		}
		RIPv2.sendFullUpdate()

	RIPv2.enabled = false
	RIPv2.routeTable = RIPv2RouteTable{}

}

func (RIPv2 *RIPv2) LogChan() *chan string {
	return &RIPv2.Log
}


func (RIPv2 *RIPv2) router() {

	RIPv2.logInfo("RIPv2 starting router")

	lastUpdate := time.Now().Add(-time.Hour)
	lastFullUpdate := time.Now().Add(-time.Hour)

	for {
		// All routeTable routes are advertised with regular updates every updateTimer
		// (defaults to 30s). Whenever there is a change in routeTable, a triggered
		// update is sent immediately, or, if an update has been just sent, after
		// a triggeredUpdateDelay
		nextFullUpdate := lastFullUpdate.Add(RIPv2.updateTimer)
		timeToNextFullUpdate := -time.Since(nextFullUpdate)
		select {

		case routeUpdate, channelOpen := <-RIPv2.routeUpdates:
			routeUpdates := []RIPv2Route{}
			routeUpdates = append(routeUpdates, routeUpdate)
			if !channelOpen {
				// RIPv2.routeUpdates channel is closed, there will be no more updates, exit router()
				return
			}
			if lastUpdate.Add(RIPv2.updateDelay).After(time.Now()) {
				sleepDelay := RIPv2.updateDelay - time.Since(lastUpdate)
				RIPv2.logDebug("RIPv2 triggered update throttled, sleeping for %f seconds", sleepDelay.Seconds())
				time.Sleep(sleepDelay)
			}
			if len(RIPv2.routeUpdates) > 0 {
				// There are more routeUpdates in the queue
				for n := 0; n < len(RIPv2.routeUpdates); n++ {
					routeUpdate = <-RIPv2.routeUpdates
					routeUpdates = append(routeUpdates, routeUpdate)
				}
			}
			RIPv2.addUpdatesToRouteTable(routeUpdates)
			RIPv2.logDebug("RIPv2 triggered partial update")
			RIPv2.sendPartialUpdate(routeUpdates)

		case <-time.After(timeToNextFullUpdate):
			RIPv2.logDebug("RIPv2 regular update")
			RIPv2.sendFullUpdate()
			lastFullUpdate = time.Now()

		}
		lastUpdate = time.Now()
	}

}

func (RIPv2 *RIPv2) addUpdatesToRouteTable(routeUpdates []RIPv2Route) {

	RIPv2.routeTable.Lock()
	for _, routeUpdate := range routeUpdates {
		// If a route with the same Route, AddressFamily and AdministrativeDistance
		// already exists in the routing table, it should be replaced with the
		// updated route
		var routeReplaced bool
		for i, routeTableEntry := range RIPv2.routeTable.Routes {
			if RIPv2.isSameRouteSameAD(routeUpdate, routeTableEntry) {
				RIPv2.routeTable.Routes[i] = routeUpdate
				routeReplaced = true
				break
			}
		}
		if !routeReplaced {
			RIPv2.routeTable.Routes = append(RIPv2.routeTable.Routes, routeUpdate)
		}
		// There might be multiple same routes with different AdministrativeDistances
		// In that case route with the lowest AdministrativeDistance is considered Best
		for i, iRoute := range RIPv2.routeTable.Routes {
			best := i
			for j, jRoute := range RIPv2.routeTable.Routes {
				if RIPv2.isSameRoute(iRoute, jRoute) {
					if iRoute.AdministrativeDistance == jRoute.AdministrativeDistance {
						if iRoute.Updated.Before(jRoute.Updated) {
							best = j
						}
					} else if iRoute.AdministrativeDistance > jRoute.AdministrativeDistance {
						best = j
					}
				}
			}
			if best == i {
				RIPv2.routeTable.Routes[i].Best = true
			} else {
				RIPv2.routeTable.Routes[i].Best = false
			}
		}
	}
	RIPv2.routeTable.Unlock()

}

func (RIPv2 *RIPv2) sendPartialUpdate(updateRoutes []RIPv2Route) {

	// If there is a same route with lower AdministrativeDistance in the routeTable,
	// do not advertise it in a partial update
	RIPv2.routeTable.RLock()
	for i := len(updateRoutes) - 1; i >= 0; i-- {
		for _, tableRoute := range RIPv2.routeTable.Routes {
			if RIPv2.isSameRoute(updateRoutes[i], tableRoute) &&
				updateRoutes[i].AdministrativeDistance > tableRoute.AdministrativeDistance &&
				tableRoute.Deleted == false {
				updateRoutes = append(updateRoutes[:i], updateRoutes[i+1:]...)
			}
		}
	}
	RIPv2.routeTable.RUnlock()

	// There might be multiple same routes with different AdministrativeDistances
	// In that case route with the lowest AdministrativeDistance is considered Best
	for i, iRoute := range updateRoutes {
		best := i
		for j, jRoute := range updateRoutes {
			if RIPv2.isSameRoute(iRoute, jRoute) {
				if iRoute.AdministrativeDistance == jRoute.AdministrativeDistance {
					if iRoute.Updated.Before(jRoute.Updated) {
						best = j
					}
				} else if iRoute.AdministrativeDistance > jRoute.AdministrativeDistance {
					best = j
				}
			}
		}
		if best == i {
			updateRoutes[i].Best = true
		} else {
			updateRoutes[i].Best = false
		}
	}

	RIPv2.sendUpdate(&updateRoutes)

}

func (RIPv2 RIPv2) sendFullUpdate() {

	RIPv2.collectGarbageRoutes()
	RIPv2.sendUpdate(&RIPv2.routeTable.Routes)

}

func (RIPv2 *RIPv2) collectGarbageRoutes() {

	var routesString string

	RIPv2.routeTable.Lock()
	for i := len(RIPv2.routeTable.Routes) - 1; i >= 0; i-- {
		// Condition to decide if current element has to be deleted:
		if RIPv2.routeTable.Routes[i].Deleted && time.Since(RIPv2.routeTable.Routes[i].Updated) > RIPv2.gcTimer {
			routesString = routesString + ", " + RIPv2.routeTable.Routes[i].Route.String() + " (next hop " + RIPv2.routeTable.Routes[i].NextHop.String() + ")"
			RIPv2.routeTable.Routes = append(RIPv2.routeTable.Routes[:i], RIPv2.routeTable.Routes[i+1:]...)
		}
	}
	RIPv2.routeTable.Unlock()

	if len(routesString) > 1 {
		RIPv2.logDebug("RIPv2 garbage collecting routes: %s", routesString[2:])
	}

}

// sendIpv4RipMessage sends out the RIPv2 Unsolicited routing update message,
// multicasted from each of the parentIP addreses.
func (RIPv2 *RIPv2) sendUpdate(routes *[]RIPv2Route) {

	// RIPv2 message structures, as per RFC2453, 4. Protocol Extensions
	type RIPv2Header struct {
		Command uint8
		Version uint8
		Unused  uint16
	}
	type RIPv2RouteEntry struct {
		AddressFamilyIdentifier uint16
		RouteTag                uint16
		IPAddress               uint32
		SubnetMask              uint32
		NextHop                 uint32
		Metric                  uint32
	}

	var parentIPs []net.IP

	RIPv2.routeTable.RLock()
	if len(*routes) == 0 {
		RIPv2.logInfo("RIPv2 has no routes to advertise")
		return
	}
	RIPv2.routeTable.RUnlock()

	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		if strings.ToLower(iface.Name)[0:2] != "lo" {
			addrs, _ := iface.Addrs()
			for _, addr := range addrs {
				ip, _, err := net.ParseCIDR(addr.String())
				if err != nil {
					//
				} else if ip.To4() == nil {
					// This is not an IPv4 address
				} else {
					parentIPs = append(parentIPs, ip.To4())
				}
			}
			continue
		}
	}

	for _, parentIP := range parentIPs {
		localAddr, err := net.ResolveUDPAddr("udp4", parentIP.String()+":520")
		if err != nil {
			RIPv2.logError("RIPv2 resolution error %v", err)
			return
		}
		remoteEP, _ := net.ResolveUDPAddr("udp4", "224.0.0.9:520")
		conn, err := net.DialUDP("udp4", localAddr, remoteEP)
		if err != nil {
			RIPv2.logError("RIPv2 connection error %v", err)
			return
		}

		ripHeader := new(RIPv2Header)
		ripHeader.Command = 2
		ripHeader.Version = 2
		var buf bytes.Buffer
		binary.Write(&buf, binary.BigEndian, ripHeader)

		routeStr := ""
		needsToBeWritten := false
		n := 0

		RIPv2.routeTable.RLock()
		for _, routeTableEntry := range *routes {
			if routeTableEntry.Best == false {
				continue
			}
			route := new(RIPv2RouteEntry)
			route.AddressFamilyIdentifier = 2
			route.IPAddress = binary.BigEndian.Uint32(routeTableEntry.Route.IP)
			route.SubnetMask = binary.BigEndian.Uint32(routeTableEntry.Route.Mask)
			if routeTableEntry.Deleted == true {
				// Deleted routes younger than gcTimer are advertised with:
				route.Metric = 16
			} else {
				route.Metric = uint32(routeTableEntry.Metric)
			}
			route.RouteTag = routeTableEntry.RouteTag

			// If NextHop is nil, leave NextHop set to 0. Receiving RIP router will
			// use sender's IP address as the NextHop.
			if routeTableEntry.NextHop != nil {
				if routeTableEntry.NextHop.To4() != nil {
					route.NextHop = binary.BigEndian.Uint32(routeTableEntry.NextHop.To4())
				}
			}

			binary.Write(&buf, binary.BigEndian, route)
			maskOnes, _ := routeTableEntry.Route.Mask.Size()
			routeStr = routeStr + "" + routeTableEntry.Route.IP.String() + "/" +
				strconv.FormatUint(uint64(maskOnes), 10) + " ("
			if routeTableEntry.NextHop != nil {
				routeStr = routeStr + "next hop " + routeTableEntry.NextHop.String() + ", "
			}
			routeStr = routeStr + "metric " + strconv.FormatUint(uint64(route.Metric), 10) + "), "

			// RFC2453 prescribes no more than 25 RTEs per UDP datagram
			// Send out an UDP datagram every 25 RTEs
			if n%25 == 24 {
				conn.Write(buf.Bytes())
				ripHeader = new(RIPv2Header)
				ripHeader.Command = 2
				ripHeader.Version = 2
				buf.Reset()
				binary.Write(&buf, binary.BigEndian, ripHeader)
				needsToBeWritten = false
			} else {
				needsToBeWritten = true
			}
			n++
		}
		RIPv2.routeTable.RUnlock()

		if needsToBeWritten {
			conn.Write(buf.Bytes())
		}
		conn.Close()

		if len(routeStr) > 1 {
			routeStr = routeStr[0:len(routeStr)-2]
		}
		RIPv2.logInfo("RIPv2 advertising routes from %s: %s", parentIP, routeStr)
	}
}

func (RIPv2 RIPv2) isSameRouteSameAD(r1, r2 RIPv2Route) bool {
	if RIPv2.isSameRoute(r1, r2) && r1.AdministrativeDistance == r2.AdministrativeDistance {
		return true
	} else {
		return false
	}
}

func (RIPv2 RIPv2) isSameRoute(r1, r2 RIPv2Route) bool {
	if (r1.Route.Contains(r2.Route.IP) && r2.Route.Contains(r1.Route.IP)) &&
		r1.AddressFamilyIdentifier == r2.AddressFamilyIdentifier {
		return true
	} else {
		return false
	}
}

func (RIPv2 *RIPv2) log(msg string) {
	select {
	case RIPv2.Log <- msg+"\n":
  	default:
  }
}

func (RIPv2 *RIPv2) logDebug(format string, a ...interface{}) {
	if RIPv2.LogLevel >= LogDebug {
		RIPv2.log(fmt.Sprintf("DEBUG "+format, a...))
	}
}
func (RIPv2 *RIPv2) logInfo(format string, a ...interface{}) {
	if RIPv2.LogLevel >= LogInfo {
		RIPv2.log(fmt.Sprintf("INFO  "+format, a...))
	}
}
func (RIPv2 *RIPv2) logWarn(format string, a ...interface{}) {
	if RIPv2.LogLevel >= LogWarning {
		RIPv2.log(fmt.Sprintf("WARN  "+format, a...))
	}
}
func (RIPv2 *RIPv2) logError(format string, a ...interface{}) {
	if RIPv2.LogLevel >= LogError {
		RIPv2.log(fmt.Sprintf("ERROR "+format, a...))
	}
}
