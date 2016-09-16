package ripster

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"
)

type RIPv2 struct {
	LogLevel uint
	// Log channel, all RIPv2 logs will be sent to this channel
	Log     chan string
	enabled bool
	// Setings
	updateTimer time.Duration
	updateDelay time.Duration
	gcTimer     time.Duration
	// RIP fields
	routeTable RIPv2RouteTable
	// Route Updates are queued in a buffered channel until served by router
	routeUpdates chan RIPv2Route
	// When RIPv2 is .Close()ed, advertise all routes as deleted if set to false
	keepRoutesUponClosure bool
}

type RIPv2RouteTable struct {
	sync.RWMutex
	Routes []RIPv2Route
}

type RIPv2Route struct {
	Updated                 time.Time
	Route                   net.IPNet
	NextHop                 net.IP
	Metric                  int
	AddressFamilyIdentifier uint16
	RouteTag                uint16
	AdministrativeDistance  uint8
	Best                    bool
	Deleted                 bool
}

const (
	RIPv2DefaultUpdateTimer             = 30.0   // in seconds
	RIPv2DefaultUpdateDelay             = 0.1    // in seconds
	RIPv2DefaultGCTimer                 = 180.0  // in seconds
	RIPv2MinUpdateTimer                 = 0.1    // in seconds
	RIPv2MinUpdateDelay                 = 0.01   // in seconds
	RIPv2MinGCTimer                     = 0.1    // in seconds
	RIPv2MaxUpdateTimer                 = 3600.0 // in seconds
	RIPv2MaxUpdateDelay                 = 3600.0 // in seconds
	RIPv2MaxGCTimer                     = 3600.0 // in seconds
	RIPv2DefaultMetric                  = 1
	RIPv2InfiniteMetric                 = 16
	RIPv2DefaultTag                     = 0
	RIPv2DefaultAddressFamilyIdentifier = 2
	RIPv2DefaultAdministrativeDistance  = 1
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

func (rip RIPv2) AddRoute(route interface{}) error {

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
		if ipNet.IP.To4() == nil {
			return errors.New(fmt.Sprintf("RIPv2 add route: route parameter must be an IPv4 CIDR notation, i.e.: 10.10.10.0/24"))
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

func (rip RIPv2) RemoveRoute(route interface{}) error {

	var ripv2route RIPv2Route

	_, ok := route.(Route)
	if ok {
		// Passed route parameter is of type Route
		_, ipNet, err := net.ParseCIDR(route.(Route).Route)
		if err == nil {
			ripv2route.Route = *ipNet
		} else {
			return errors.New(fmt.Sprintf("RIPv2 remove route: route parameter must be in CIDR notation, i.e.: 10.10.10.0/24"))
		}
		if ipNet.IP.To4() == nil {
			return errors.New(fmt.Sprintf("RIPv2 remove route: route parameter must be an IPv4 CIDR notation, i.e.: 10.10.10.0/24"))
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

func (rip *RIPv2) SetTimers(update, updateDelay, gc float32) error {

	if update < RIPv2MinUpdateTimer || update > RIPv2MaxUpdateTimer {
		return errors.New(fmt.Sprintf("RIPv2 Update timer should be between %.f and %.f", RIPv2MinUpdateTimer, RIPv2MaxUpdateTimer))
	} else if updateDelay < RIPv2MinUpdateDelay || updateDelay > RIPv2MaxUpdateDelay {
		return errors.New(fmt.Sprintf("RIPv2 Update delay timer should be between %.f and %.f", RIPv2MinUpdateDelay, RIPv2MaxUpdateDelay))
	} else if gc < RIPv2MinGCTimer || gc > RIPv2MaxGCTimer {
		return errors.New(fmt.Sprintf("RIPv2 GC timer should be between %.f and %.f", RIPv2MinGCTimer, RIPv2MaxGCTimer))
	}

	rip.updateTimer = time.Duration(int(update*1000)) * time.Millisecond
	rip.updateDelay = time.Duration(int(updateDelay*1000)) * time.Millisecond
	rip.gcTimer = time.Duration(int(gc*1000)) * time.Millisecond

	return nil

}

// Setter, because RIPv2 fields cannot be exposed through the RouterInterface
func (rip *RIPv2) KeepRoutesUponClosure(b bool) {
	rip.keepRoutesUponClosure = b
}

func (rip *RIPv2) Close() {

	// Close routeUpdates channel. rip.router() routine will quit upon channel closure.
	close(rip.routeUpdates)

	// Advertise all remaining routes as deleted before quitting
	rip.logInfo("RIPv2 stopping router")
	if !rip.keepRoutesUponClosure {
		rip.routeTable.Lock()
		for key, _ := range rip.routeTable.Routes {
			rip.routeTable.Routes[key].Updated = time.Now()
			rip.routeTable.Routes[key].Deleted = true
		}
		rip.routeTable.Unlock()
	}

	rip.sendFullUpdate()

	rip.enabled = false
	rip.routeTable = RIPv2RouteTable{}

}

func (rip *RIPv2) LogChan() *chan string {
	return &rip.Log
}

func (rip *RIPv2) router() {

	rip.logInfo("RIPv2 starting router")

	lastUpdate := time.Now().Add(-time.Hour)
	lastFullUpdate := time.Now().Add(-time.Hour)

	for {
		// All routeTable routes are advertised with regular updates every updateTimer
		// (defaults to 30s). Whenever there is a change in routeTable, a triggered
		// update is sent immediately, or, if an update has been just sent, after
		// a triggeredUpdateDelay
		nextFullUpdate := lastFullUpdate.Add(rip.updateTimer)
		timeToNextFullUpdate := -time.Since(nextFullUpdate)
		select {

		case routeUpdate, channelOpen := <-rip.routeUpdates:
			routeUpdates := []RIPv2Route{}
			routeUpdates = append(routeUpdates, routeUpdate)
			if !channelOpen {
				// rip.routeUpdates channel is closed, there will be no more updates, exit router()
				return
			}
			if lastUpdate.Add(rip.updateDelay).After(time.Now()) {
				sleepDelay := rip.updateDelay - time.Since(lastUpdate)
				rip.logDebug("RIPv2 triggered update throttled, sleeping for %f seconds", sleepDelay.Seconds())
				time.Sleep(sleepDelay)
			}
			if len(rip.routeUpdates) > 0 {
				// There are more routeUpdates in the queue
				for n := 0; n < len(rip.routeUpdates); n++ {
					routeUpdate = <-rip.routeUpdates
					routeUpdates = append(routeUpdates, routeUpdate)
				}
			}
			rip.addUpdatesToRouteTable(routeUpdates)
			rip.logDebug("RIPv2 triggered partial update")
			rip.sendPartialUpdate(routeUpdates)

		case <-time.After(timeToNextFullUpdate):
			rip.logDebug("RIPv2 regular update")
			rip.sendFullUpdate()
			lastFullUpdate = time.Now()

		}
		lastUpdate = time.Now()
	}

}

func (rip *RIPv2) addUpdatesToRouteTable(routeUpdates []RIPv2Route) {

	rip.routeTable.Lock()
	for _, routeUpdate := range routeUpdates {
		// If a route with the same Route, AddressFamily and AdministrativeDistance
		// already exists in the routing table, it should be replaced with the
		// updated route
		var routeReplaced bool
		for i, routeTableEntry := range rip.routeTable.Routes {
			if rip.isSameRouteSameAD(routeUpdate, routeTableEntry) {
				rip.routeTable.Routes[i] = routeUpdate
				routeReplaced = true
				break
			}
		}
		if !routeReplaced {
			rip.routeTable.Routes = append(rip.routeTable.Routes, routeUpdate)
		}
		// There might be multiple same routes with different AdministrativeDistances
		// In that case route with the lowest AdministrativeDistance is considered Best
		for i, iRoute := range rip.routeTable.Routes {
			best := i
			for j, jRoute := range rip.routeTable.Routes {
				if rip.isSameRoute(iRoute, jRoute) {
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
				rip.routeTable.Routes[i].Best = true
			} else {
				rip.routeTable.Routes[i].Best = false
			}
		}
	}
	rip.routeTable.Unlock()

}

func (rip *RIPv2) sendPartialUpdate(updateRoutes []RIPv2Route) {

	// If there is a same route with lower AdministrativeDistance in the routeTable,
	// do not advertise it in a partial update
	rip.routeTable.RLock()
	for i := len(updateRoutes) - 1; i >= 0; i-- {
		for _, tableRoute := range rip.routeTable.Routes {
			if rip.isSameRoute(updateRoutes[i], tableRoute) &&
				updateRoutes[i].AdministrativeDistance > tableRoute.AdministrativeDistance &&
				tableRoute.Deleted == false {
				updateRoutes = append(updateRoutes[:i], updateRoutes[i+1:]...)
				break
			}
		}
	}
	rip.routeTable.RUnlock()

	// There might be multiple same routes with different AdministrativeDistances
	// In that case route with the lowest AdministrativeDistance is considered Best
	for i, iRoute := range updateRoutes {
		best := i
		for j, jRoute := range updateRoutes {
			if rip.isSameRoute(iRoute, jRoute) {
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

	rip.routeTable.RLock()
	updateLen := len(updateRoutes)
	rip.routeTable.RUnlock()

	if updateLen == 0 {
		rip.logDebug("RIPv2 partial update has no best routes to advertise")
	} else {
		rip.sendUpdate(&updateRoutes)
	}

}

func (rip RIPv2) sendFullUpdate() {

	rip.collectGarbageRoutes()
	rip.sendUpdate(&rip.routeTable.Routes)

}

func (rip *RIPv2) collectGarbageRoutes() {

	var routesStr string

	rip.routeTable.Lock()
	for i := len(rip.routeTable.Routes) - 1; i >= 0; i-- {
		// Condition to decide if current element has to be deleted:
		if rip.routeTable.Routes[i].Deleted && time.Since(rip.routeTable.Routes[i].Updated) > rip.gcTimer {
			routesStr = routesStr + ", " + rip.routeTable.Routes[i].Route.String()
			if rip.routeTable.Routes[i].NextHop != nil {
				routesStr = routesStr + " (next hop " + rip.routeTable.Routes[i].NextHop.String() + ")"
			}
			rip.routeTable.Routes = append(rip.routeTable.Routes[:i], rip.routeTable.Routes[i+1:]...)
		}
	}
	rip.routeTable.Unlock()

	if len(routesStr) > 1 {
		rip.logDebug("RIPv2 garbage collecting routes: %s", routesStr[2:])
	}

}

// sendIpv4RipMessage sends out the RIPv2 Unsolicited routing update message,
// multicasted from each of the IP addreses.
func (rip *RIPv2) sendUpdate(routes *[]RIPv2Route) {

	// RIPv2 message structures, as per RFC2453, 4. Protocol Extensions
	type RIPv2Header struct {
		Command uint8
		Version uint8
		Unused  uint16
	}
	type RIPv2RTE struct {
		AddressFamilyIdentifier uint16
		RouteTag                uint16
		IPAddress               uint32
		SubnetMask              uint32
		NextHop                 uint32
		Metric                  uint32
	}

	rip.routeTable.RLock()
	routesLen := len(*routes)
	rip.routeTable.RUnlock()
	if routesLen == 0 {
		rip.logInfo("RIPv2 has no routes to advertise")
		return
	}

	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			ip, _, err := net.ParseCIDR(addr.String())
			if err != nil {
				//
			} else if ip.To4() == nil {
				// This is not an IPv4 address
			} else if ip.IsLoopback() {
				// Not advertising on loopbacks
			} else {
				localAddr, err := net.ResolveUDPAddr("udp4", ip.String()+":520")
				if err != nil {
					rip.logError("RIPv2 local address resolution error %v", err)
					return
				}
				remoteEP, _ := net.ResolveUDPAddr("udp4", "224.0.0.9:520")
				conn, err := net.DialUDP("udp4", localAddr, remoteEP)
				if err != nil {
					rip.logError("RIPv2 remote address connection error %v", err)
					return
				}

				ripHeader := new(RIPv2Header)
				ripHeader.Command = 2
				ripHeader.Version = 2
				var buf bytes.Buffer
				binary.Write(&buf, binary.BigEndian, ripHeader)

				var routeStr string
				var needsToBeWritten bool
				n := 0

				rip.routeTable.RLock()
				for _, routeTableEntry := range *routes {
					if routeTableEntry.Best == false {
						continue
					}
					route := new(RIPv2RTE)
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
					routeStr = routeStr + ", " + routeTableEntry.Route.IP.String() + "/" +
						strconv.FormatUint(uint64(maskOnes), 10) + " ("
					if routeTableEntry.NextHop != nil {
						routeStr = routeStr + "next hop " + routeTableEntry.NextHop.String() + ", "
					}
					routeStr = routeStr + "metric " + strconv.FormatUint(uint64(route.Metric), 10) + ")"

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
				rip.routeTable.RUnlock()

				if needsToBeWritten {
					conn.Write(buf.Bytes())
				}
				conn.Close()

				if len(routeStr) > 1 {
					routeStr = routeStr[2:]
				}
				rip.logInfo("RIPv2 advertising from %s: %s", ip.String(), routeStr)
			}
		}
	}

}

func (rip RIPv2) isSameRouteSameAD(r1, r2 RIPv2Route) bool {
	if rip.isSameRoute(r1, r2) && r1.AdministrativeDistance == r2.AdministrativeDistance {
		return true
	} else {
		return false
	}
}

func (rip RIPv2) isSameRoute(r1, r2 RIPv2Route) bool {
	if (r1.Route.Contains(r2.Route.IP) && r2.Route.Contains(r1.Route.IP)) &&
		r1.AddressFamilyIdentifier == r2.AddressFamilyIdentifier {
		return true
	} else {
		return false
	}
}

func (rip *RIPv2) log(msg string) {
	select {
	case rip.Log <- msg + "\n":
	default:
	}
}

func (rip *RIPv2) logDebug(format string, a ...interface{}) {
	if rip.LogLevel >= LogDebug {
		rip.log(fmt.Sprintf("DEBUG "+format, a...))
	}
}
func (rip *RIPv2) logInfo(format string, a ...interface{}) {
	if rip.LogLevel >= LogInfo {
		rip.log(fmt.Sprintf("INFO  "+format, a...))
	}
}
func (rip *RIPv2) logWarn(format string, a ...interface{}) {
	if rip.LogLevel >= LogWarning {
		rip.log(fmt.Sprintf("WARN  "+format, a...))
	}
}
func (rip *RIPv2) logError(format string, a ...interface{}) {
	if rip.LogLevel >= LogError {
		rip.log(fmt.Sprintf("ERROR "+format, a...))
	}
}
