package ripster

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"
)

type RIPng struct {
	LogLevel uint
	// Log channel, all RIPng logs will be sent to this channel
	Log     chan string
	enabled bool
	// Setings
	updateTimer time.Duration
	updateDelay time.Duration
	gcTimer     time.Duration
	// RIP fields
	routeTable RIPngRouteTable
	// Route Updates are queued in a buffered channel until served by router
	routeUpdates chan RIPngRoute
	// When RIPng is .Close()ed, advertise all routes as deleted if set to false
	keepRoutesUponClosure bool
}

type RIPngRouteTable struct {
	sync.RWMutex
	Routes []RIPngRoute
}

type RIPngRoute struct {
	Updated                time.Time
	Route                  net.IPNet
	NextHop                net.IP
	Metric                 int
	RouteTag               uint16
	AdministrativeDistance uint8
	Best                   bool
	Deleted                bool
}

const (
	RIPngDefaultUpdateTimer            = 30.0   // in seconds
	RIPngDefaultUpdateDelay            = 0.1    // in seconds
	RIPngDefaultGCTimer                = 180.0  // in seconds
	RIPngMinUpdateTimer                = 0.1    // in seconds
	RIPngMinUpdateDelay                = 0.01   // in seconds
	RIPngMinGCTimer                    = 0.1    // in seconds
	RIPngMaxUpdateTimer                = 3600.0 // in seconds
	RIPngMaxUpdateDelay                = 3600.0 // in seconds
	RIPngMaxGCTimer                    = 3600.0 // in seconds
	RIPngDefaultMetric                 = 1
	RIPngInfiniteMetric                = 16
	RIPngDefaultTag                    = 0
	RIPngDefaultAdministrativeDistance = 1
)

var ripNg RIPng

func NewRIPng() (*RIPng, error) {

	// There can be only one RIPng instance
	if ripNg.enabled == true {
		return &ripNg, errors.New("RIPng router is already running")
	}

	ripNg.enabled = true
	ripNg.updateTimer = time.Duration(int(RIPngDefaultUpdateTimer*1000)) * time.Millisecond
	ripNg.updateDelay = time.Duration(int(RIPngDefaultUpdateDelay*1000)) * time.Millisecond
	ripNg.gcTimer = time.Duration(int(RIPngDefaultGCTimer*1000)) * time.Millisecond

	ripNg.routeUpdates = make(chan RIPngRoute, 100)

	ripNg.Log = make(chan string, 100)

	go ripNg.router()

	return &ripNg, nil

}

func (rip RIPng) AddRoute(route interface{}) error {

	var ripNgroute RIPngRoute

	_, ok := route.(Route)
	if ok {
		// Passed route parameter is of type Route
		_, ipNet, err := net.ParseCIDR(route.(Route).Route)
		if err == nil {
			ripNgroute.Route = *ipNet
		} else {
			return errors.New(fmt.Sprintf("RIPng add route: route parameter must be in CIDR notation, i.e.: 2001:db8::/32"))
		}
		if ipNet.IP.To4() != nil {
			return errors.New(fmt.Sprintf("RIPng add route: route parameter must be an IPv6 CIDR notation, i.e.: 2001:db8::/32"))
		}
		if route.(Route).NextHop != "" {
			ip := net.ParseIP(route.(Route).NextHop)
			if ip != nil && ip.To4() == nil {
				ripNgroute.NextHop = ip
			} else {
				return errors.New(fmt.Sprintf("RIPng add route: next hop parameter must be a valid IPv6 address, i.e.: 2001:db8::1"))
			}
		}
		if route.(Route).Metric != 0 {
			ripNgroute.Metric = route.(Route).Metric
		} else {
			ripNgroute.Metric = RIPngDefaultMetric
		}
		if route.(Route).RouteTag != 0 {
			ripNgroute.RouteTag = route.(Route).RouteTag
		} else {
			ripNgroute.RouteTag = RIPngDefaultTag
		}
		if route.(Route).AdministrativeDistance != 0 {
			ripNgroute.AdministrativeDistance = route.(Route).AdministrativeDistance
		} else {
			ripNgroute.AdministrativeDistance = RIPngDefaultAdministrativeDistance
		}
		ripNgroute.Updated = time.Now()
	} else {
		_, ok = route.(string)
		if ok {
			// Passed route parameter is a string
			_, ipNet, err := net.ParseCIDR(route.(string))
			if err == nil {
				ripNgroute.Route = *ipNet
				ripNgroute.Metric = RIPngDefaultMetric
				ripNgroute.RouteTag = RIPngDefaultTag
				ripNgroute.AdministrativeDistance = RIPngDefaultAdministrativeDistance
				ripNgroute.Updated = time.Now()
			} else {
				return errors.New(fmt.Sprintf("RIPng add route: route parameter must be in CIDR notation, i.e.: 2001:db8::/32"))
			}
		} else {
			return errors.New(fmt.Sprintf("RIPng add route: route parameter must be a Route struct or a string"))
		}
	}

	ripNg.routeUpdates <- ripNgroute

	return nil

}

func (rip RIPng) RemoveRoute(route interface{}) error {

	var ripNgroute RIPngRoute

	_, ok := route.(Route)
	if ok {
		// Passed route parameter is of type Route
		_, ipNet, err := net.ParseCIDR(route.(Route).Route)
		if err == nil {
			ripNgroute.Route = *ipNet
		} else {
			return errors.New(fmt.Sprintf("Route remove route: route parameter must be in CIDR notation, i.e.: 2001:db8::/32"))
		}
		if ipNet.IP.To4() != nil {
			return errors.New(fmt.Sprintf("RIPng remove route: route parameter must be an IPv6 CIDR notation, i.e.: 2001:db8::/32"))
		}
		ip := net.ParseIP(route.(Route).NextHop)
		if ip != nil && ip.To4() == nil {
			ripNgroute.NextHop = ip
		} else {
			return errors.New(fmt.Sprintf("RIPng remove route: next hop parameter must be a valid IPv6 address, i.e.: 2001:db8::1"))
		}
		ripNgroute.Metric = RIPngInfiniteMetric
		if route.(Route).RouteTag != 0 {
			ripNgroute.RouteTag = route.(Route).RouteTag
		} else {
			ripNgroute.RouteTag = RIPngDefaultTag
		}
		if route.(Route).AdministrativeDistance != 0 {
			ripNgroute.AdministrativeDistance = route.(Route).AdministrativeDistance
		} else {
			ripNgroute.AdministrativeDistance = RIPngDefaultAdministrativeDistance
		}
		ripNgroute.Updated = time.Now()
		ripNgroute.Deleted = true
	} else {
		_, ok = route.(string)
		if ok {
			// Passed route parameter is a string
			_, ipNet, err := net.ParseCIDR(route.(string))
			if err == nil {
				ripNgroute.Route = *ipNet
				ripNgroute.Metric = RIPngDefaultMetric
				ripNgroute.RouteTag = RIPngDefaultTag
				ripNgroute.AdministrativeDistance = RIPngDefaultAdministrativeDistance
				ripNgroute.Updated = time.Now()
				ripNgroute.Deleted = true
			} else {
				return errors.New(fmt.Sprintf("RIPng remove route: route parameter must be in CIDR notation, i.e.: 2001:db8::/32"))
			}
		} else {
			return errors.New(fmt.Sprintf("RIPng remove route: route parameter must be a Route struct or a string"))
		}
	}

	ripNg.routeUpdates <- ripNgroute

	return nil

}

func (rip *RIPng) SetTimers(update, updateDelay, gc float32) error {

	if update < RIPngMinUpdateTimer || update > RIPngMaxUpdateTimer {
		return errors.New(fmt.Sprintf("RIPng Update timer should be between %.f and %.f", RIPngMinUpdateTimer, RIPngMaxUpdateTimer))
	} else if updateDelay < RIPngMinUpdateDelay || updateDelay > RIPngMaxUpdateDelay {
		return errors.New(fmt.Sprintf("RIPng Update delay timer should be between %.f and %.f", RIPngMinUpdateDelay, RIPngMaxUpdateDelay))
	} else if gc < RIPngMinGCTimer || gc > RIPngMaxGCTimer {
		return errors.New(fmt.Sprintf("RIPng GC timer should be between %.f and %.f", RIPngMinGCTimer, RIPngMaxGCTimer))
	}

	rip.updateTimer = time.Duration(int(update*1000)) * time.Millisecond
	rip.updateDelay = time.Duration(int(updateDelay*1000)) * time.Millisecond
	rip.gcTimer = time.Duration(int(gc*1000)) * time.Millisecond

	return nil

}

// Setter, because RIPng fields cannot be exposed through the RouterInterface
func (rip *RIPng) KeepRoutesUponClosure(b bool) {
	rip.keepRoutesUponClosure = b
}

func (rip *RIPng) Close() {

	// Close routeUpdates channel. rip.router() routine will quit upon channel closure.
	close(rip.routeUpdates)

	// Advertise all remaining routes as deleted before quitting
	rip.logInfo("RIPng stopping router")
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
	rip.routeTable = RIPngRouteTable{}

}

func (rip *RIPng) LogChan() *chan string {
	return &rip.Log
}

func (rip *RIPng) router() {

	rip.logInfo("RIPng starting router")

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
			routeUpdates := []RIPngRoute{}
			routeUpdates = append(routeUpdates, routeUpdate)
			if !channelOpen {
				// rip.routeUpdates channel is closed, there will be no more updates, exit router()
				return
			}
			if lastUpdate.Add(rip.updateDelay).After(time.Now()) {
				sleepDelay := rip.updateDelay - time.Since(lastUpdate)
				rip.logDebug("RIPng triggered update throttled, sleeping for %f seconds", sleepDelay.Seconds())
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
			rip.logDebug("RIPng triggered partial update")
			rip.sendPartialUpdate(routeUpdates)

		case <-time.After(timeToNextFullUpdate):
			rip.logDebug("RIPng regular update")
			rip.sendFullUpdate()
			lastFullUpdate = time.Now()

		}
		lastUpdate = time.Now()
	}

}

func (rip *RIPng) addUpdatesToRouteTable(routeUpdates []RIPngRoute) {

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

func (rip *RIPng) sendPartialUpdate(updateRoutes []RIPngRoute) {

	// If there is a same route with lower AdministrativeDistance in the routeTable,
	// do not advertise it in a partial update
	rip.routeTable.RLock()
	for i := len(updateRoutes) - 1; i >= 0; i-- {
		for _, tableRoute := range rip.routeTable.Routes {
			if rip.isSameRoute(updateRoutes[i], tableRoute) &&
				updateRoutes[i].AdministrativeDistance > tableRoute.AdministrativeDistance &&
				tableRoute.Deleted == false {
				if len(updateRoutes) == 1 {
					updateRoutes = []RIPngRoute{}
				} else {
					updateRoutes = append(updateRoutes[:i], updateRoutes[i+1:]...)
				}
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
		rip.logDebug("RIPng partial update has no best routes to advertise")
	} else {
		rip.sendUpdate(&updateRoutes)
	}

}

func (rip RIPng) sendFullUpdate() {

	rip.collectGarbageRoutes()
	rip.sendUpdate(&rip.routeTable.Routes)

}

func (rip *RIPng) collectGarbageRoutes() {

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
		rip.logDebug("RIPng garbage collecting routes: %s", routesStr[2:])
	}

}

// sendIpv4RipMessage sends out the RIPng Unsolicited routing update message,
// multicasted from each of the parentIP addreses.
func (rip *RIPng) sendUpdate(routes *[]RIPngRoute) {

	// RIPng message structures, as per RFC2080
	type RIPngHeader struct {
		Command uint8
		Version uint8
		Unused  uint16
	}
	type RIPngRTE struct {
		IPAddress [16]byte
		RouteTag  uint16
		PrefixLen uint8
		Metric    uint8
	}
	type RIPngNextHopRTE struct {
		IPAddress  [16]byte
		MustBeZero [3]byte
		MustBeFF   uint8
	}

	rip.routeTable.RLock()
	routesLen := len(*routes)
	rip.routeTable.RUnlock()
	if routesLen == 0 {
		rip.logInfo("RIPng has no routes to advertise")
		return
	}

	// In RIPng, the next hop is specified by a special RTE and applies to all of
	// the address RTEs following the next hop RTE until the end of the message or
	// until another next hop RTE is encountered.
	// We need to order the rotues by nexthop, starting with no next hop routes.
	rip.routeTable.Lock()
	sort.Sort(ByNextHop(*routes))
	rip.routeTable.Unlock()

	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			ip, _, err := net.ParseCIDR(addr.String())
			if err != nil {
				//
			} else if ip.To16() == nil {
				// This is not an IPv6 address
			} else if !ip.IsLinkLocalUnicast() {
				// only advertise on link-local (per RFC2080)
			} else if ip.To4() == nil {
				localAddr, err := net.ResolveUDPAddr("udp6", "["+ip.String()+"%"+iface.Name+"]:521")
				if err != nil {
					rip.logError("RIPng local address resolution error %v", err)
					return
				}
				remoteEP, err := net.ResolveUDPAddr("udp6", "[ff02::9]:521")
				if err != nil {
					rip.logError("RIPng remote address resolution error %v", err)
					return
				}
				conn, err := net.DialUDP("udp6", localAddr, remoteEP)
				if err != nil {
					rip.logError("RIPng connection error %v", err)
					return
				}
				ripHeader := new(RIPngHeader)
				ripHeader.Command = 2
				ripHeader.Version = 1

				var buf bytes.Buffer
				binary.Write(&buf, binary.BigEndian, ripHeader)

				// Next hop RTE is not used, receiving router will use RIPng message's source
				// address as the next hop
				var routeStr string
				var needsToBeWritten bool
				var previousNextHop net.IP

				rip.routeTable.RLock()
				for _, routeTableEntry := range *routes {

					// NextHop of this route differes from NextHop of the previous route,
					// add a NextHop RTE
					if bytes.Compare(routeTableEntry.NextHop, previousNextHop) != 0 {
						nextHopRTE := new(RIPngNextHopRTE)
						copy(nextHopRTE.IPAddress[:], routeTableEntry.NextHop)
						nextHopRTE.MustBeFF = 0xff
						binary.Write(&buf, binary.BigEndian, nextHopRTE)
					}

					route := new(RIPngRTE)
					copy(route.IPAddress[:], routeTableEntry.Route.IP)
					prefixLen, _ := routeTableEntry.Route.Mask.Size()
					route.PrefixLen = uint8(prefixLen)
					if routeTableEntry.Deleted == true {
						// Deleted routes younger than gcTimer are advertised with:
						route.Metric = 16
					} else {
						route.Metric = uint8(routeTableEntry.Metric)
					}
					route.RouteTag = routeTableEntry.RouteTag
					binary.Write(&buf, binary.BigEndian, route)
					routeStr = routeStr + ", " + routeTableEntry.Route.IP.String() + "/" + strconv.FormatUint(uint64(route.PrefixLen), 10) + " (metric " + strconv.FormatUint(uint64(route.Metric), 10) + ")"

					// RFC2080 prescribes UDP datagram should not exceed MTU - IPv6 header
					// Substract 20 for IPv6 header, and 20 for the last RTE included
					if buf.Len() > iface.MTU-40 {
						conn.Write(buf.Bytes())
						ripHeader = new(RIPngHeader)
						ripHeader.Command = 2
						ripHeader.Version = 2
						buf.Reset()
						binary.Write(&buf, binary.BigEndian, ripHeader)
						needsToBeWritten = false
					} else {
						needsToBeWritten = true
					}

				}
				rip.routeTable.RUnlock()

				if needsToBeWritten {
					conn.Write(buf.Bytes())
				}
				conn.Close()

				if len(routeStr) > 1 {
					routeStr = routeStr[2:]
				}
				rip.logInfo("RIPng advertising from %s: %s", ip.String(), routeStr)
			}
		}
	}

}

func (rip RIPng) isSameRouteSameAD(r1, r2 RIPngRoute) bool {
	if rip.isSameRoute(r1, r2) && r1.AdministrativeDistance == r2.AdministrativeDistance {
		return true
	} else {
		return false
	}
}

func (rip RIPng) isSameRoute(r1, r2 RIPngRoute) bool {
	if r1.Route.Contains(r2.Route.IP) && r2.Route.Contains(r1.Route.IP) {
		return true
	} else {
		return false
	}
}

// []RIPngRoute.Sort() methods
type ByNextHop []RIPngRoute

func (routes ByNextHop) Len() int {
	return len(routes)
}
func (routes ByNextHop) Less(i, j int) bool {
	if routes[i].NextHop == nil {
		return true
	} else if routes[j].NextHop == nil {
		return false
	} else if bytes.Compare(routes[i].NextHop, routes[j].NextHop) == -1 {
		return true
	} else {
		return false
	}
}
func (routes ByNextHop) Swap(i, j int) {
	r := routes[i]
	routes[i] = routes[j]
	routes[j] = r
}

func (rip *RIPng) log(msg string) {
	select {
	case rip.Log <- msg + "\n":
	default:
	}
}

func (rip *RIPng) logDebug(format string, a ...interface{}) {
	if rip.LogLevel >= LogDebug {
		rip.log(fmt.Sprintf("DEBUG "+format, a...))
	}
}
func (rip *RIPng) logInfo(format string, a ...interface{}) {
	if rip.LogLevel >= LogInfo {
		rip.log(fmt.Sprintf("INFO  "+format, a...))
	}
}
func (rip *RIPng) logWarn(format string, a ...interface{}) {
	if rip.LogLevel >= LogWarning {
		rip.log(fmt.Sprintf("WARN  "+format, a...))
	}
}
func (rip *RIPng) logError(format string, a ...interface{}) {
	if rip.LogLevel >= LogError {
		rip.log(fmt.Sprintf("ERROR "+format, a...))
	}
}
