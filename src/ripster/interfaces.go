package ripster

type RouterInterface interface {
	AddRoute(interface{}) error
	RemoveRoute(interface{}) error
	KeepRoutesUponClosure(bool)
	Close()
}

// Route struct is used as parameter to pass Route parameters to .AddRoute() and
// .RemoveRoute() methods of RouterInterface
type Route struct {
	Route                   string
	NextHop                 string
	Metric                  int
	AddressFamilyIdentifier uint16
	RouteTag                uint16
	AdministrativeDistance  uint8
}

type LogGeneratorInterface interface {
	LogChan() *chan string
}
