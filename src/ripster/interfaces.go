package ripster


type RouterInterface interface {
  AddRoute(interface{}) error
  RemoveRoute(interface{}) error
}

type LogGeneratorInterface interface {
    LogChan() *chan string
}
