package c2external

import (
	"flag"
	"net"

	"github.com/vulncheck-oss/go-exploit/c2"
	"github.com/vulncheck-oss/go-exploit/c2/channel"
	"github.com/vulncheck-oss/go-exploit/c2/external"
)

var flagCommand string

var (
	Name      = "ExtServer"
	ExtServer c2.Impl
)

type ExternalC2 struct {
	Channel *channel.Channel
	// Example of how you can define variables accessible in the set functions
	Listener *net.Listener
}

func New() ExternalC2 {
	return ExternalC2{}
}

func (c2 *ExternalC2) ExtServerFlags() {
	// Flags for the external C2. The run function in the framework handles the parsing and
	// the options will be available to the exploit.
	flag.StringVar(&flagCommand, Name+".command", "", "Run a single command and exit the payload.")
}

func (c2 *ExternalC2) ExtServerInit() {
	// Any initialization such as key generation or external configuration components can go
	// here.
}

func (c2 *ExternalC2) ExtServerChannel(channel *channel.Channel) {
	// This will generally just be setting the internal channel to match the expected
	// go-exploit channel and provide access to the framework channel.
	c2.Channel = channel
}

func (c2 *ExternalC2) ExtServerRun(timeout int) bool {
	// Add any servers or connection pooling here
	// Make sure to handle the timeout!
	return false
}

func Configure(externalServer *external.Server) {
	ExtServer = c2.AddC2(Name)
	extc2 := New()
	externalServer.SetFlags(extc2.ExtServerFlags)
	externalServer.SetChannel(extc2.ExtServerChannel)
	externalServer.SetInit(extc2.ExtServerInit)
	externalServer.SetRun(extc2.ExtServerRun)
}
