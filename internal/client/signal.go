package client

import (
	"net"
	"os"
	"os/signal"

	"github.com/marcelocantos/doit/internal/ipc"
)

// ForwardSignals catches SIGINT and sends a Signal frame to the daemon.
// Returns a cleanup function to deregister the handler.
func ForwardSignals(conn net.Conn) func() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt)
	go func() {
		for range ch {
			ipc.WriteJSON(conn, ipc.TagSignal, ipc.SignalMsg{Signal: "INT"})
		}
	}()
	return func() {
		signal.Stop(ch)
		close(ch)
	}
}
