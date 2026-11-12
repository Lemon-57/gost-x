package wrapper

import (
	"net"

	limiter "github.com/go-gost/core/limiter/conn"
)

type listener struct {
	net.Listener
	limiter limiter.ConnLimiter
}

// WrapListener wraps a net.Listener with a ConnLimiter. Each accepted
// connection is checked against the limiter using the remote IP as the key.
// If the limit is exceeded, the connection is closed and Accept continues
// waiting for an allowed connection. A rejected connection must not terminate
// the service's accept loop. If
// limiter is nil, the original listener is returned unchanged.
func WrapListener(limiter limiter.ConnLimiter, ln net.Listener) net.Listener {
	if limiter == nil {
		return ln
	}

	return &listener{
		limiter:  limiter,
		Listener: ln,
	}
}

func (ln *listener) Accept() (net.Conn, error) {
	for {
		c, err := ln.Listener.Accept()
		if err != nil {
			return nil, err
		}

		host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
		if lim := ln.limiter.Limiter(host); lim != nil {
			if lim.Allow(1) {
				return WrapConn(lim, c), nil
			}
			c.Close()
			continue
		}

		return c, nil
	}
}
