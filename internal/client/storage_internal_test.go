package client

import "net"

// FindByName finds persistent client by name.  And returns its shallow copy.
// It is currently only used in tests.
func (s *Storage) FindByName(name string) (p *Persistent, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	p, ok = s.index.findByName(name)
	if ok {
		return p.ShallowClone(), ok
	}

	return nil, false
}

// FindByMAC finds persistent client by MAC and returns its shallow copy.  s.mu
// is expected to be locked.  It is currently only used in tests.
func (s *Storage) FindByMAC(mac net.HardwareAddr) (p *Persistent, ok bool) {
	p, ok = s.index.findByMAC(mac)
	if ok {
		return p.ShallowClone(), ok
	}

	return nil, false
}
