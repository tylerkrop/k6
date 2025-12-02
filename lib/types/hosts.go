package types

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

const nullJSON = "null"

// NullHosts is a wrapper around Hosts like guregu/null
type NullHosts struct {
	Trie  *Hosts
	Valid bool
}

// NewNullHosts returns valid (Valid: true) Hosts
func NewNullHosts(source map[string]Host) (NullHosts, error) {
	hosts, err := NewHosts(source)
	if err != nil {
		return NullHosts{}, err
	}

	return NullHosts{
		Trie:  hosts,
		Valid: true,
	}, nil
}

// MarshalJSON converts NullHosts to valid JSON
func (n NullHosts) MarshalJSON() ([]byte, error) {
	if !n.Valid {
		return []byte(nullJSON), nil
	}

	jsonMap := make(map[string]interface{})
	for k, v := range n.Trie.source {
		if len(v.IPs) > 1 {
			list := make([]string, 0, len(v.IPs))
			for _, ip := range v.IPs {
				if v.Port != 0 {
					list = append(list, net.JoinHostPort(ip.String(), strconv.Itoa(v.Port)))
				} else {
					list = append(list, ip.String())
				}
			}
			jsonMap[k] = list
		} else if len(v.IPs) == 1 {
			if v.Port != 0 {
				jsonMap[k] = v.String()
			} else {
				jsonMap[k] = v.IPs[0].String()
			}
		}
	}

	return json.Marshal(jsonMap)
}

// UnmarshalJSON converts JSON to NullHosts
func (n *NullHosts) UnmarshalJSON(data []byte) error {
	if bytes.Equal(data, []byte(nullJSON)) {
		n.Trie = nil
		n.Valid = false
		return nil
	}

	var jsonSource map[string]interface{}
	if err := json.Unmarshal(data, &jsonSource); err != nil {
		return err
	}

	source := make(map[string]Host)
	for k, v := range jsonSource {
		switch val := v.(type) {
		case string:
			h, err := parseHost(val)
			if err != nil {
				return err
			}
			source[k] = h
		case []interface{}:
			var ips []net.IP
			var port int
			for _, item := range val {
				s, ok := item.(string)
				if !ok {
					return fmt.Errorf("invalid host value: %v", item)
				}
				h, err := parseHost(s)
				if err != nil {
					return err
				}
				if port == 0 {
					port = h.Port
				} else if h.Port != 0 && h.Port != port {
					return fmt.Errorf("conflicting ports for host %s", k)
				}
				ips = append(ips, h.IPs...)
			}
			source[k] = Host{IPs: ips, Port: port}
		default:
			return fmt.Errorf("invalid host value type for %s", k)
		}
	}

	hosts, err := NewHosts(source)
	if err != nil {
		return err
	}
	n.Trie = hosts
	n.Valid = true
	return nil
}

func parseHost(v string) (Host, error) {
	ip, port, err := net.SplitHostPort(v)
	if err == nil {
		pInt, err := strconv.Atoi(port)
		if err != nil {
			return Host{}, err
		}
		return Host{IPs: []net.IP{net.ParseIP(ip)}, Port: pInt}, nil
	}
	return Host{IPs: []net.IP{net.ParseIP(v)}}, nil
}

// Hosts is wrapper around trieNode to integrate with net.TCPAddr
type Hosts struct {
	n      *trieNode
	source map[string]Host
}

// NewHosts returns new Hosts from given addresses.
func NewHosts(source map[string]Host) (*Hosts, error) {
	h := &Hosts{
		source: toLowerKeys(source),
		n: &trieNode{
			children: make(map[rune]*trieNode),
		},
	}

	for k := range h.source {
		err := h.insert(k)
		if err != nil {
			return nil, err
		}
	}

	return h, nil
}

func toLowerKeys(source map[string]Host) map[string]Host {
	result := make(map[string]Host, len(source))
	for k, v := range source {
		result[strings.ToLower(k)] = v
	}
	return result
}

// Regex description of domain(:port)? pattern to enforce blocks by.
// Global var to avoid compilation penalty at runtime.
// Based on regex from https://stackoverflow.com/a/106223/5427244
//
//nolint:lll
var validHostPattern = regexp.MustCompile(`^(\*\.?)?((([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9]))?(:[0-9]{1,5})?$`)

func isValidHostPattern(s string) error {
	if len(validHostPattern.FindString(s)) != len(s) {
		return fmt.Errorf("invalid host pattern '%s'", s)
	}
	return nil
}

func (t *Hosts) insert(s string) error {
	s = strings.ToLower(s) // domains are not case-sensitive

	if err := isValidHostPattern(s); err != nil {
		return err
	}

	t.n.insert(s)

	return nil
}

// Match returns the host matching s, where the value can be one of:
// - nil (no match)
// - IP:0 (Only IP match, record does not have port information)
// - IP:Port
func (t *Hosts) Match(s string) *Host {
	s = strings.ToLower(s)
	match, ok := t.n.contains(s)

	if !ok {
		return nil
	}

	address := t.source[match]

	return &address
}
