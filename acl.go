package forwardproxy

import (
	"errors"
	"net"
	"strings"
)

type aclDecision uint8

const (
	aclDecisionAllow = iota
	aclDecisionDeny
	aclDecisionNoMatch
)

type aclRule interface {
	tryMatch(ip net.IP, domain string) aclDecision
}

type aclIPRule struct {
	net   net.IPNet
	allow bool
}

func (a *aclIPRule) tryMatch(ip net.IP, domain string) aclDecision {
	if !a.net.Contains(ip) {
		return aclDecisionNoMatch
	}
	if a.allow {
		return aclDecisionAllow
	}
	return aclDecisionDeny

}

type aclDomainRule struct {
	domain            string
	subdomainsAllowed bool
	allow             bool
}

func (a *aclDomainRule) tryMatch(ip net.IP, domain string) aclDecision {
	if strings.HasSuffix(domain, ".") {
		domain = domain[:len(domain)-1]
	}
	if domain == a.domain ||
		a.subdomainsAllowed && strings.HasSuffix(domain, "."+a.domain) {
		if a.allow {
			return aclDecisionAllow
		}
		return aclDecisionDeny
	}
	return aclDecisionNoMatch
}

type aclAllRule struct {
	allow bool
}

func (a *aclAllRule) tryMatch(ip net.IP, domain string) aclDecision {
	if a.allow {
		return aclDecisionAllow
	}
	return aclDecisionDeny
}

func newAclRule(ruleSubject string, allow bool) (aclRule, error) {
	if ruleSubject == "all" {
		return &aclAllRule{allow: allow}, nil
	}
	_, ipNet, err := net.ParseCIDR(ruleSubject)
	if err != nil {
		ip := net.ParseIP(ruleSubject)
		// support specifying just an IP
		if ip.To4() != nil {
			_, ipNet, err = net.ParseCIDR(ruleSubject + "/32")
		} else if ip.To16() != nil {
			_, ipNet, err = net.ParseCIDR(ruleSubject + "/128")
		}
	}
	if err == nil {
		return &aclIPRule{net: *ipNet, allow: allow}, nil
	}

	subdomainsAllowed := false
	if strings.HasPrefix(ruleSubject, `*.`) {
		subdomainsAllowed = true
		ruleSubject = ruleSubject[2:]
	}
	err = isValidDomainLite(ruleSubject)
	if err != nil {
		return nil, errors.New(ruleSubject + " could not be parsed as either IP, IP network, or domain: " + err.Error())
	}
	return &aclDomainRule{domain: ruleSubject, subdomainsAllowed: subdomainsAllowed, allow: allow}, nil
}
