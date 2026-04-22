package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/apernet/hysteria/core/v2/server"
	"github.com/apernet/hysteria/extras/v2/l2tp"
	"github.com/apernet/hysteria/extras/v2/pppbridge"
	"go.uber.org/zap"
)

func (c *serverConfig) fillPPPConfig(hyConfig *server.Config) error {
	if !c.PPP.Enabled {
		return nil
	}

	mode := strings.ToLower(c.PPP.Mode)
	if mode == "" {
		mode = "local"
	}

	switch mode {
	case "local":
		return c.fillPPPConfigLocal(hyConfig)
	case "l2tp":
		return c.fillPPPConfigL2TP(hyConfig)
	default:
		return configError{Field: "ppp.mode", Err: fmt.Errorf("unsupported mode %q (must be \"local\" or \"l2tp\")", c.PPP.Mode)}
	}
}

func (c *serverConfig) fillPPPConfigLocal(hyConfig *server.Config) error {
	pppdPath := c.PPP.PPPDPath
	if pppdPath == "" {
		pppdPath = "/usr/sbin/pppd"
	}

	var pool *pppbridge.IPPool
	if c.PPP.IPv4Pool != "" {
		var err error
		pool, err = pppbridge.NewIPPool(c.PPP.IPv4Pool)
		if err != nil {
			return configError{Field: "ppp.ipv4Pool", Err: err}
		}
	}

	poolDesc := "(IPv6-only)"
	if c.PPP.IPv4Pool != "" {
		poolDesc = c.PPP.IPv4Pool
	}
	logger.Info("PPP enabled (local mode)",
		zap.String("ipv4Pool", poolDesc),
		zap.String("pppdPath", pppdPath),
		zap.Bool("sudo", c.PPP.Sudo),
		zap.Uint32("mtu", c.PPP.MTU))

	hyConfig.PPPRequestHandler = &pppbridge.ServerPPPHandler{
		PPPDPath:   pppdPath,
		PPPDArgs:   c.PPP.PPPDArgs,
		Sudo:       c.PPP.Sudo,
		IPv4Pool:   pool,
		DNS:        c.PPP.DNS,
		MTU:        int(c.PPP.MTU),
		Salamander: strings.EqualFold(c.Obfs.Type, "salamander"),
		Logger:     logger,
	}
	return nil
}

func (c *serverConfig) fillPPPConfigL2TP(hyConfig *server.Config) error {
	l2tpCfg := c.PPP.L2TP

	if l2tpCfg.Hostname == "" {
		l2tpCfg.Hostname = os.Getenv("HYSTERIA_LAC_HOSTNAME")
	}
	if l2tpCfg.Hostname == "" {
		l2tpCfg.Hostname, _ = os.Hostname()
	}
	if l2tpCfg.Hostname == "" {
		return configError{Field: "ppp.l2tp.hostname", Err: fmt.Errorf("hostname is required but could not be determined")}
	}

	// Validate groups
	if len(l2tpCfg.Groups) == 0 {
		return configError{Field: "ppp.l2tp.groups", Err: fmt.Errorf("at least one LNS group is required")}
	}
	lbGroups := make(map[string][]l2tp.LNSConfig)
	for name, group := range l2tpCfg.Groups {
		if len(group.LNS) == 0 {
			return configError{Field: fmt.Sprintf("ppp.l2tp.groups.%s.lns", name), Err: fmt.Errorf("at least one LNS is required")}
		}
		for _, lns := range group.LNS {
			if lns.Address == "" {
				return configError{Field: fmt.Sprintf("ppp.l2tp.groups.%s.lns.address", name), Err: fmt.Errorf("LNS address is required")}
			}
			w := lns.Weight
			if w <= 0 {
				w = 1
			}
			lbGroups[name] = append(lbGroups[name], l2tp.LNSConfig{
				Address: lns.Address,
				Secret:  lns.Secret,
				Weight:  w,
			})
		}
	}

	// Validate realms
	if len(l2tpCfg.Realms) == 0 {
		return configError{Field: "ppp.l2tp.realms", Err: fmt.Errorf("at least one realm rule is required")}
	}
	var realmRules []l2tp.RealmRule
	for _, realm := range l2tpCfg.Realms {
		if realm.Pattern == "" {
			return configError{Field: "ppp.l2tp.realms.pattern", Err: fmt.Errorf("realm pattern is required")}
		}
		if _, ok := l2tpCfg.Groups[realm.Group]; !ok {
			return configError{Field: "ppp.l2tp.realms.group", Err: fmt.Errorf("realm references unknown group %q", realm.Group)}
		}
		realmRules = append(realmRules, l2tp.RealmRule{
			Pattern: realm.Pattern,
			Group:   realm.Group,
		})
	}

	helloInterval := time.Duration(l2tpCfg.HelloInterval) * time.Second

	tm := l2tp.NewTunnelManager(l2tpCfg.Hostname, helloInterval, logger)
	rr := l2tp.NewRealmRouter(realmRules)
	lb := l2tp.NewLoadBalancer(lbGroups)

	logger.Info("PPP enabled (L2TP mode)",
		zap.String("hostname", l2tpCfg.Hostname),
		zap.Int("helloInterval", l2tpCfg.HelloInterval),
		zap.Int("groups", len(l2tpCfg.Groups)),
		zap.Int("realms", len(l2tpCfg.Realms)))

	hyConfig.PPPRequestHandler = &pppbridge.L2TPPPPHandler{
		TunnelManager: tm,
		RealmRouter:   rr,
		LoadBalancer:  lb,
		Logger:        logger,
	}
	return nil
}
