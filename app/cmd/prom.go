package main

import (
	"github.com/apernet/hysteria/core/cs"
	"github.com/prometheus/client_golang/prometheus"
)

type prometheusTrafficCounter struct {
	reg            *prometheus.Registry
	upCounterVec   *prometheus.CounterVec
	downCounterVec *prometheus.CounterVec
	connGaugeVec   *prometheus.GaugeVec
	counterMap     map[string]counters
}

type counters struct {
	UpCounter   prometheus.Counter
	DownCounter prometheus.Counter
	ConnGauge   prometheus.Gauge
}

func NewPrometheusTrafficCounter(reg *prometheus.Registry) cs.TrafficCounter {
	c := &prometheusTrafficCounter{
		reg: reg,
		upCounterVec: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "hysteria_traffic_uplink_bytes_total",
		}, []string{"auth"}),
		downCounterVec: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "hysteria_traffic_downlink_bytes_total",
		}, []string{"auth"}),
		connGaugeVec: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "hysteria_active_conn",
		}, []string{"auth"}),
		counterMap: make(map[string]counters),
	}
	reg.MustRegister(c.upCounterVec, c.downCounterVec, c.connGaugeVec)
	return c
}

func (c *prometheusTrafficCounter) getCounters(auth string) counters {
	cts, ok := c.counterMap[auth]
	if !ok {
		cts = counters{
			UpCounter:   c.upCounterVec.WithLabelValues(auth),
			DownCounter: c.downCounterVec.WithLabelValues(auth),
			ConnGauge:   c.connGaugeVec.WithLabelValues(auth),
		}
		c.counterMap[auth] = cts
	}
	return cts
}

func (c *prometheusTrafficCounter) Rx(auth string, n int) {
	cts := c.getCounters(auth)
	cts.DownCounter.Add(float64(n))
}

func (c *prometheusTrafficCounter) Tx(auth string, n int) {
	cts := c.getCounters(auth)
	cts.UpCounter.Add(float64(n))
}

func (c *prometheusTrafficCounter) IncConn(auth string) {
	cts := c.getCounters(auth)
	cts.ConnGauge.Inc()
}

func (c *prometheusTrafficCounter) DecConn(auth string) {
	cts := c.getCounters(auth)
	cts.ConnGauge.Dec()
}
