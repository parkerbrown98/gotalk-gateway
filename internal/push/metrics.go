package push

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Metrics are the push pipeline's Prometheus metrics.
type Metrics struct {
	accepted        prometheus.Counter
	rejected        *prometheus.CounterVec
	requests        *prometheus.CounterVec
	requestDuration *prometheus.HistogramVec
	outcomes        *prometheus.CounterVec
	latency         prometheus.Histogram
	deadLettered    prometheus.Counter
}

// NewMetrics creates the metrics and registers them on reg, unless reg is nil.
func NewMetrics(reg prometheus.Registerer) *Metrics {
	const ns = "gotalk_gateway"
	m := &Metrics{
		accepted: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: ns, Subsystem: "push", Name: "accepted_total",
			Help: "Push entries accepted and queued.",
		}),
		rejected: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: ns, Subsystem: "push", Name: "rejected_total",
			Help: "Push entries rejected before queueing, by error code.",
		}, []string{"code"}),
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: ns, Subsystem: "provider", Name: "requests_total",
			Help: "Requests to push providers by provider and result (ok, retry, gone, rejected).",
		}, []string{"provider", "result"}),
		requestDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: ns, Subsystem: "provider", Name: "request_duration_seconds",
			Help:    "Latency of requests to push providers.",
			Buckets: []float64{.01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10},
		}, []string{"provider"}),
		outcomes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: ns, Subsystem: "push", Name: "finished_total",
			Help: "Pushes by final status (sent, failed, expired, gone).",
		}, []string{"status"}),
		latency: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: ns, Subsystem: "push", Name: "delivery_latency_seconds",
			Help:    "Time from accepting a push to its final status.",
			Buckets: []float64{.05, .1, .25, .5, 1, 2, 5, 10, 30, 60, 300},
		}),
		deadLettered: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: ns, Subsystem: "push", Name: "dead_lettered_total",
			Help: "Pushes given up after their retries ran out.",
		}),
	}
	if reg != nil {
		reg.MustRegister(m.accepted, m.rejected, m.requests, m.requestDuration, m.outcomes, m.latency, m.deadLettered)
	}
	return m
}

func (m *Metrics) observeRequest(provider, result string, d time.Duration) {
	m.requests.WithLabelValues(provider, result).Inc()
	m.requestDuration.WithLabelValues(provider).Observe(d.Seconds())
}

func (m *Metrics) finished(status string, latencyMs *int32) {
	m.outcomes.WithLabelValues(status).Inc()
	if latencyMs != nil {
		m.latency.Observe(float64(*latencyMs) / 1000)
	}
}
