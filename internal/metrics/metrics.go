package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// S1AP metrics
	S1APMessagesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "mme",
		Subsystem: "s1ap",
		Name:      "messages_total",
		Help:      "Total S1AP messages processed, split by procedure and direction.",
	}, []string{"procedure", "direction", "result"})

	S1APMessageDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "mme",
		Subsystem: "s1ap",
		Name:      "message_duration_seconds",
		Help:      "S1AP message processing duration.",
		Buckets:   []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1},
	}, []string{"procedure"})

	S1APConnectedENBs = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "mme",
		Subsystem: "s1ap",
		Name:      "connected_enbs",
		Help:      "Number of eNodeBs with an active S1 connection.",
	})

	// NAS metrics
	NASProceduresTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "mme",
		Subsystem: "nas",
		Name:      "procedures_total",
		Help:      "Total NAS procedures, split by type and result.",
	}, []string{"procedure", "result"})

	// S6a metrics
	S6aRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "mme",
		Subsystem: "s6a",
		Name:      "requests_total",
		Help:      "Total S6a Diameter requests, split by command and result.",
	}, []string{"command", "result"})

	S6aRequestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "mme",
		Subsystem: "s6a",
		Name:      "request_duration_seconds",
		Help:      "S6a request processing duration.",
		Buckets:   []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5},
	}, []string{"command"})

	S13ECAsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "mme", Subsystem: "s13", Name: "eca_received_total", Help: "Total S13 Equipment-Check-Answers received.",
	})
	S13ChecksTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "mme", Subsystem: "s13", Name: "check_total", Help: "S13 equipment-check outcomes.",
	}, []string{"result"})
	S13AttachRejectsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "mme", Subsystem: "s13", Name: "attach_reject_total", Help: "S13-driven attach rejections.",
	}, []string{"reason"})

	// S11 metrics
	S11MessagesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "mme",
		Subsystem: "s11",
		Name:      "messages_total",
		Help:      "Total GTPv2-C S11 messages, split by procedure and result.",
	}, []string{"procedure", "result"})

	// UE metrics
	AttachedUEs = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "mme",
		Subsystem: "ue",
		Name:      "attached_total",
		Help:      "Number of currently attached UEs.",
	})

	// Paging metrics
	PagingTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "mme",
		Subsystem: "s1ap",
		Name:      "paging_total",
		Help:      "S1AP Paging events by result.",
	}, []string{"result"})
	// Labels: "sent", "retry", "timeout", "success",
	//         "unknown_imsi", "not_idle", "not_registered", "no_enb"

	// Path Switch (X2 handover) metrics
	PathSwitchTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "mme",
		Subsystem: "s1ap",
		Name:      "path_switch_total",
		Help:      "S1AP Path Switch events by result.",
	}, []string{"result"})
	// Labels: "attempt", "success", "s11_error", "ue_not_found", "no_bearer", "decode_error"

	// S10 inter-MME context transfer metrics
	S10MessagesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "mme",
		Subsystem: "s10",
		Name:      "messages_total",
		Help:      "Total GTPv2-C S10 messages by type and result.",
	}, []string{"type", "result"})

	InterMMETAUTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "mme",
		Subsystem: "nas",
		Name:      "inter_mme_tau_total",
		Help:      "Inter-MME TAU events by result.",
	}, []string{"result"})
	// result: "attempt"|"ctx_timeout"|"ctx_not_found"|"ulr_error"|"s11_error"|"success"

	// EMM Information metrics
	EMMInformationTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "mme",
		Subsystem: "nas",
		Name:      "emm_information_total",
		Help:      "EMM Information messages by trigger and result.",
	}, []string{"trigger", "result"})
	// trigger: "attach" | "tau"; result: "sent" | "no_security" | "encode_error" | "send_error"

	// Intra-MME S1 Handover metrics
	HandoverTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "mme",
		Subsystem: "s1ap",
		Name:      "handover_total",
		Help:      "Intra-MME S1 handover events by phase and result.",
	}, []string{"phase", "result"})
	// phase: "preparation" | "execution"
	// result: "attempt" | "success" | "failure" | "timeout" | "no_target_enb" |
	//         "ue_not_found" | "no_bearer" | "wrong_state" | "s11_error"
)
