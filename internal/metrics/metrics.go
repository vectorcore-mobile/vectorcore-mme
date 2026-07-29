package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	SMSRegistrationRequestsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "mme", Subsystem: "sms", Name: "registration_requests_total",
		Help: "SMS-in-MME registration requests carried in S6a ULRs.",
	})
	SMSRegistrationSuccessTotal = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "mme", Subsystem: "sms", Name: "registration_success_total",
		Help: "SMS-in-MME registrations accepted by the HSS.",
	})
	SMSRegistrationFailuresTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "mme", Subsystem: "sms", Name: "registration_failures_total",
		Help: "SMS-in-MME registration failures by bounded cause.",
	}, []string{"cause"})
	SMSMORequestsTotal         = promauto.NewCounterVec(prometheus.CounterOpts{Namespace: "mme", Subsystem: "sms", Name: "mo_requests_total", Help: "MO SMS transactions by result."}, []string{"result"})
	SMSMTRequestsTotal         = promauto.NewCounterVec(prometheus.CounterOpts{Namespace: "mme", Subsystem: "sms", Name: "mt_requests_total", Help: "MT SMS transactions by result."}, []string{"result"})
	SMSMTPagingTotal           = promauto.NewCounterVec(prometheus.CounterOpts{Namespace: "mme", Subsystem: "sms", Name: "mt_paging_total", Help: "MT SMS paging attempts by result."}, []string{"result"})
	SMSAlertServiceCentreTotal = promauto.NewCounterVec(prometheus.CounterOpts{Namespace: "mme", Subsystem: "sms", Name: "alert_service_centre_total", Help: "Alert Service Centre attempts by result."}, []string{"result"})
	SMSActiveTransactions      = promauto.NewGauge(prometheus.GaugeOpts{Namespace: "mme", Subsystem: "sms", Name: "active_transactions", Help: "Active UE-facing SMS transactions."})
	SMSTimerExpirationsTotal   = promauto.NewCounterVec(prometheus.CounterOpts{Namespace: "mme", Subsystem: "sms", Name: "timer_expirations_total", Help: "SMS transaction timer expirations."}, []string{"direction"})
	SMSDuplicateMessagesTotal  = promauto.NewCounterVec(prometheus.CounterOpts{Namespace: "mme", Subsystem: "sms", Name: "duplicate_messages_total", Help: "Suppressed duplicate SMS messages."}, []string{"direction"})

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
	SBcAPLegacyPPIDZeroTotal = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "mme", Subsystem: "sbcap", Name: "legacy_ppid_zero_messages_total",
		Help: "Non-standard SCTP PPID 0 SBc-AP messages accepted from admitted CBC peers by explicit compatibility configuration.",
	})
	SBcAPAssociations            = promauto.NewGauge(prometheus.GaugeOpts{Namespace: "mme", Subsystem: "sbcap", Name: "associations", Help: "Currently admitted CBC SCTP associations."})
	SBcAPMessagesTotal           = promauto.NewCounterVec(prometheus.CounterOpts{Namespace: "mme", Subsystem: "sbcap", Name: "messages_total", Help: "SBc-AP messages by direction, procedure, and result."}, []string{"direction", "procedure", "result"})
	SBcAPPPIDRejectedTotal       = promauto.NewCounterVec(prometheus.CounterOpts{Namespace: "mme", Subsystem: "sbcap", Name: "ppid_rejected_total", Help: "Rejected inbound SCTP payloads by PPID."}, []string{"ppid"})
	SBcAPDecodeFailuresTotal     = promauto.NewCounter(prometheus.CounterOpts{Namespace: "mme", Subsystem: "sbcap", Name: "decode_failures_total", Help: "SBc-AP APER PDU decode failures."})
	SBcAPValidationFailuresTotal = promauto.NewCounterVec(prometheus.CounterOpts{Namespace: "mme", Subsystem: "sbcap", Name: "validation_failures_total", Help: "SBc-AP validation failures by bounded reason."}, []string{"reason"})
	SBcAPTransactionsTotal       = promauto.NewCounterVec(prometheus.CounterOpts{Namespace: "mme", Subsystem: "sbcap", Name: "transactions_total", Help: "SBc-AP response collection transactions by result."}, []string{"result"})

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
	MobileReachableExpiriesTotal       = promauto.NewCounter(prometheus.CounterOpts{Namespace: "mme", Name: "mobile_reachable_expiries_total", Help: "MME mobile-reachable timer expiries."})
	ImplicitDetachExpiriesTotal        = promauto.NewCounter(prometheus.CounterOpts{Namespace: "mme", Name: "implicit_detach_expiries_total", Help: "MME implicit-detach timer expiries."})
	ImplicitDetachRecoveriesTotal      = promauto.NewCounter(prometheus.CounterOpts{Namespace: "mme", Name: "implicit_detach_recoveries_total", Help: "UE returns that cancel implicit detach."})
	ImplicitDetachCleanupFailuresTotal = promauto.NewCounter(prometheus.CounterOpts{Namespace: "mme", Name: "implicit_detach_cleanup_failures_total", Help: "Terminal cleanup DSR failures."})
	ImplicitDetachCleanupTimeoutsTotal = promauto.NewCounter(prometheus.CounterOpts{Namespace: "mme", Name: "implicit_detach_cleanup_timeouts_total", Help: "Terminal cleanup deadline expiries."})

	// Paging metrics
	PagingTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "mme",
		Subsystem: "s1ap",
		Name:      "paging_total",
		Help:      "S1AP Paging events by result.",
	}, []string{"result"})

	PositioningRequestsTotal      = promauto.NewCounter(prometheus.CounterOpts{Namespace: "mme", Subsystem: "positioning", Name: "requests_total", Help: "Positioning transactions created."})
	PositioningSuccessTotal       = promauto.NewCounter(prometheus.CounterOpts{Namespace: "mme", Subsystem: "positioning", Name: "success_total", Help: "Positioning transactions completed with an estimate."})
	PositioningFailureTotal       = promauto.NewCounterVec(prometheus.CounterOpts{Namespace: "mme", Subsystem: "positioning", Name: "failure_total", Help: "Positioning transaction failures by bounded reason."}, []string{"reason"})
	PositioningActiveTransactions = promauto.NewGauge(prometheus.GaugeOpts{Namespace: "mme", Subsystem: "positioning", Name: "active_transactions", Help: "Active SLs positioning transactions."})
	PositioningPendingLPPMessages = promauto.NewGauge(prometheus.GaugeOpts{Namespace: "mme", Subsystem: "positioning", Name: "pending_lpp_messages", Help: "Queued ECM-idle LPP NAS messages."})
	PositioningLPPDownlinkTotal   = promauto.NewCounterVec(prometheus.CounterOpts{Namespace: "mme", Subsystem: "positioning", Name: "lpp_downlink_total", Help: "LPP downlink relay events by delivery mode."}, []string{"mode"})
	PositioningLPPUplinkTotal     = promauto.NewCounter(prometheus.CounterOpts{Namespace: "mme", Subsystem: "positioning", Name: "lpp_uplink_total", Help: "LPP uplink relay events."})
	PositioningPagingTotal        = promauto.NewCounterVec(prometheus.CounterOpts{Namespace: "mme", Subsystem: "positioning", Name: "paging_total", Help: "Positioning paging results."}, []string{"result"})
	PositioningQueueRejectTotal   = promauto.NewCounter(prometheus.CounterOpts{Namespace: "mme", Subsystem: "positioning", Name: "queue_reject_total", Help: "Rejected pending LPP messages due to queue bounds."})
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
