package sgd

import (
	"github.com/fiorix/go-diameter/v4/diam"
)

// TS 29.338 §7.4.3 Experimental-Result-Code values (Vendor-Id 10415) for
// MT-Forward-Short-Message-Answer.
const (
	ResultErrorAbsentUser           uint32 = 5550
	ResultErrorUserBusyForMTSMS     uint32 = 5551
	ResultErrorFacilityNotSupported uint32 = 5552
	ResultErrorIllegalUser          uint32 = 5553
	ResultErrorIllegalEquipment     uint32 = 5554
	ResultErrorSMDeliveryFailure    uint32 = 5555
)

// SM-Enumerated-Delivery-Failure-Cause values (TS 29.338 §7.3.5), carried in
// SM-Delivery-Failure-Cause with DIAMETER_ERROR_SM_DELIVERY_FAILURE.
const (
	DeliveryFailureMemoryCapacityExceeded uint32 = 0
	DeliveryFailureEquipmentProtocolError uint32 = 1
	DeliveryFailureEquipmentNotSMEquipped uint32 = 2
	DeliveryFailureUnknownServiceCentre   uint32 = 3
	DeliveryFailureSCCongestion           uint32 = 4
	DeliveryFailureInvalidSMEAddress      uint32 = 5
	DeliveryFailureUserNotSCUser          uint32 = 6
)

// Absent-User-Diagnostic-SM values (TS 23.040 §3.3.2). The MME reports in
// the MSC role for SMS in MME.
const (
	AbsentDiagNoPagingResponse       uint32 = 0
	AbsentDiagIMSIDetached           uint32 = 1
	AbsentDiagTemporarilyUnavailable uint32 = 13
)

// MTOutcome is the result of one MT-Forward-Short-Message delivery attempt.
// Exactly one of ResultCode (base, RFC 6733) or ExperimentalResultCode
// (TS 29.338, Vendor-Id 10415) is set.
type MTOutcome struct {
	ResultCode             uint32
	ExperimentalResultCode uint32
	// AbsentUserDiagnostic is sent as Absent-User-Diagnostic-SM with
	// DIAMETER_ERROR_ABSENT_USER.
	AbsentUserDiagnostic *uint32
	// DeliveryFailureCause and DiagnosticInfo form SM-Delivery-Failure-Cause
	// with DIAMETER_ERROR_SM_DELIVERY_FAILURE. DiagnosticInfo carries the
	// UE's RP-ERROR RP-User-Data (SMS-DELIVER-REPORT TPDU) when present.
	DeliveryFailureCause *uint32
	DiagnosticInfo       []byte
	// SMRPUI is the UE's RP-ACK RP-User-Data on success.
	SMRPUI []byte
}

// Code returns the effective result code for logging and metrics.
func (o MTOutcome) Code() uint32 {
	if o.ExperimentalResultCode != 0 {
		return o.ExperimentalResultCode
	}
	return o.ResultCode
}

// Clone returns a deep copy, so cached outcomes are never shared.
func (o MTOutcome) Clone() MTOutcome {
	c := o
	if o.AbsentUserDiagnostic != nil {
		v := *o.AbsentUserDiagnostic
		c.AbsentUserDiagnostic = &v
	}
	if o.DeliveryFailureCause != nil {
		v := *o.DeliveryFailureCause
		c.DeliveryFailureCause = &v
	}
	c.DiagnosticInfo = append([]byte(nil), o.DiagnosticInfo...)
	c.SMRPUI = append([]byte(nil), o.SMRPUI...)
	return c
}

func MTDelivered(rpui []byte) MTOutcome {
	return MTOutcome{ResultCode: diam.Success, SMRPUI: append([]byte(nil), rpui...)}
}

// MTBaseResult is for MME-side faults that have no TS 29.338 meaning.
func MTBaseResult(code uint32) MTOutcome { return MTOutcome{ResultCode: code} }

func MTAbsentUser(diagnostic uint32) MTOutcome {
	return MTOutcome{ExperimentalResultCode: ResultErrorAbsentUser, AbsentUserDiagnostic: &diagnostic}
}

func MTUserBusy() MTOutcome { return MTOutcome{ExperimentalResultCode: ResultErrorUserBusyForMTSMS} }

func MTDeliveryFailure(cause uint32, diagnosticInfo []byte) MTOutcome {
	return MTOutcome{ExperimentalResultCode: ResultErrorSMDeliveryFailure, DeliveryFailureCause: &cause, DiagnosticInfo: append([]byte(nil), diagnosticInfo...)}
}
