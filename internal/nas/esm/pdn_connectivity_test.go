package esm

import (
	"bytes"
	"net"
	"testing"
)

func TestDecodePDNConnectivityRequestPCO(t *testing.T) {
	raw := []byte{
		0x02, 0x01, MsgPDNConnectivityRequest,
		0x11,
		0xd1,
		0x27, 0x06, 0x80, 0x80, 0x21, 0x10, 0x01, 0x00,
	}

	req := DecodePDNConnectivityRequest(raw)
	if req == nil {
		t.Fatal("DecodePDNConnectivityRequest returned nil")
	}
	if req.ProcedureTransactionID != 1 {
		t.Fatalf("PTI got %d, want 1", req.ProcedureTransactionID)
	}
	if req.RequestType != 1 {
		t.Fatalf("request type got %d, want 1", req.RequestType)
	}
	if req.PDNType != PDNTypeIPv4 {
		t.Fatalf("PDN type got %d, want IPv4", req.PDNType)
	}
	wantPCO := []byte{0x80, 0x80, 0x21, 0x10, 0x01, 0x00}
	if !bytes.Equal(req.PCO, wantPCO) {
		t.Fatalf("PCO got %x, want %x", req.PCO, wantPCO)
	}
}

func TestDecodePDNConnectivityRequestIMSFixture(t *testing.T) {
	raw := []byte{
		0x02, 0x01, MsgPDNConnectivityRequest, 0x31,
		0x28, 0x04, 0x03, 'i', 'm', 's',
		0x27, 0x23,
		0x80, 0x80, 0x21, 0x10, 0x01, 0x01, 0x00, 0x10,
		0x81, 0x06, 0x00, 0x00, 0x00, 0x00, 0x83, 0x06,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
		0x03, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x0d, 0x00,
		0x00, 0x10, 0x00,
	}
	req := DecodePDNConnectivityRequest(raw)
	if req == nil {
		t.Fatal("DecodePDNConnectivityRequest returned nil")
	}
	if req.EPSBearerID != 0 {
		t.Fatalf("EBI got %d, want 0", req.EPSBearerID)
	}
	if req.ProcedureTransactionID != 1 {
		t.Fatalf("PTI got %d, want 1", req.ProcedureTransactionID)
	}
	if req.PDNType != PDNTypeIPv4v6 {
		t.Fatalf("PDN type got %d, want IPv4v6", req.PDNType)
	}
	if req.RequestType != 1 {
		t.Fatalf("request type got %d, want initial request", req.RequestType)
	}
	if req.APN != "ims" {
		t.Fatalf("APN got %q, want ims", req.APN)
	}
	wantPCO := raw[12:]
	if !bytes.Equal(req.PCO, wantPCO) {
		t.Fatalf("PCO got %x, want %x", req.PCO, wantPCO)
	}
}

func TestDecodePDNConnectivityRequestCombinedRequestAndPDNType(t *testing.T) {
	tests := []struct {
		name            string
		combined        byte
		wantRequestType uint8
		wantPDNType     uint8
	}{
		{name: "Nokia IMS IPv4v6 initial", combined: 0x31, wantRequestType: 1, wantPDNType: PDNTypeIPv4v6},
		{name: "IPv4 initial", combined: 0x11, wantRequestType: 1, wantPDNType: PDNTypeIPv4},
		{name: "IPv6 initial", combined: 0x21, wantRequestType: 1, wantPDNType: PDNTypeIPv6},
		{name: "handover IPv4v6", combined: 0x32, wantRequestType: 2, wantPDNType: PDNTypeIPv4v6},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := DecodePDNConnectivityRequest([]byte{0x02, 0x02, MsgPDNConnectivityRequest, tt.combined})
			if req == nil {
				t.Fatal("DecodePDNConnectivityRequest returned nil")
			}
			if got := req.RequestType; got != tt.wantRequestType {
				t.Fatalf("request type got %d, want %d", got, tt.wantRequestType)
			}
			if got := req.PDNType; got != tt.wantPDNType {
				t.Fatalf("PDN type got %d, want %d", got, tt.wantPDNType)
			}
		})
	}
}

func TestEncodeActivateDefaultEPSBearerContextRequestVector(t *testing.T) {
	got := EncodePDNConnectivityAccept(1, "internet", 5, net.IP{100, 64, 0, 241})
	want := []byte{
		0x52, 0x01, MsgActivateDefaultEPSBearerContextRequest,
		0x01, 0x09,
		0x09, 0x08, 'i', 'n', 't', 'e', 'r', 'n', 'e', 't',
		0x05, PDNTypeIPv4, 0x64, 0x40, 0x00, 0xf1,
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("Activate Default EPS Bearer Context Request got %x, want %x", got, want)
	}
}

func TestEncodeActivateDefaultEPSBearerContextRequestIncludesPCO(t *testing.T) {
	pco := []byte{0x80, 0x00, 0x0d, 0x04, 0x01, 0x01, 0x01, 0x01}
	got := EncodePDNConnectivityAcceptWithPCO(1, "internet", 5, net.IP{100, 64, 0, 241}, pco)
	wantSuffix := append([]byte{0x27, byte(len(pco))}, pco...)
	if !bytes.HasSuffix(got, wantSuffix) {
		t.Fatalf("Activate Default EPS Bearer Context Request suffix got %x, want suffix %x", got, wantSuffix)
	}
}

func TestEncodeActivateDefaultEPSBearerContextRequestUsesSubscribedQCIAndAPNAMBR(t *testing.T) {
	got := EncodePDNConnectivityAcceptWithQoS(1, "ims.mnc435.mcc311.gprs", 6, net.IP{10, 1, 2, 3}, 5, 3_850_000, 1_530_000, nil)
	if got[3] != 1 || got[4] != 5 {
		t.Fatalf("EPS QoS got %x, want length=1 qci=5", got[3:5])
	}
	if !bytes.Contains(got, []byte{0x5e, 0x02, 0x8f, 0xb4}) {
		t.Fatalf("APN-AMBR got %x, want DL=0x8f UL=0xb4", got)
	}
}

func TestEncodeAPNAMBRExtendedRates(t *testing.T) {
	got, ok := encodeAPNAMBR(200_000_000, 50_000_000)
	if !ok || !bytes.Equal(got, []byte{0xfe, 0xfe, 0xde, 0x6c}) {
		t.Fatalf("200/50 Mbps APN-AMBR got %x ok=%t, want fefede6c", got, ok)
	}
	got, ok = encodeAPNAMBR(128_000, 128_000)
	if !ok || !bytes.Equal(got, []byte{0x48, 0x48}) {
		t.Fatalf("128 kbps APN-AMBR got %x ok=%t, want 4848", got, ok)
	}
}

func TestEncodeActivateDefaultBearerPDNTypeDowngradeCause(t *testing.T) {
	pco := []byte{0x80, 0x00, 0x0d, 0x00}
	base := EncodePDNConnectivityAcceptWithQoSAndCause(2, "ims.mnc435.mcc311.gprs", 6, net.IP{10, 150, 3, 193}, 5, 3_850_000, 1_530_000, ESMCausePDNTypeIPv4OnlyAllowed, pco)
	if !bytes.Contains(base, []byte{0x58, ESMCausePDNTypeIPv4OnlyAllowed}) {
		t.Fatalf("IPv4v6 to IPv4 cause missing from %x", base)
	}
	if !bytes.Contains(base, []byte{0x5e, 0x02, 0x8f, 0xb4, 0x58, ESMCausePDNTypeIPv4OnlyAllowed, 0x27, byte(len(pco))}) {
		t.Fatalf("downgrade cause ordering got %x, want APN-AMBR, cause, then PCO", base)
	}
	matched := EncodePDNConnectivityAcceptWithQoSAndCause(2, "ims.mnc435.mcc311.gprs", 6, net.IP{10, 150, 3, 193}, 5, 3_850_000, 1_530_000, 0, pco)
	if bytes.Contains(matched, []byte{0x58, ESMCausePDNTypeIPv4OnlyAllowed}) {
		t.Fatalf("unexpected downgrade cause in %x", matched)
	}
}

func TestEncodeIMSDefaultBearerInterworkingOptionsMatchesCiscoSemanticLayout(t *testing.T) {
	pco := []byte{
		0x80, 0x00, 0x0d, 0x04, 0x0a, 0x5a, 0xfa, 0x0a,
		0x00, 0x0d, 0x04, 0x0a, 0x5a, 0xfa, 0x0c,
		0x00, 0x0c, 0x04, 0x0a, 0x5a, 0xfa, 0x32,
		0x80, 0x21, 0x10, 0x03, 0x01, 0x00, 0x10,
		0x81, 0x06, 0x0a, 0x5a, 0xfa, 0x0a,
		0x83, 0x06, 0x0a, 0x5a, 0xfa, 0x0c,
		0x00, 0x10, 0x02, 0x05, 0x78,
	}
	got := EncodePDNConnectivityAcceptWithQoSAndCauseAndOptionalIEs(
		2, "ims.mnc435.mcc311.gprs", 6, net.IP{10, 150, 3, 156}, 5,
		3_850_000, 1_530_000, ESMCausePDNTypeIPv4OnlyAllowed, pco,
		IMSDefaultBearerInterworkingOptions(3_850_000, 1_530_000),
	)
	want := []byte{
		0x62, 0x02, MsgActivateDefaultEPSBearerContextRequest,
		0x01, 0x05,
		0x17, 0x03, 'i', 'm', 's', 0x06, 'm', 'n', 'c', '4', '3', '5', 0x06, 'm', 'c', 'c', '3', '1', '1', 0x04, 'g', 'p', 'r', 's',
		0x05, PDNTypeIPv4, 0x0a, 0x96, 0x03, 0x9c,
		0x5d, 0x01, 0x10,
		0x30, 0x0c, 0x0b, 0x91, 0x1f, 0x73, 0x96, 0xb4, 0x8f, 0x76, 0x49, 0xff, 0xff, 0x10,
		0x32, 0x03,
		0x84,
		0x5e, 0x02, 0x8f, 0xb4,
		0x58, ESMCausePDNTypeIPv4OnlyAllowed,
		0x27, byte(len(pco)),
	}
	want = append(want, pco...)
	if !bytes.Equal(got, want) {
		t.Fatalf("Cisco-equivalent activation got %x, want %x", got, want)
	}

	decoded, err := DecodeActivateDefaultEPSBearerContextRequest(got)
	if err != nil {
		t.Fatalf("DecodeActivateDefaultEPSBearerContextRequest: %v", err)
	}
	if decoded.EPSBearerID != 6 || decoded.ProcedureTransactionID != 2 || decoded.QCI != 5 || decoded.APN != "ims.mnc435.mcc311.gprs" || !decoded.IPv4.Equal(net.IP{10, 150, 3, 156}) {
		t.Fatalf("unexpected mandatory fields: %+v", decoded)
	}
	if decoded.OptionalIEs.TransactionIdentifier == nil || *decoded.OptionalIEs.TransactionIdentifier != 1 {
		t.Fatalf("transaction identifier got %+v, want 1", decoded.OptionalIEs.TransactionIdentifier)
	}
	if decoded.OptionalIEs.LLCSAPI == nil || *decoded.OptionalIEs.LLCSAPI != 3 {
		t.Fatalf("LLC SAPI got %+v, want 3", decoded.OptionalIEs.LLCSAPI)
	}
	if decoded.OptionalIEs.RadioPriority == nil || *decoded.OptionalIEs.RadioPriority != 4 {
		t.Fatalf("radio priority got %+v, want 4", decoded.OptionalIEs.RadioPriority)
	}
	qos := decoded.OptionalIEs.NegotiatedQoS
	if qos == nil || qos.TrafficClass != 3 || qos.TrafficHandlingPriority != 1 || !qos.SignallingIndication || qos.MaximumSDUSize != 150 || qos.DeliveryOrder != 2 || qos.DeliveryOfErroneousSDUs != 3 || qos.ResidualBER != 7 || qos.SDUErrorRatio != 6 || qos.TransferDelay != 18 || qos.MaximumBitRateUplinkBps != 3_904_000 || qos.MaximumBitRateDownlinkBps != 1_536_000 || qos.GuaranteedBitRateUplinkBps != 0 || qos.GuaranteedBitRateDownlinkBps != 0 {
		t.Fatalf("unexpected Cisco-equivalent negotiated QoS: %+v", qos)
	}
	if !bytes.Equal(decoded.APNAMBR, []byte{0x8f, 0xb4}) || decoded.ESMCause != ESMCausePDNTypeIPv4OnlyAllowed || !bytes.Equal(decoded.PCO, pco) {
		t.Fatalf("optional fields got AMBR=%x cause=%#x PCO=%x", decoded.APNAMBR, decoded.ESMCause, decoded.PCO)
	}
}

func TestEncodeActivateDefaultBearerWithoutOptionalInterworkingIEsUnchanged(t *testing.T) {
	base := EncodePDNConnectivityAcceptWithQoSAndCause(2, "internet", 5, net.IP{10, 150, 3, 194}, 9, 50_000_000, 200_000_000, 0, []byte{0x80, 0x00, 0x0d})
	withEmptyOptions := EncodePDNConnectivityAcceptWithQoSAndCauseAndOptionalIEs(2, "internet", 5, net.IP{10, 150, 3, 194}, 9, 50_000_000, 200_000_000, 0, []byte{0x80, 0x00, 0x0d}, ActivateDefaultBearerOptionalIEs{})
	if !bytes.Equal(base, withEmptyOptions) {
		t.Fatalf("empty optional IEs changed activation: base=%x with_options=%x", base, withEmptyOptions)
	}
	for _, ie := range [][]byte{{0x5d, 0x01, 0x10}, {0x30, 0x0c}, {0x32, 0x03}, {0x84}} {
		if bytes.Contains(base, ie) {
			t.Fatalf("unexpected interworking IE %x in non-IMS activation %x", ie, base)
		}
	}
}

func TestDecodeActivateDefaultEPSBearerContextAccept(t *testing.T) {
	raw := []byte{0x52, 0x01, MsgActivateDefaultEPSBearerContextAccept}
	got, err := DecodeActivateDefaultEPSBearerContextAccept(raw)
	if err != nil {
		t.Fatalf("DecodeActivateDefaultEPSBearerContextAccept: %v", err)
	}
	if got.EPSBearerID != 5 {
		t.Fatalf("EBI got %d, want 5", got.EPSBearerID)
	}
	if got.ProcedureTransactionID != 1 {
		t.Fatalf("PTI got %d, want 1", got.ProcedureTransactionID)
	}
	if len(got.PCO) != 0 {
		t.Fatalf("PCO got %x, want empty", got.PCO)
	}
}

func TestDecodePDNConnectivityRequestESMInformationFlag(t *testing.T) {
	raw := []byte{
		0x02, 0x01, MsgPDNConnectivityRequest,
		0x31,
		0xd1,
		0x27, 0x03, 0x80, 0x00, 0x0d,
	}
	req := DecodePDNConnectivityRequest(raw)
	if req == nil {
		t.Fatal("DecodePDNConnectivityRequest returned nil")
	}
	if !req.ESMInformationRequired {
		t.Fatal("ESMInformationRequired=false, want true")
	}
	if req.ProcedureTransactionID != 1 || req.PDNType != PDNTypeIPv4v6 || req.RequestType != 1 {
		t.Fatalf("unexpected request: %+v", req)
	}
}

func TestESMInformationRequestResponse(t *testing.T) {
	req := EncodeESMInformationRequest(7)
	if want := []byte{0x02, 0x07, MsgESMInformationRequest}; !bytes.Equal(req, want) {
		t.Fatalf("ESM Information Request got %x, want %x", req, want)
	}

	resp, err := DecodeESMInformationResponse([]byte{
		0x02, 0x07, MsgESMInformationResponse,
		0x28, 0x09, 0x08, 'i', 'n', 't', 'e', 'r', 'n', 'e', 't',
		0x27, 0x03, 0x80, 0x00, 0x0d,
	})
	if err != nil {
		t.Fatalf("DecodeESMInformationResponse: %v", err)
	}
	if resp.ProcedureTransactionID != 7 || resp.APN != "internet" || !bytes.Equal(resp.PCO, []byte{0x80, 0x00, 0x0d}) {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestDecodePDNDisconnectRequest(t *testing.T) {
	raw := []byte{
		0x02, 0x03, MsgPDNDisconnectRequest, 0x06,
		0x27, 0x03, 0x80, 0x00, 0x0d,
	}
	req, err := DecodePDNDisconnectRequest(raw)
	if err != nil {
		t.Fatalf("DecodePDNDisconnectRequest: %v", err)
	}
	if req.EPSBearerID != 0 {
		t.Fatalf("EPSBearerID got %d, want 0", req.EPSBearerID)
	}
	if req.ProcedureTransactionID != 3 {
		t.Fatalf("PTI got %d, want 3", req.ProcedureTransactionID)
	}
	if req.LinkedEPSBearerID != 6 {
		t.Fatalf("linked EBI got %d, want 6", req.LinkedEPSBearerID)
	}
	if !bytes.Equal(req.PCO, []byte{0x80, 0x00, 0x0d}) {
		t.Fatalf("PCO got %x, want %x", req.PCO, []byte{0x80, 0x00, 0x0d})
	}
}
