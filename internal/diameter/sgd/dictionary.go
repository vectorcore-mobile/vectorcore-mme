package sgd

import (
	"bytes"
	"fmt"
	"sync"

	"github.com/fiorix/go-diameter/v4/diam/dict"
)

var (
	sgdDictionaryOnce sync.Once
	sgdDictionaryErr  error
)

// EnsureDictionary loads the SGd application into the same dictionary used by
// the shared Diameter client/server. go-diameter needs commands registered to
// decode a received header; constructing an outbound message does not do so.
func EnsureDictionary() error {
	sgdDictionaryOnce.Do(func() {
		sgdDictionaryErr = dict.Default.Load(bytes.NewBufferString(sgdDictionaryXML))
	})
	return sgdDictionaryErr
}

func init() {
	if err := EnsureDictionary(); err != nil {
		panic(fmt.Sprintf("sgd: load Diameter dictionary: %v", err))
	}
}

// Keep this dictionary intentionally small and local. It declares every
// command and AVP that this MME decodes on SGd, including base AVPs because
// go-diameter's fast receive lookup does not inherit base AVPs for this app.
const sgdDictionaryXML = `<?xml version="1.0" encoding="UTF-8"?>
<diameter>
  <application id="16777313" type="auth" name="3GPP SGd">
    <vendor id="10415" name="3GPP"/>
    <command code="8388645" short="OF" name="MO-Forward-Short-Message">
      <request><rule avp="AVP" required="false"/></request>
      <answer><rule avp="AVP" required="false"/></answer>
    </command>
    <command code="8388646" short="TF" name="MT-Forward-Short-Message">
      <request><rule avp="AVP" required="false"/></request>
      <answer><rule avp="AVP" required="false"/></answer>
    </command>
    <command code="8388648" short="AL" name="Alert-Service-Centre">
      <request><rule avp="AVP" required="false"/></request>
      <answer><rule avp="AVP" required="false"/></answer>
    </command>

    <avp name="Session-Id" code="263" vendor-id="0" must="M" may-encrypt="N"><data type="UTF8String"/></avp>
    <avp name="User-Name" code="1" vendor-id="0" must="M" may-encrypt="N"><data type="UTF8String"/></avp>
    <avp name="Result-Code" code="268" vendor-id="0" must="M" may-encrypt="N"><data type="Unsigned32"/></avp>
    <avp name="Auth-Session-State" code="277" vendor-id="0" must="M" may-encrypt="N"><data type="Enumerated"/></avp>
    <avp name="Origin-Host" code="264" vendor-id="0" must="M" may-encrypt="N"><data type="DiameterIdentity"/></avp>
    <avp name="Origin-Realm" code="296" vendor-id="0" must="M" may-encrypt="N"><data type="DiameterIdentity"/></avp>
    <avp name="Destination-Host" code="293" vendor-id="0" must="M" may-encrypt="N"><data type="DiameterIdentity"/></avp>
    <avp name="Destination-Realm" code="283" vendor-id="0" must="M" may-encrypt="N"><data type="DiameterIdentity"/></avp>
    <avp name="MSISDN" code="701" vendor-id="10415" must="M,V" may-encrypt="N"><data type="OctetString"/></avp>
    <avp name="MME-Number-for-MT-SMS" code="1645" vendor-id="10415" must="M,V" may-encrypt="N"><data type="OctetString"/></avp>
    <avp name="User-Identifier" code="3102" vendor-id="10415" must="M,V" may-encrypt="N"><data type="Grouped"><rule avp="AVP" required="false"/></data></avp>
    <avp name="SC-Address" code="3300" vendor-id="10415" must="M,V" may-encrypt="N"><data type="OctetString"/></avp>
    <avp name="SM-RP-UI" code="3301" vendor-id="10415" must="M,V" may-encrypt="N"><data type="OctetString"/></avp>
    <avp name="SMSMI-Correlation-ID" code="3324" vendor-id="10415" must="M,V" may-encrypt="N"><data type="OctetString"/></avp>
  </application>
</diameter>`
