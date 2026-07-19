package timer

import "fmt"

const (
	DefaultT3402 = 720
	DefaultT3396 = 720
	DefaultT3412 = 3240
	DefaultT3423 = 720

	gprsTimerUnit2Seconds = 0
	gprsTimerUnit1Minute  = 1
	gprsTimerUnitDeciHour = 2

	gprsTimer3Unit2Seconds  = 0
	gprsTimer3Unit30Seconds = 1
	gprsTimer3Unit1Minute   = 2
	gprsTimer3Unit10Minutes = 3
	gprsTimer3Unit1Hour     = 4
	gprsTimer3Unit10Hours   = 5
	gprsTimer3Unit320Hours  = 6
)

// EncodeGPRSTimer encodes a TS 24.008 GPRS timer octet from seconds.
func EncodeGPRSTimer(sec int) (byte, error) {
	if sec <= 0 {
		return 0, fmt.Errorf("must be greater than 0 seconds")
	}
	if sec <= 63 {
		if sec%2 != 0 {
			return 0, fmt.Errorf("not a multiple of 2 seconds")
		}
		return encodeTimerOctet(gprsTimerUnit2Seconds, sec/2), nil
	}
	if sec%60 != 0 {
		return 0, fmt.Errorf("not a multiple of 1 minute")
	}
	minutes := sec / 60
	if minutes <= 31 {
		return encodeTimerOctet(gprsTimerUnit1Minute, minutes), nil
	}
	if minutes%6 != 0 {
		return 0, fmt.Errorf("not a multiple of 6 minutes")
	}
	decihours := minutes / 6
	if decihours <= 31 {
		return encodeTimerOctet(gprsTimerUnitDeciHour, decihours), nil
	}
	return 0, fmt.Errorf("overflow")
}

// EncodeGPRSTimer3 encodes a TS 24.008 GPRS timer 3 octet from seconds.
func EncodeGPRSTimer3(sec int) (byte, error) {
	if sec <= 0 {
		return 0, fmt.Errorf("must be greater than 0 seconds")
	}
	if sec <= 63 {
		if sec%2 != 0 {
			return 0, fmt.Errorf("not a multiple of 2 seconds")
		}
		return encodeTimerOctet(gprsTimer3Unit2Seconds, sec/2), nil
	}
	if sec%30 != 0 {
		return 0, fmt.Errorf("not a multiple of 30 seconds")
	}
	thirtySeconds := sec / 30
	if thirtySeconds <= 31 {
		return encodeTimerOctet(gprsTimer3Unit30Seconds, thirtySeconds), nil
	}
	if thirtySeconds%2 != 0 {
		return 0, fmt.Errorf("not a multiple of 1 minute")
	}
	minutes := thirtySeconds / 2
	if minutes <= 31 {
		return encodeTimerOctet(gprsTimer3Unit1Minute, minutes), nil
	}
	if minutes%10 != 0 {
		return 0, fmt.Errorf("not a multiple of 10 minutes")
	}
	tenMinutes := minutes / 10
	if tenMinutes <= 31 {
		return encodeTimerOctet(gprsTimer3Unit10Minutes, tenMinutes), nil
	}
	if tenMinutes%6 != 0 {
		return 0, fmt.Errorf("not a multiple of 1 hour")
	}
	hours := tenMinutes / 6
	if hours <= 31 {
		return encodeTimerOctet(gprsTimer3Unit1Hour, hours), nil
	}
	if hours%10 != 0 {
		return 0, fmt.Errorf("not a multiple of 10 hours")
	}
	tenHours := hours / 10
	if tenHours <= 31 {
		return encodeTimerOctet(gprsTimer3Unit10Hours, tenHours), nil
	}
	if hours%320 != 0 {
		return 0, fmt.Errorf("not a multiple of 320 hours")
	}
	threeTwentyHours := hours / 320
	if threeTwentyHours <= 31 {
		return encodeTimerOctet(gprsTimer3Unit320Hours, threeTwentyHours), nil
	}
	return 0, fmt.Errorf("overflow")
}

func encodeTimerOctet(unit int, value int) byte {
	return byte((unit << 5) | (value & 0x1f))
}
