package hazexpired

import (
	"testing"
	"time"
)

func TestFetchChainInvalidAddress(t *testing.T) {
	_, err := FetchChain("iamateapot:418")
	if err == nil {
		t.Errorf("Expected failure when calling with an invalid address, err is nil")
	}
}

func TestExpiredInvalidAddress(t *testing.T) {
	_, err := Expired("iamateapot:418")
	if err == nil {
		t.Errorf("Expected failure when calling with an invalid address, err is nil")
	}
}

func TestExpiresWithinDaysInvalidAddress(t *testing.T) {
	_, err := ExpiresWithinDays("iamateapot:418", 30)
	if err == nil {
		t.Errorf("Expected failure when calling with an invalid address, err is nil")
	}
}

func TestExpiresBeforeDateInvalidAddress(t *testing.T) {
	_, err := ExpiresBeforeDate("iamateapot:418", time.Now())
	if err == nil {
		t.Errorf("Expected failure when calling with an invalid address, err is nil")
	}
}
