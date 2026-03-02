package utils

import (
	"fmt"
	"time"
)

// ParseFlexibleTimestamp attempts to parse a timestamp in multiple formats
// to handle variations in Tenable API responses
func ParseFlexibleTimestamp(ts string) (time.Time, error) {
	// Try RFC3339 first (most common)
	if t, err := time.Parse(time.RFC3339, ts); err == nil {
		return t, nil
	}
	// Try RFC3339Nano
	if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
		return t, nil
	}
	// Try common date-only format
	if t, err := time.Parse("2006-01-02", ts); err == nil {
		return t, nil
	}
	// Try datetime without timezone
	if t, err := time.Parse("2006-01-02T15:04:05", ts); err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("unable to parse timestamp: %s", ts)
}
