// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// parseLifetime reads a lifetime like "30m", "12h" or "7d".
//
// time.ParseDuration has no day, because a day is not a fixed length of time in
// general. It is here: this is a number of seconds sent to an instance, not a
// calendar calculation, so "7d" means 168 hours and says what somebody means
// when they choose how long a link should live.
func parseLifetime(text string) (time.Duration, error) {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return 0, fmt.Errorf("no lifetime given")
	}

	if rest, found := strings.CutSuffix(trimmed, "d"); found {
		days, err := strconv.ParseFloat(rest, 64)
		if err != nil {
			return 0, fmt.Errorf("%q is not a number of days", text)
		}
		if days < 0 {
			return 0, fmt.Errorf("%q is negative", text)
		}
		return time.Duration(days * 24 * float64(time.Hour)), nil
	}

	d, err := time.ParseDuration(trimmed)
	if err != nil {
		return 0, fmt.Errorf(
			"%q is not a lifetime: use something like 30m, 12h or 7d", text)
	}
	if d < 0 {
		return 0, fmt.Errorf("%q is negative", text)
	}
	return d, nil
}
