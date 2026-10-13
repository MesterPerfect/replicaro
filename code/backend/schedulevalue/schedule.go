package schedulevalue

import (
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/robfig/cron/v3"
)

const MaxCustomMinutes int64 = math.MaxInt64 / int64(time.Minute)

// Bound calendar intervals to the existing custom-duration horizon, using
// the longest month so even the maximum interval fits that horizon.
const MaxCustomMonths = MaxCustomMinutes / (31 * 24 * 60)
const MaxCronExpressionLength = 256

const cronPrefix = "cron:"

var fiveFieldCronParser = cron.NewParser(
	cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow,
)

func CustomMinutes(value string) (int64, bool) {
	const prefix = "every:"
	if !strings.HasPrefix(value, prefix) {
		return 0, false
	}
	digits := strings.TrimPrefix(value, prefix)
	if digits == "" {
		return 0, false
	}
	for _, digit := range digits {
		if digit < '0' || digit > '9' {
			return 0, false
		}
	}
	minutes, err := strconv.ParseInt(digits, 10, 64)
	if err != nil || minutes <= 0 || minutes > MaxCustomMinutes {
		return 0, false
	}
	return minutes, true
}

// CustomMonths is a job-only calendar interval in the existing schedule field.
func CustomMonths(value string) (int, bool) {
	const prefix = "every-months:"
	if !strings.HasPrefix(value, prefix) {
		return 0, false
	}
	digits := strings.TrimPrefix(value, prefix)
	if digits == "" {
		return 0, false
	}
	for _, digit := range digits {
		if digit < '0' || digit > '9' {
			return 0, false
		}
	}
	months, err := strconv.ParseInt(digits, 10, 64)
	if err != nil || months <= 0 || months > MaxCustomMonths {
		return 0, false
	}
	return int(months), true
}

func Valid(value string) bool {
	switch value {
	case "", "manual", "hourly", "daily", "weekly", "monthly":
		return true
	default:
		_, valid := CustomMinutes(value)
		return valid
	}
}

// NormalizeJob accepts the ordinary schedule vocabulary, job-only calendar
// intervals, and standard five-field cron expressions. Cron is never
// installed into the host's system cron service.
func NormalizeJob(value string) (string, bool) {
	if Valid(value) {
		return value, true
	}
	if _, valid := CustomMonths(value); valid {
		return value, true
	}
	if !strings.HasPrefix(value, cronPrefix) {
		return "", false
	}
	rawExpression := strings.TrimPrefix(value, cronPrefix)
	if len(rawExpression) > MaxCronExpressionLength {
		return "", false
	}
	expression := strings.TrimSpace(rawExpression)
	if expression == "" {
		return "", false
	}
	fields := strings.Fields(expression)
	if len(fields) != 5 {
		return "", false
	}
	expression = strings.Join(fields, " ")
	schedule, err := fiveFieldCronParser.Parse(expression)
	if err != nil || schedule.Next(time.Now()).IsZero() {
		return "", false
	}
	return cronPrefix + expression, true
}

func ValidJob(value string) bool {
	_, valid := NormalizeJob(value)
	return valid
}

func CronExpression(value string) (string, bool) {
	normalized, valid := NormalizeJob(value)
	if !valid || !strings.HasPrefix(normalized, cronPrefix) {
		return "", false
	}
	return strings.TrimPrefix(normalized, cronPrefix), true
}

// NextCron returns the first occurrence of a cron job schedule after from,
// in the host computer's local time.
func NextCron(value string, from time.Time) (time.Time, bool) {
	return nextCronIn(value, from, time.Local)
}

func nextCronIn(value string, from time.Time, location *time.Location) (time.Time, bool) {
	expression, valid := CronExpression(value)
	if !valid {
		return time.Time{}, false
	}
	parsed, err := fiveFieldCronParser.Parse(expression)
	if err != nil {
		return time.Time{}, false
	}
	schedule, ok := parsed.(*cron.SpecSchedule)
	if !ok {
		return time.Time{}, false
	}
	// Cron fields name wall-clock readings. Search them on a clock that has
	// no daylight-saving changes (UTC holding the local readings) and then
	// place each match with localInstant. Searching the local clock directly
	// skips a reading that falls in the spring gap and matches a repeated
	// reading twice in the autumn.
	schedule.Location = time.UTC
	reading := wallClock(from.In(location))
	for {
		reading = schedule.Next(reading)
		if reading.IsZero() {
			return time.Time{}, false
		}
		// In the repeated autumn hour the first occurrence of a reading can
		// already be behind from; that reading has had its run.
		if next := localInstant(reading, location); next.After(from) {
			return next, true
		}
	}
}

// NextLocal steps a calendar schedule on the local clock: advance moves the
// wall-clock reading of from in location (given in UTC, which has no
// daylight-saving changes) to the next occurrence's reading, and the result
// is placed with localInstant. A schedule stepped this way keeps its local
// time of day, so a daily step is 23 or 25 hours across a daylight-saving
// change.
func NextLocal(from time.Time, location *time.Location, advance func(reading time.Time) time.Time) time.Time {
	return localInstant(advance(wallClock(from.In(location))), location)
}

// localInstant returns the instant a schedule uses for a local wall-clock
// reading: the date and clock fields of reading (its own location is ignored)
// read in location. A reading that a daylight-saving change skips runs at the
// first instant after the skipped period, and a reading that happens twice
// runs at its first occurrence, so a schedule runs once in both cases.
//
// time.Date leaves the choice between the two offsets unspecified for such
// readings, so the candidates on both sides of the nearest zone change are
// checked here instead.
func localInstant(reading time.Time, location *time.Location) time.Time {
	reading = wallClock(reading)
	year, month, day := reading.Date()
	hour, minute, second := reading.Clock()
	guess := time.Date(year, month, day, hour, minute, second, reading.Nanosecond(), location)
	first := time.Time{}
	consider := func(candidate time.Time) {
		if wallClock(candidate.In(location)).Equal(reading) && (first.IsZero() || candidate.Before(first)) {
			first = candidate
		}
	}
	consider(guess)
	start, end := guess.ZoneBounds()
	_, offset := guess.Zone()
	if !start.IsZero() {
		_, previous := start.Add(-time.Nanosecond).Zone()
		consider(guess.Add(time.Duration(offset-previous) * time.Second))
	}
	if !end.IsZero() {
		_, following := end.Zone()
		consider(guess.Add(time.Duration(offset-following) * time.Second))
	}
	if !first.IsZero() {
		return first
	}
	// The reading falls in a skipped period. The zone change that skipped it
	// is the first instant after it.
	if wallClock(guess).After(reading) {
		if !start.IsZero() {
			return start.In(location)
		}
	} else if !end.IsZero() {
		return end.In(location)
	}
	return guess
}

// wallClock keeps the date and clock fields of value in its own location and
// drops the location, so readings can be compared and stepped without
// daylight-saving changes.
func wallClock(value time.Time) time.Time {
	year, month, day := value.Date()
	hour, minute, second := value.Clock()
	return time.Date(year, month, day, hour, minute, second, value.Nanosecond(), time.UTC)
}
