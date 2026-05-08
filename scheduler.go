package main

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"
)

func runOnCronSchedule(ctx context.Context, app *App, now func() time.Time, schedule CronSchedule) error {
	if app == nil {
		return fmt.Errorf("app is required")
	}

	if now == nil {
		now = time.Now
	}

	for {
		runAt, err := nextCronRun(now(), schedule)
		if err != nil {
			return err
		}
		waitDuration := runAt.Sub(now())
		if waitDuration <= 0 {
			waitDuration = time.Second
		}

		log.Printf("next delete run scheduled at %s", runAt.Format(time.RFC3339))

		timer := time.NewTimer(waitDuration)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return nil
		case <-timer.C:
		}

		if err := app.Run(ctx); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			log.Printf("scheduled delete run failed: %v", err)
			continue
		}

		log.Printf("scheduled delete run completed")
	}
}

func parseCronSchedule(value string) (CronSchedule, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return CronSchedule{}, fmt.Errorf("cron must be an expression with 5 fields")
	}

	parts := strings.Fields(value)
	if len(parts) != 5 {
		return CronSchedule{}, fmt.Errorf("cron %q must have 5 cron fields", value)
	}

	minute, err := parseCronField(parts[0], 0, 59, false)
	if err != nil {
		return CronSchedule{}, fmt.Errorf("cron minute field: %w", err)
	}
	hour, err := parseCronField(parts[1], 0, 23, false)
	if err != nil {
		return CronSchedule{}, fmt.Errorf("cron hour field: %w", err)
	}
	dayOfMonth, err := parseCronField(parts[2], 1, 31, false)
	if err != nil {
		return CronSchedule{}, fmt.Errorf("cron day-of-month field: %w", err)
	}
	month, err := parseCronField(parts[3], 1, 12, false)
	if err != nil {
		return CronSchedule{}, fmt.Errorf("cron month field: %w", err)
	}
	dayOfWeek, err := parseCronField(parts[4], 0, 7, true)
	if err != nil {
		return CronSchedule{}, fmt.Errorf("cron day-of-week field: %w", err)
	}

	return CronSchedule{
		Minute:     minute,
		Hour:       hour,
		DayOfMonth: dayOfMonth,
		Month:      month,
		DayOfWeek:  dayOfWeek,
	}, nil
}

func parseCronField(value string, min int, max int, allowSevenAlias bool) (cronField, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return cronField{}, fmt.Errorf("field is required")
	}
	if value == "*" {
		return cronField{Any: true}, nil
	}

	field := cronField{Values: make(map[int]struct{})}
	segments := strings.Split(value, ",")
	for _, segment := range segments {
		segment = strings.TrimSpace(segment)
		if segment == "" {
			return cronField{}, fmt.Errorf("invalid empty segment")
		}

		base := segment
		step := 1
		hasStep := false
		if strings.Contains(segment, "/") {
			stepParts := strings.Split(segment, "/")
			if len(stepParts) != 2 || stepParts[0] == "" || stepParts[1] == "" {
				return cronField{}, fmt.Errorf("invalid step segment %q", segment)
			}
			base = stepParts[0]
			parsedStep, err := strconv.Atoi(stepParts[1])
			if err != nil || parsedStep <= 0 {
				return cronField{}, fmt.Errorf("invalid step value in %q", segment)
			}
			step = parsedStep
			hasStep = true
		}

		start := min
		end := max
		switch {
		case base == "*":
		case strings.Contains(base, "-"):
			rangeParts := strings.Split(base, "-")
			if len(rangeParts) != 2 || rangeParts[0] == "" || rangeParts[1] == "" {
				return cronField{}, fmt.Errorf("invalid range %q", base)
			}
			rangeStart, err := strconv.Atoi(rangeParts[0])
			if err != nil {
				return cronField{}, fmt.Errorf("invalid range start %q", rangeParts[0])
			}
			rangeEnd, err := strconv.Atoi(rangeParts[1])
			if err != nil {
				return cronField{}, fmt.Errorf("invalid range end %q", rangeParts[1])
			}
			start = rangeStart
			end = rangeEnd
		default:
			single, err := strconv.Atoi(base)
			if err != nil {
				return cronField{}, fmt.Errorf("invalid value %q", base)
			}
			start = single
			end = single
			if hasStep {
				end = max
			}
		}

		if start < min || start > max {
			return cronField{}, fmt.Errorf("value %d out of range [%d,%d]", start, min, max)
		}
		if end < min || end > max {
			return cronField{}, fmt.Errorf("value %d out of range [%d,%d]", end, min, max)
		}
		if start > end {
			return cronField{}, fmt.Errorf("range start %d is greater than end %d", start, end)
		}

		for item := start; item <= end; item++ {
			if (item-start)%step != 0 {
				continue
			}
			valueToStore := item
			if allowSevenAlias && item == 7 {
				valueToStore = 0
			}
			field.Values[valueToStore] = struct{}{}
		}
	}

	if len(field.Values) == 0 {
		return cronField{}, fmt.Errorf("field has no values")
	}

	return field, nil
}

func nextCronRun(value time.Time, schedule CronSchedule) (time.Time, error) {
	candidate := value.Truncate(time.Minute).Add(time.Minute)
	maxChecks := 5 * 366 * 24 * 60
	for check := 0; check < maxChecks; check++ {
		if schedule.matches(candidate) {
			return candidate, nil
		}
		candidate = candidate.Add(time.Minute)
	}

	return time.Time{}, fmt.Errorf("cron has no matching run time in next 5 years")
}

func (s CronSchedule) matches(value time.Time) bool {
	if !s.Minute.matches(value.Minute()) {
		return false
	}
	if !s.Hour.matches(value.Hour()) {
		return false
	}
	if !s.Month.matches(int(value.Month())) {
		return false
	}

	dayOfMonthMatch := s.DayOfMonth.matches(value.Day())
	dayOfWeekMatch := s.DayOfWeek.matches(int(value.Weekday()))
	switch {
	case s.DayOfMonth.Any && s.DayOfWeek.Any:
		return true
	case s.DayOfMonth.Any:
		return dayOfWeekMatch
	case s.DayOfWeek.Any:
		return dayOfMonthMatch
	default:
		return dayOfMonthMatch || dayOfWeekMatch
	}
}

func (f cronField) matches(value int) bool {
	if f.Any {
		return true
	}
	_, exists := f.Values[value]
	return exists
}
