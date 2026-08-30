package schedule

import (
	"errors"
	"strconv"
	"strings"
	"time"
)

type field struct {
	allowed    map[int]bool
	restricted bool
}

type expression struct {
	minute, hour, day, month, weekday field
}

var monthNames = map[string]int{"jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6, "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12}
var weekdayNames = map[string]int{"sun": 0, "mon": 1, "tue": 2, "wed": 3, "thu": 4, "fri": 5, "sat": 6}

// Next validates a standard five-field cron expression and IANA timezone and
// returns the next UTC occurrence strictly after the supplied instant.
func Next(raw, timezone string, after time.Time) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 256 {
		return time.Time{}, errors.New("cron expression is required and must not exceed 256 bytes")
	}
	if timezone == "" {
		timezone = "UTC"
	}
	if len(timezone) > 128 {
		return time.Time{}, errors.New("timezone must not exceed 128 bytes")
	}
	location, err := time.LoadLocation(timezone)
	if err != nil {
		return time.Time{}, errors.New("timezone must be a valid IANA timezone")
	}
	spec, err := parse(raw)
	if err != nil {
		return time.Time{}, err
	}
	candidate := after.UTC().Truncate(time.Minute).Add(time.Minute)
	for checked := 0; checked < 5*366*24*60; checked++ {
		local := candidate.In(location)
		dayMatches := spec.day.allowed[local.Day()]
		weekdayMatches := spec.weekday.allowed[int(local.Weekday())]
		if spec.minute.allowed[local.Minute()] && spec.hour.allowed[local.Hour()] && spec.month.allowed[int(local.Month())] && dayRuleMatches(spec.day.restricted, spec.weekday.restricted, dayMatches, weekdayMatches) {
			return candidate, nil
		}
		candidate = candidate.Add(time.Minute)
	}
	return time.Time{}, errors.New("cron expression has no occurrence within five years")
}

func dayRuleMatches(dayRestricted, weekdayRestricted, dayMatches, weekdayMatches bool) bool {
	if dayRestricted && weekdayRestricted {
		return dayMatches || weekdayMatches
	}
	return dayMatches && weekdayMatches
}

func parse(raw string) (expression, error) {
	descriptors := map[string]string{
		"@yearly": "0 0 1 1 *", "@annually": "0 0 1 1 *", "@monthly": "0 0 1 * *",
		"@weekly": "0 0 * * 0", "@daily": "0 0 * * *", "@midnight": "0 0 * * *", "@hourly": "0 * * * *",
	}
	if expanded, ok := descriptors[strings.ToLower(raw)]; ok {
		raw = expanded
	}
	parts := strings.Fields(raw)
	if len(parts) != 5 {
		return expression{}, errors.New("invalid five-field cron expression")
	}
	minute, err := parseField(parts[0], 0, 59, nil, false)
	if err != nil {
		return expression{}, errors.New("invalid cron minute field")
	}
	hour, err := parseField(parts[1], 0, 23, nil, false)
	if err != nil {
		return expression{}, errors.New("invalid cron hour field")
	}
	day, err := parseField(parts[2], 1, 31, nil, false)
	if err != nil {
		return expression{}, errors.New("invalid cron day-of-month field")
	}
	month, err := parseField(parts[3], 1, 12, monthNames, false)
	if err != nil {
		return expression{}, errors.New("invalid cron month field")
	}
	weekday, err := parseField(parts[4], 0, 7, weekdayNames, true)
	if err != nil {
		return expression{}, errors.New("invalid cron day-of-week field")
	}
	return expression{minute: minute, hour: hour, day: day, month: month, weekday: weekday}, nil
}

func parseField(raw string, minimum, maximum int, names map[string]int, sundayAlias bool) (field, error) {
	result := field{allowed: map[int]bool{}, restricted: raw != "*"}
	for _, item := range strings.Split(strings.ToLower(raw), ",") {
		if item == "" {
			return field{}, errors.New("empty item")
		}
		base, stepText, hasStep := strings.Cut(item, "/")
		step := 1
		var err error
		if hasStep {
			step, err = strconv.Atoi(stepText)
			if err != nil || step < 1 || step > maximum-minimum+1 || strings.Contains(stepText, "/") {
				return field{}, errors.New("invalid step")
			}
		}
		start, end := minimum, maximum
		if base != "*" {
			left, right, ranged := strings.Cut(base, "-")
			start, err = fieldValue(left, names)
			if err != nil {
				return field{}, err
			}
			end = start
			if ranged {
				end, err = fieldValue(right, names)
				if err != nil || strings.Contains(right, "-") {
					return field{}, errors.New("invalid range")
				}
			} else if hasStep {
				end = maximum
			}
		}
		if start < minimum || end > maximum || start > end {
			return field{}, errors.New("value outside range")
		}
		for value := start; value <= end; value += step {
			if sundayAlias && value == 7 {
				result.allowed[0] = true
				continue
			}
			result.allowed[value] = true
		}
	}
	if len(result.allowed) == 0 {
		return field{}, errors.New("field has no values")
	}
	return result, nil
}

func fieldValue(raw string, names map[string]int) (int, error) {
	if value, ok := names[raw]; ok {
		return value, nil
	}
	return strconv.Atoi(raw)
}
