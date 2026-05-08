package main

import "time"

func deleteCutoff(now time.Time, age int) time.Time {
	return startOfDay(now.AddDate(0, 0, -age)).AddDate(0, 0, 1)
}

func startOfDay(value time.Time) time.Time {
	year, month, day := value.Date()
	return time.Date(year, month, day, 0, 0, 0, 0, value.Location())
}
