package main

import (
	"context"
	"io"
	"time"

	"github.com/lechefran/mailbin"
)

type App struct {
	Accounts          []ConfiguredAccount
	GetEmailAddresses func(context.Context) (EmailsResponse, error)
	Delete            func(context.Context, mailbin.Config, mailbin.DeleteCriteria) (mailbin.DeleteResult, error)
	Timeout           time.Duration
	DefaultAge        int
	Now               func() time.Time
	Output            io.Writer
}

type accountDeleteResult struct {
	AccountName string
	Result      mailbin.DeleteResult
	Err         error
}

type indexedAccountDeleteResult struct {
	Index  int
	Result accountDeleteResult
}

type CronSchedule struct {
	Minute     cronField
	Hour       cronField
	DayOfMonth cronField
	Month      cronField
	DayOfWeek  cronField
}

type cronField struct {
	Any    bool
	Values map[int]struct{}
}

type EmailsResponse struct {
	Addresses []string       `json:"addresses"`
	Status    StatusResponse `json:"status"`
}

type StatusResponse struct {
	Code  int    `json:"code"`
	Title string `json:"title"`
	Msg   string `json:"message"`
}
