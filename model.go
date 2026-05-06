package main

type EmailsResponse struct {
	Addresses []string       `json:"addresses"`
	Status    StatusResponse `json:"status"`
}

type StatusResponse struct {
	Code  int    `json:"code"`
	Title string `json:"title"`
	Msg   string `json:"message"`
}
