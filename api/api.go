package api

import (
	"fmt"
	"net/http"
)

type ApiConfiguration struct {
	Address string
	Port    int
}

type Api struct {
	*http.Server
}

func NewAPI(address string, port int) *Api {
	return &Api{
		Server: &http.Server{
			Addr: fmt.Sprintf("%v:%v", address, port),
		},
	}
}
