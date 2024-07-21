package api

import (
	"fmt"
	"log"
	"net/http"

	"github.com/secnex/auth-api/auth"
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

func (a *Api) GETNewToken(w http.ResponseWriter, r *http.Request) {
	__auth := auth.NewAuthentication()
	__token, __hash := __auth.GenerateToken()
	log.Printf("Generating token: %v", __hash)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf(`{"token": "%v", "expires_in": "%v", "header": "Bearer %v"}`, __token, __auth.ExpiresIn, __token)))
}

// HTTP function to create a new authentication token
func (a *Api) Token(w http.ResponseWriter, r *http.Request) {
	// Only allow GET requests
	if r.Method != http.MethodGet {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Write([]byte(`{"error": "Method not allowed"}`))
		return
	}
	if r.Method == http.MethodGet {
		a.GETNewToken(w, r)
		return
	}
}

func (a *Api) Start() {
	http.HandleFunc("/token", a.Token)
	http.ListenAndServe(a.Addr, nil)
}
