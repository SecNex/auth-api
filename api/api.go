package api

import (
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/secnex/auth-api/auth"
)

type ApiConfiguration struct {
	Address string
	Port    int
}

type Api struct {
	Address        string
	Port           int
	TrustedProxies []TrustedProxy
}

type TrustedProxy string

func NewTrustedProxies() []TrustedProxy {
	return []TrustedProxy{}
}

func (a *Api) AddTrustedProxy(proxy string) {
	a.TrustedProxies = append(a.TrustedProxies, TrustedProxy(proxy))
}

func NewAPI(address string, port int, proxies []TrustedProxy) *Api {
	return &Api{
		Address:        address,
		Port:           port,
		TrustedProxies: proxies,
	}
}

func (a *Api) GETNewToken(w http.ResponseWriter, r *http.Request) {
	__auth := auth.NewAuthentication()
	__token, _ := __auth.GenerateToken()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf(`{"token": "%v", "expires_in": "%v", "header": "Bearer %v"}`, __token, __auth.ExpiresIn, __token)))
}

func (a *Api) POSTNewToken(w http.ResponseWriter, r *http.Request) {
	__auth := auth.NewAuthentication()
	__token, _ := __auth.GenerateToken()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf(`{"token": "%v", "expires_in": "%v", "header": "Bearer %v"}`, __token, __auth.ExpiresIn, __token)))
}

// HTTP function to create a new authentication token
func (a *Api) Token(w http.ResponseWriter, r *http.Request) {
	// Only allow GET or POST methods
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		result := ResultError{
			Code:    http.StatusMethodNotAllowed,
			Message: http.StatusText(http.StatusMethodNotAllowed),
			Error:   "Method not allowed",
		}
		w.Write([]byte(result.String()))
		return
	}
	if r.Method == http.MethodGet {
		a.GETNewToken(w, r)
		return
	}
	if r.Method == http.MethodPost {
		a.POSTNewToken(w, r)
		return
	}
}

func CheckTrustedProxies(next http.Handler, proxies []TrustedProxy) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyCount := len(proxies)
		log.Printf("Count of trusted proxies: %v", proxyCount)
		clientIP := extractIP(r)
		trusted := false
		if proxyCount > 0 {
			for _, proxy := range proxies {
				if string(proxy) == clientIP {
					log.Printf("Trusted proxy: %v", clientIP)
					trusted = true
					break
				}
			}
		} else {
			trusted = true
		}
		if !trusted {
			log.Printf("Unauthorized access from %v", r.RemoteAddr)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			result := ResultError{
				Code:    http.StatusUnauthorized,
				Message: http.StatusText(http.StatusUnauthorized),
				Error:   "Unauthorized access",
			}
			w.Write([]byte(result.String()))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *Api) Start() {
	r := http.NewServeMux()
	r.HandleFunc("/token/generate", a.Token)
	router := CheckTrustedProxies(r, a.TrustedProxies)
	http.ListenAndServe(fmt.Sprintf("%v:%v", a.Address, a.Port), router)
}

func extractIP(r *http.Request) string {
	clientIP := r.RemoteAddr
	if strings.Contains(clientIP, "[") || strings.Contains(clientIP, "]") {
		clientIP = strings.Split(clientIP, "]")[0]
		clientIP = strings.Split(clientIP, "[")[1]
	} else {
		clientIP = strings.Split(clientIP, ":")[0]
	}
	return clientIP
}
