package main

import (
	"encoding/json"
	"io"
	"log"
	"os"

	"github.com/google/uuid"
	"github.com/secnex/auth-api/api"
	"github.com/secnex/auth-api/auth"
)

const appName = "AUTH"

type ConfigClient struct {
	ClientID     uuid.UUID `json:"id"`
	ClientSecret string    `json:"secret"`
}

type Config struct {
	Client ConfigClient `json:"client"`
}

func main() {
	log.Printf("Starting %v...", appName)
	// Test()
	if checkConfig() {
		byteData := readConfig()
		data := configToStruct(byteData)
		log.Printf("Config: %v", data)
		__token, __tokenHash := auth.NewAuthenticationWithID(data.Client.ClientID).GenerateTokenWithSecret(data.Client.ClientSecret)
		log.Printf("Authentication token: %v", __token)
		log.Printf("Authentication header: Bearer %v", __token)
		log.Printf("Authentication token hash: %v", __tokenHash)
		rmConfig()
	} else {
		// TOOD: Check if a client already exists, if not create a new one with default values and save it to the database
		log.Printf("Config not found! Check if a client already exists, if not create a new one with default values and save it to the database.")
	}
	proxies := api.NewTrustedProxies()
	__api := api.NewAPI("localhost", 8081, proxies)
	__api.AddTrustedProxy("127.0.0.1")
	__api.AddTrustedProxy("::1")
	__api.Start()
}

func Test(password string, hash string) {
	id, secret, _ := auth.Base64ToIDAndToken(password)
	log.Printf("ID: %v", id)
	log.Printf("Secret: %v", secret)
	VerifyTest(hash, secret)
}

func VerifyTest(hash string, password string) {
	log.Printf("Verifying test...")
	__hash := auth.NewDefaultHash()
	res, err := __hash.VerifyPassword(hash, password)
	if err != nil {
		log.Fatalf("Error verifying test: %v", err)
	}
	if res {
		log.Printf("Test verified!")
	} else {
		log.Fatalf("Test not verified!")
	}
}

// Check if config.json exists
func checkConfig() bool {
	log.Printf("Checking if config.json exists...")
	if _, err := os.Stat("config.json"); os.IsNotExist(err) {
		return false
	}
	return true
}

func readConfig() []byte {
	log.Printf("Reading config.json...")
	file, err := os.Open("config.json")
	if err != nil {
		log.Fatalf("Error reading config.json: %v", err)
	}
	defer file.Close()
	data, err := io.ReadAll(file)
	if err != nil {
		log.Fatalf("Error reading config.json: %v", err)
	}
	return data
}

func rmConfig() {
	log.Printf("Removing config.json...")
	err := os.Remove("config.json")
	if err != nil {
		log.Fatalf("Error removing config.json: %v", err)
	}
}

func configToStruct(data []byte) Config {
	log.Printf("Converting config.json to struct...")
	var config Config
	err := json.Unmarshal(data, &config)
	if err != nil {
		log.Fatalf("Error converting config.json to struct: %v", err)
	}
	return config
}
