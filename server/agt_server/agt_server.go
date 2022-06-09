/**
* (C) 2020 Geotab Inc
*
* All files and artifacts in the repository at https://github.com/nicslabdev/automotive-viss2
* are licensed under the provisions of the license provided by the LICENSE file in this repository.
*
**/

package main

import (
	"crypto"
	"crypto/elliptic"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/akamensky/argparse"
	"github.com/google/uuid"
	"github.com/nicslabdev/automotive-viss2/utils"
)

var Policies struct {
	Connection       utils.Connectivity     `json:"conectivity"`
	SigningKey       utils.Key              `json:"signing_key"`
	PopCheckPolicies utils.PopCheck         `json:"PoP_Policies"`
	AgtGenPolicies   utils.AGTGenerate      `json:"AGT"`
	ManagerPolicies  utils.ManagementConfig `json:"Management"`
}

func writePolicies() {
	content, err := json.Marshal(Policies)
	if err != nil {
		utils.Error.Printf("Could not write policies: %s", err)
	}
	err = ioutil.WriteFile("agt_config.json", content, 0644)
	if err != nil {
		utils.Error.Printf("Could not write policies: %s", err)
	}
	utils.Info.Printf("Policies updated and saved")
}

func initPolicies() {
	content, err := ioutil.ReadFile("agt_config.json")
	if err != nil {
		utils.Error.Println("Error reading config file")
		log.Fatal(err)
	}
	err = json.Unmarshal(content, &Policies)
	if err != nil {
		utils.Error.Println("Error unmarshalling content of agt_config file")
		log.Fatal(err)
	}
	initKey()
}

// Load key from file, if not, creates new key file
func initKey() {
	switch Policies.SigningKey.Algorithm {
	case "RS256":
		if err := utils.ImportRsaKey(Policies.SigningKey.PrivKeyDir, &Policies.SigningKey.RsaPrivKey); err != nil {
			utils.Error.Printf("Error importing key, generating one.")
			genSignKey("RS256", 0)
		}
	case "ES256":
		if err := utils.ImportEcdsaKey(Policies.SigningKey.PrivKeyDir, &Policies.SigningKey.EcdsaPrivKey); err != nil {
			utils.Error.Printf("Error importing key generating one")
			genSignKey("ES256", 0)
		}
	default:
		utils.Error.Printf("Invalid key type: %s, generating RSA", Policies.SigningKey.Algorithm)
		genSignKey("RS256", 0)
	}
}

func genSignKey(alg string, lifetime int) {
	switch alg {
	case "RS256":
		if err := utils.GenRsaKey(256, &Policies.SigningKey.RsaPrivKey); err != nil {
			utils.Error.Printf("Error generating private key: %s. Signature not avaliable", err)
		} else { // Key generated correctly, saving it
			utils.Info.Printf("RSA key generated correctly")
			keyUuid := uuid.New()
			if err := utils.ExportKeyPair(Policies.SigningKey.RsaPrivKey, keyUuid.String()+".rsa", keyUuid.String()+".rsa.pub"); err != nil {
				utils.Error.Printf("Error exporting key: %s", err)
			} else {
				Policies.SigningKey.Algorithm = "RS256"
				Policies.SigningKey.PrivKeyDir = keyUuid.String() + ".rsa"
				Policies.SigningKey.PubKeyDir = keyUuid.String() + ".rsa.pub"
			}
		}
	case "ES256":
		if err := utils.GenEcdsaKey(elliptic.P256(), &Policies.SigningKey.EcdsaPrivKey); err != nil {
			utils.Error.Printf("Error generating private key: %s. Signature not avaliable", err)
		} else { // Key generated correctly, saving it
			utils.Info.Printf("ECDSA key generated correctly")
			keyUuid := uuid.New()
			if err := utils.ExportKeyPair(Policies.SigningKey.RsaPrivKey, keyUuid.String()+".ec", keyUuid.String()+".ec.pub"); err != nil {
				utils.Error.Printf("Error exporting key: %s", err)
			} else {
				Policies.SigningKey.Algorithm = "ES256"
				Policies.SigningKey.PrivKeyDir = keyUuid.String() + ".rsa"
				Policies.SigningKey.PubKeyDir = keyUuid.String() + ".rsa.pub"
			}
		}
	}
	writePolicies()
}

func getSignKey() crypto.PrivateKey {
	actTime := time.Now().Unix()
	if actTime > int64(Policies.SigningKey.Expiration) && Policies.SigningKey.Expiration != 0 {
		genSignKey(Policies.SigningKey.Algorithm, 0)
	}
	switch Policies.SigningKey.Algorithm {
	case "RS256":
		return Policies.SigningKey.RsaPrivKey
	case "ES256":
		return Policies.SigningKey.EcdsaPrivKey
	default:
		return nil
	}
}

// Stores a cache of the jwt ids received to not be reused
var popIDCache map[string]struct{}

type Payload struct {
	Vin     string `json:"vin"`
	Context string `json:"context"`
	Proof   string `json:"proof"`
	Key     string `json:"key"`
	PoP     utils.PopToken
}

func makeAgtServerHandler(serverChannel chan string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		utils.Info.Printf("agtServer:url=%s", req.URL.Path)
		if req.URL.Path != "/agts" {
			http.Error(w, "404 url path not found.", 404)
		} else if req.Method != "POST" {
			if req.Method == "OPTIONS" { //CORS POLICY, necessary for web client
				w.Header().Set("Access-Control-Allow-Origin", "*")
				w.Header().Set("Access-Control-Allow-Headers", "PoP")
				w.Header().Set("Access-Control-Allow-Methods", "POST")
				w.Header().Set("Access-Control-Max-Age", "57600")
			} else {
				http.Error(w, "400 bad request method.", 400)
			}
		} else {
			bodyBytes, err := ioutil.ReadAll(req.Body)
			if err != nil {
				http.Error(w, "400 request unreadable.", 400)
			} else {
				utils.Info.Printf("agtServer:received POST request=%s\n", string(bodyBytes))
				/*
					THE BODY MUST
					BE SENT ALONG -------------------------------------------------------------------------------------------------
					WITH THE POP
				*/
				serverChannel <- string(bodyBytes) // If everything works fine, sends to serverChannel the body
				// It is also necessary to send to serverChannel the POP (if it exists)
				pop := string(req.Header.Get("PoP"))
				if pop != "" {
					utils.Info.Printf("agtServer: received POP = %s", pop)
				}
				serverChannel <- pop
				response := <-serverChannel // Receives the response and sends it
				utils.Info.Printf("agtServer:POST response=%s", response)
				if len(response) == 0 {
					http.Error(w, "400 bad input.", 400)
				} else {
					w.Header().Set("Access-Control-Allow-Origin", "*")
					w.Header().Set("Content-Type", "application/json")
					w.Write([]byte(response))
				}
			}
		}
	}
}

// Initializes http server
func initAgtServer(serverChannel chan string, muxServer *http.ServeMux) {
	utils.Info.Printf("initAGTServer()%s, TLS: %t", Policies.Connection.ServingPort, Policies.Connection.TlsManagement.Use)
	agtServerHandler := makeAgtServerHandler(serverChannel)
	muxServer.HandleFunc("/agts", agtServerHandler)
	//muxServer.HandleFunc("/agtmanagement")
	if Policies.Connection.TlsManagement.Use {
		utils.Error.Fatal(http.ListenAndServeTLS(Policies.Connection.ServingPort, Policies.Connection.TlsManagement.CertDir,
			Policies.Connection.TlsManagement.KeyDir, muxServer))
	} else {
		utils.Error.Fatal(http.ListenAndServe(Policies.Connection.ServingPort, muxServer))
	}
}

// GenerateResponse must unmarshall the payload, then ask for AGT Generation
func generateResponse(input string, pop string) string {
	var payload Payload
	err := json.Unmarshal([]byte(input), &payload)
	if err != nil {
		utils.Error.Printf("generateResponse:error input=%s", input)
		return `{"error": "Client request malformed"}`
	}
	if authenticateClient(payload) {
		if pop != "" {
			return generateLTAgt(payload, pop)
		}
		return generateAgt(payload)
	}
	return `{"error": "Client authentication failed"}`
}

// Part of roles
func checkUserRole(userRole string) bool {
	for _, role := range Policies.AgtGenPolicies.ClientContext.User {
		if role == userRole {
			return true
		}
	}
	return false
}

// Part of user role
func checkAppRole(appRole string) bool {
	for _, role := range Policies.AgtGenPolicies.ClientContext.Application {
		if role == appRole {
			return true
		}
	}
	return false
}

// Part of user role
func checkDeviceRole(deviceRole string) bool {
	for _, role := range Policies.AgtGenPolicies.ClientContext.Device {
		if role == deviceRole {
			return true
		}
	}
	return false
}

// Part of user role
func checkRoles(context string) bool {
	if strings.Count(context, "+") != 2 {
		return false
	}
	delimiter1 := strings.Index(context, "+")
	delimiter2 := strings.Index(context[delimiter1+1:], "+")
	if !checkUserRole(context[:delimiter1]) || !checkAppRole(context[delimiter1+1:delimiter1+1+delimiter2]) || !checkDeviceRole(context[delimiter1+1+delimiter2+1:]) {
		return false
	}
	return true
}

// Client should prove he is who he says he is. Proof of possesion now exist, authentication not.
func authenticateClient(payload Payload) bool {
	if checkRoles(payload.Context) && payload.Proof == "ABC" { // a bit too simple validation...
		return true
	}
	return false
}

func deleteJti(jti string) {
	time.Sleep((time.Duration(Policies.PopCheckPolicies.TimeExp) + time.Duration(Policies.PopCheckPolicies.TimeMargin)) * time.Second)
	delete(popIDCache, jti)
}

// Checks if jwt id exist in cache, if it does, return false. If not, it adds it and automatically clear it from cache when it expires
func addCheckJti(jti string) bool {
	if popIDCache == nil { // If map is empty (first time), it doesnt even check, initializes and add
		popIDCache = make(map[string]struct{})
		popIDCache[jti] = struct{}{}
		go deleteJti(jti)
		return true
	}
	if _, ok := popIDCache[jti]; ok { // Check if jti exist in cache
		return false
	}
	// If we get here, it does not exist in cache
	popIDCache[jti] = struct{}{}
	go deleteJti(jti)
	return true
}

// Checks pop before doing anything
func generateLTAgt(payload Payload, pop string) string {
	var popToken utils.PopToken
	err := popToken.Unmarshal(pop)
	if err != nil {
		utils.Error.Printf("generateLTAgt: Error unmarshalling pop, err = %s", err)
		return `{"error": "Client request malformed"}`
	}
	if !addCheckJti(popToken.PayloadClaims["jti"]) {
		utils.Error.Printf("generateLTAgt: JTI used")
		return `{"error": "Repeated JTI"}`
	}
	err = popToken.CheckSignature()
	if err != nil {
		utils.Info.Printf("generateLTAgt: Invalid POP signature")
		return `{"error": "Invalid POP signature"}`
	}
	if ok, info := popToken.Validate(payload.Key, "vissv2/agts", Policies.PopCheckPolicies.TimeMargin, Policies.PopCheckPolicies.TimeExp); !ok {
		utils.Info.Printf("generateLTAgt: Not valid POP Token: %s", info)
		return `{"error": "Invalid POP Token"}`
	}
	// Generates the response token
	var jwtoken utils.JsonWebToken
	var unparsedId uuid.UUID
	if unparsedId, err = uuid.NewRandom(); err != nil { // Better way to generate uuid than calling an ext program
		utils.Error.Printf("generateAgt:Error generating uuid, err=%s", err)
		return `{"error": "Internal error"}`
	}
	iat := int(time.Now().Unix())
	exp := iat + Policies.AgtGenPolicies.TimeExpLT // Expiration time
	jwtoken.SetHeader(Policies.SigningKey.Algorithm)
	jwtoken.AddClaim("vin", payload.Vin) // No need to check if it is filled, if not, it does nothing (new imp makes this claim not mandatory)
	jwtoken.AddClaim("iat", strconv.Itoa(iat))
	jwtoken.AddClaim("exp", strconv.Itoa(exp))
	jwtoken.AddClaim("clx", payload.Context)
	jwtoken.AddClaim("aud", Policies.AgtGenPolicies.Audience)
	jwtoken.AddClaim("jti", unparsedId.String())
	jwtoken.AddClaim("pub", payload.Key)
	//utils.Info.Printf("generateAgt:jwtHeader=%s", jwtoken.GetHeader())
	//utils.Info.Printf("generateAgt:jwtPayload=%s", jwtoken.GetPayload())
	jwtoken.Encode()
	jwtoken.AssymSign(getSignKey())
	return `{"token":"` + jwtoken.GetFullToken() + `"}`
}

func generateAgt(payload Payload) string {
	var jwtoken utils.JsonWebToken
	uuid, err := exec.Command("uuidgen").Output()
	if err != nil {
		utils.Error.Printf("generateAgt:Error generating uuid, err=%s", err)
		return `{"error": "Internal error"}`
	}
	uuid = uuid[:len(uuid)-1] // remove '\n' char
	iat := int(time.Now().Unix())
	exp := iat + Policies.AgtGenPolicies.TimeExpST // 4 hours
	jwtoken.SetHeader(Policies.SigningKey.Algorithm)
	jwtoken.AddClaim("vin", payload.Vin)
	jwtoken.AddClaim("iat", strconv.Itoa(iat))
	jwtoken.AddClaim("exp", strconv.Itoa(exp))
	jwtoken.AddClaim("clx", payload.Context)
	jwtoken.AddClaim("aud", Policies.AgtGenPolicies.Audience)
	jwtoken.AddClaim("jti", string(uuid))
	utils.Info.Printf("generateAgt:jwtHeader=%s", jwtoken.GetHeader())
	utils.Info.Printf("generateAgt:jwtPayload=%s", jwtoken.GetPayload())
	jwtoken.Encode()
	jwtoken.AssymSign(getSignKey())
	return `{"token":"` + jwtoken.GetFullToken() + `"}`
}

func main() {
	// Create new parser object
	parser := argparse.NewParser("agt_server", "Process that simulates the behaviour of the Access Grant Server")
	// Create string flag
	logFile := parser.Flag("", "logfile", &argparse.Options{Required: false, Help: "outputs to logfile in ./logs folder"})
	logLevel := parser.Selector("", "loglevel", []string{"trace", "debug", "info", "warn", "error", "fatal", "panic"}, &argparse.Options{
		Required: false,
		Help:     "changes log output level",
		Default:  "info"})
	// Parse input
	err := parser.Parse(os.Args)
	if err != nil {
		fmt.Print(parser.Usage(err))
	}
	utils.InitLog("agtserver-log.txt", "./logs", *logFile, *logLevel)

	serverChan := make(chan string) // Communication between methods and different process
	muxServer := http.NewServeMux() // ServeMux for routing

	initPolicies()

	go initAgtServer(serverChan, muxServer)
	for {
		//select {
		//case request := <-serverChan:
		request := <-serverChan
		pop := <-serverChan
		// Server is running concurrently, generateResponse is called when anything is received from it
		response := generateResponse(request, pop)
		serverChan <- response
		//}
	}
}
