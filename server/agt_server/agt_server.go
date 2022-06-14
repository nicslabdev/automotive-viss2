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
	"net/http/httputil"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/akamensky/argparse"
	"github.com/google/uuid"
	"github.com/nicslabdev/automotive-viss2/utils"
)

var Policies struct { // Policies and claims to check AGT Requests received
	Connection       utils.Connectivity     `json:"conectivity"`
	SigningKey       utils.Key              `json:"signing_key"`
	PopCheckPolicies utils.PopCheck         `json:"PoP_Policies"`
	AgtGenPolicies   utils.AGTGenerate      `json:"AGT"`
	ManagerPolicies  utils.ManagementConfig `json:"Management"`
}

var popIDCache map[string]struct{} // Cache of POP Ids not to be accepted

type AGTRequest struct { // The received payload of an AGT Request
	Vin     string `json:"vin"`
	Context string `json:"context"`
	Proof   string `json:"proof"`
	Key     string `json:"key"`
	PoP     utils.PopToken
}

type Response struct {
	Error      bool
	ErrCode    int
	ErrMessage string
	//In case of success
	Body    string
	Headers map[string]string
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

func genErrorMap(code string, message string) map[string]string {
	errMap := make(map[string]string)
	errMap["type"] = "error"
	errMap["errorMessage"] = message
	errMap["errorCode"] = code
	return errMap
}

func makeAgtServerHandler(serverChannel chan map[string]string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		utils.Info.Printf("agtServer:url=%s", req.URL.Path)
		reqDump, err := httputil.DumpRequestOut(req, true)
		if err != nil {
			http.Error(w, "400 request unreadable.", 400)
			utils.Info.Printf("agtServer: Received unreadable request")
			return
		}
		bodyBytes, err := ioutil.ReadAll(req.Body)
		if err != nil {
			http.Error(w, "400 request unreadable.", 400)
			utils.Info.Printf("agtServer: Received unreadable body request: %s", string(reqDump))
			return
		}
		utils.Info.Printf("agtServer: Received AGT request: %s", string(reqDump))
		switch req.Method {
		case "POST":
			reqMap := make(map[string]string)
			reqMap["typ"] = "agtRequest"
			reqMap["body"] = string(bodyBytes)
			reqMap["pop"] = req.Header.Get("PoP")
			serverChannel <- reqMap
			response := <-serverChannel
			if response["type"] == "error" {
				errCode, _ := strconv.Atoi(response["errorCode"])
				http.Error(w, response["errorMessage"], errCode)
				utils.Info.Printf("agtServer: Sending POST error Response")
				return
			} else {
				w.Header().Set("Content-Type", "application/json")
				utils.Info.Printf("agtServer: Sending POST Response: %s", response["response"])
				w.Write([]byte(response["response"]))
			}
		case "OPTIONS":
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Headers", "PoP")
			w.Header().Set("Access-Control-Allow-Methods", "POST")
			w.Header().Set("Access-Control-Max-Age", "57600")
			utils.Info.Printf("agtServer: Sending OPTIONS Response")
			return
		default:
			http.Error(w, "400 bad request method.", 400)
			utils.Info.Printf("agtServer: Sending 400 Error, bad method")
			return
		}
	}
}

func makeMgmServerHandler(managementChannel chan map[string]string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		utils.Info.Printf("agtServer:url=%s", req.URL.Path)
		reqDump, err := httputil.DumpRequestOut(req, true)
		if err != nil {
			http.Error(w, "400 request unreadable.", 400)
			utils.Info.Printf("agtServer: Received unreadable request")
			return
		}
		bodyBytes, err := ioutil.ReadAll(req.Body)
		if err != nil {
			http.Error(w, "400 request unreadable.", 400)
			utils.Info.Printf("agtServer: Received unreadable body request: %s", string(reqDump))
			return
		}
		utils.Info.Printf("agtServer: Received Management request: %s", string(reqDump))

		switch req.Method {
		case "POST":
			reqMap := make(map[string]string)
			reqMap["typ"] = "management"
			reqMap["body"] = string(bodyBytes)
			managementChannel <- reqMap
			response := <-managementChannel
			utils.Info.Printf("agtServer: response=%s", response["response"])
			if response["type"] == "error" {
				errCode, _ := strconv.Atoi(response["errorCode"])
				http.Error(w, response["errorMessage"], errCode)
				utils.Info.Printf("agtServer: Sending error Response")
				return
			} else {
				w.Header().Set("Content-Type", "application/json")
				utils.Info.Printf("agtServer: Sending Response: %s", response["response"])
				w.Write([]byte(response["response"]))
			}
		case "OPTIONS":
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization")
			w.Header().Set("Access-Control-Allow-Methods", "POST, GET")
			w.Header().Set("Access-Control-Max-Age", "57600")
		default:
			http.Error(w, "400 bad request method.", 400)
			utils.Info.Printf("agtServer: Sending 400 Error, bad Method")
			return
		}
	}
}

// Initializes http server
func initAgtServer(serverChannel chan map[string]string, mgmChannel chan map[string]string, muxServer *http.ServeMux) {
	utils.Info.Printf("initAGTServer()%s, TLS: %t", Policies.Connection.ServingPort, Policies.Connection.TlsManagement.Use)
	agtServerHandler := makeAgtServerHandler(serverChannel)
	muxServer.HandleFunc("/agts", agtServerHandler)
	mgmServerHandler := makeMgmServerHandler(mgmChannel)
	muxServer.HandleFunc("/management", mgmServerHandler)
	//muxServer.HandleFunc("/agtmanagement")
	if Policies.Connection.TlsManagement.Use {
		utils.Error.Fatal(http.ListenAndServeTLS(Policies.Connection.ServingPort, Policies.Connection.TlsManagement.CertDir,
			Policies.Connection.TlsManagement.KeyDir, muxServer))
	} else {
		utils.Error.Fatal(http.ListenAndServe(Policies.Connection.ServingPort, muxServer))
	}
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

// Check Client Proof
func checkProof(proof string, context string) bool {
	if proof == "ABC" {
		return true
	} else {
		return false
	}
}

// Client should prove he is who he says he is. Proof of possesion now exist, authentication not.
func authenticateClient(request AGTRequest) bool {
	if checkRoles(request.Context) && checkProof(request.Proof, request.Context) { // a bit too simple validation...
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
func generateAgtResponse(request map[string]string) map[string]string {
	longTerm := false
	var agtRequest AGTRequest
	if err := json.Unmarshal([]byte(request["body"]), &agtRequest); err != nil {
		utils.Error.Printf("generateResponse: unvalid request")
		return genErrorMap("400", `{"error": "Client request malformed"}`)
	}
	if request["pop"] != "" {
		longTerm = true
		if err := agtRequest.PoP.Unmarshal(request["pop"]); err != nil {
			utils.Error.Printf("generateResponse: Error unmarshalling pop, err = %s", err)
			return genErrorMap("400", `{"error": "Proof of possession malformed"}`)
		}
		if !addCheckJti(agtRequest.PoP.PayloadClaims["jti"]) {
			utils.Error.Printf("generateLTAgt: JTI used")
			return genErrorMap("400", `{"error": "Repeated JTI"}`)
		}
		if err := agtRequest.PoP.CheckSignature(); err != nil {
			utils.Info.Printf("generateLTAgt: Invalid POP signature")
			return genErrorMap("400", `{"error": "Repeated JTI"}`)
		}
		if ok, info := agtRequest.PoP.Validate(agtRequest.Key, Policies.PopCheckPolicies.Audience, Policies.PopCheckPolicies.TimeMargin, Policies.PopCheckPolicies.TimeExp); !ok {
			utils.Info.Printf("generateLTAgt: Not valid POP Token: %s", info)
			return genErrorMap("400", `{"error": "Invalid POP Token"}`)
		}
	}
	if !authenticateClient(agtRequest) {
		utils.Info.Printf("generateLTAgt: Can not Authenticate Client context")
		return genErrorMap("400", `{"error": "Could not Authenticate Context"}`)
	}

	// Generates the response token
	var jwtoken utils.JsonWebToken
	var unparsedId uuid.UUID
	var err error
	if unparsedId, err = uuid.NewRandom(); err != nil { // Better way to generate uuid than calling an ext program
		utils.Error.Printf("generateAgt:Error generating uuid, err=%s", err)
		return genErrorMap("500", `{"error": "Internal error"}`)
	}
	jwtoken.SetHeader(Policies.SigningKey.Algorithm)
	jwtoken.AddClaim("vin", agtRequest.Vin) // No need to check if it is filled, if not, it does nothing (new imp makes this claim not mandatory)
	jwtoken.AddClaim("clx", agtRequest.Context)
	jwtoken.AddClaim("aud", Policies.AgtGenPolicies.Audience)
	jwtoken.AddClaim("jti", unparsedId.String())
	iat := int(time.Now().Unix())
	exp := iat + Policies.AgtGenPolicies.TimeExpST // Expiration time
	if longTerm {
		jwtoken.AddClaim("pub", agtRequest.Key)
		exp = iat + Policies.AgtGenPolicies.TimeExpLT // Expiration time
	}
	jwtoken.AddClaim("iat", strconv.Itoa(iat))
	jwtoken.AddClaim("exp", strconv.Itoa(exp))
	jwtoken.Encode()
	jwtoken.AssymSign(getSignKey())
	response := make(map[string]string)
	response["type"] = "response"
	response["response"] = `{"token":"` + jwtoken.GetFullToken() + `"}`
	return response
}

func generateManagementResponse(request map[string]string) map[string]string {
	// First, check management authorization. Management Key is in the JSON.
	//var receivedRequest utils.PopToken
	//receivedRequest.Unmarshal(request["body"])
	//receivedRequest.CheckManualSignature()
	//receivedRequest.CheckIat()
	//receivedRequest.CheckAud()

	//var requestList map[string]([]string)
	//json.Unmarshal([]byte(receivedRequest.PayloadClaims["toDo"]), &requestList)
	/*
		for _, value := range requestList["post"] {
			route := strings.SplitAfter(value, "/")
			var point interface{}
			point = &Policies
			for _, subroute := range route {
				if point != nil && point[subroute] != nil {
					if !strings.Contains(subroute, "=") {
						switch t := *point.(type){
						case struct:

						case map:

						}
						point = &point[Policies]
					} else {
						sep := strings.SplitAfter(subroute, "=")
						point[sep[0]] = sep[1]
					}
				} else {
					// UNVALID
				}
			}
		}

		for element := range requestList["get"] {
			route := strings.SplitAfter(element)
			for index := range route {

			}
		}*/
	response := make(map[string]string)
	response["type"] = "response"
	response["response"] = "managementresponse"
	return response
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

	serverChan := make(chan map[string]string)     // Communication between AGT Request methods
	managementChan := make(chan map[string]string) // Communication between management methods
	muxServer := http.NewServeMux()                // ServeMux for routing

	initPolicies()

	go initAgtServer(serverChan, managementChan, muxServer)
	for {
		select {
		case AGRequest := <-serverChan:
			response := generateAgtResponse(AGRequest)
			serverChan <- response
		case mgmRequest := <-managementChan:
			response := generateManagementResponse(mgmRequest)
			serverChan <- response
		}
	}
}
