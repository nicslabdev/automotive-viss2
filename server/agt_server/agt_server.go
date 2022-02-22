/**
* (C) 2020 Geotab Inc
*
* All files and artifacts in the repository at https://github.com/MEAE-GOT/WAII
* are licensed under the provisions of the license provided by the LICENSE file in this repository.
*
**/

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/MEAE-GOT/WAII/utils"
	"github.com/akamensky/argparse"
)

type KeySet struct {
	PrvKey string
	PubKey string
}

var keySet KeySet

type Payload struct {
	Vin     string           `json:"vin"`
	Context string           `json:"context"`
	Proof   string           `json:"proof"`
	Key     utils.JsonWebKey `json:"key"`
}

var ChallengeCache map[string]Payload // jti is the map key

func makeAgtServerHandler(serverChannel chan string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		utils.Info.Printf("agtServer:url=%s", req.URL.Path)
		if req.URL.Path != "/agtserver" {
			http.Error(w, "404 url path not found.", 404)
		} else if req.Method != "POST" {
			http.Error(w, "400 bad request method.", 400)
		} else {
			bodyBytes, err := ioutil.ReadAll(req.Body)
			if err != nil {
				http.Error(w, "400 request unreadable.", 400)
			} else {
				utils.Info.Printf("agtServer:received POST request=%s\n", string(bodyBytes))
				serverChannel <- string(bodyBytes) // If everything works fine, sends to serverChannel the body
				response := <-serverChannel        // Receives the response and sends it
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

func initAgtServer(serverChannel chan string, muxServer *http.ServeMux) {
	utils.Info.Printf("initAtServer(): :7500/agtserver")
	agtServerHandler := makeAgtServerHandler(serverChannel)
	muxServer.HandleFunc("/agtserver", agtServerHandler) // Only one url is supported: "/agtserver"
	utils.Error.Fatal(http.ListenAndServe(":7500", muxServer))
}

func initKey(prvDirectory string, pubDirectory string) {
	prvFile, err := os.Open(prvDirectory) // Open pem file containing PEM block
	if err != nil {
		utils.Error.Printf("Error loading private key, should generate new keypair")
		return
	}
	prvFileInfo, _ := prvFile.Stat() // Creates a buffer to read all the data in the file
	size := prvFileInfo.Size()
	prvBytes := make([]byte, size)
	prvBuffer := bufio.NewReader(prvFile)
	_, err = prvBuffer.Read(prvBytes)
	keySet.PrvKey = string(prvBytes) // Saves Private Key in PEM format

	pubFile, err := os.Open(pubDirectory) // Same as Private Key
	if err != nil {
		utils.Error.Printf("Error loading public key, generating one")
		return
	}
	pubFileInfo, _ := pubFile.Stat()
	size = pubFileInfo.Size()
	pubBytes := make([]byte, size)
	pubBuffer := bufio.NewReader(pubFile)
	_, err = pubBuffer.Read(pubBytes)
	keySet.PubKey = string(pubBytes)
}

// GenerateResponse must unmarshall the payload after checking what type of payload it is.
// Can be simple agt request (resp : agt), long term agt request (resp: challenge) or proof of possesion (resp: lt agt)
func generateResponse(input string) string {
	var payload Payload
	err := json.Unmarshal([]byte(input), &payload) // Unmarshal json received
	if err != nil {
		var popToken utils.PopToken
		err = popToken.Unmarshal(input)
		if err != nil {
			utils.Error.Printf("generateResponse:error: %s ; input=%s", err, input)
			return `{"error": "Client request malformed"}`
		}
		return generateLTAgt(popToken)
	}
	if authenticateClient(payload) == true { // If unmarshall is succesful, proceeds to authenticate the client
		if payload.Key != (utils.JsonWebKey{}) {
			return generateChallenge(payload)
		} else {
			return generateAgt(payload)
		}
	}
	return `{"error": "Client authentication failed"}`
}

func checkUserRole(userRole string) bool {
	if userRole != "OEM" && userRole != "Dealer" && userRole != "Independent" && userRole != "Owner" && userRole != "Driver" && userRole != "Passenger" {
		return false
	}
	return true
}

func checkAppRole(appRole string) bool {
	if appRole != "OEM" && appRole != "Third party" {
		return false
	}
	return true
}

func checkDeviceRole(deviceRole string) bool {
	if deviceRole != "Vehicle" && deviceRole != "Nomadic" && deviceRole != "Cloud" {
		return false
	}
	return true
}

func checkRoles(context string) bool {
	if strings.Count(context, "+") != 2 {
		return false
	}
	delimiter1 := strings.Index(context, "+")
	delimiter2 := strings.Index(context[delimiter1+1:], "+")
	if checkUserRole(context[:delimiter1]) == false || checkAppRole(context[delimiter1+1:delimiter1+1+delimiter2]) == false || checkDeviceRole(context[delimiter1+1+delimiter2+1:]) == false {
		return false
	}
	return true
}

func authenticateClient(payload Payload) bool {
	if checkRoles(payload.Context) == true && payload.Proof == "ABC" { // a bit too simple validation... Client should prove he is who he says he is. Proof of possesion now extist, authentication not.
		return true
	}
	return false
}

//https://datatracker.ietf.org/doc/html/draft-fett-oauth-dpop-03#section-7
// https://stackoverflow.com/questions/42588786/how-to-fingerprint-a-jwk

// Delete cached data after some time (this data is deleted if a long term AGT is generated or if no POP is returned)
func deleteTimer(mapId string, sec int) {
	time.Sleep(time.Duration(sec) * time.Second)
	if ChallengeCache != nil {
		delete(ChallengeCache, mapId)
	}
}

// Challenge consist in sending iat + uuid. Rest of claims are saved in a map.
func generateChallenge(payload Payload) string {
	// Saves data in the map
	if ChallengeCache == nil {
		ChallengeCache = make(map[string]Payload)
	}
	uuid, err := exec.Command("uuidgen").Output()
	if err != nil {
		utils.Error.Printf("generateAgt:Error generating uuid, err=%s", err)
		return `{"error": "Internal error"}`
	}
	uuid = uuid[:len(uuid)-1]
	ChallengeCache[string(uuid)] = payload
	go deleteTimer(string(uuid), 10)

	// Generates response from the data received
	var response string
	utils.JsonRecursiveMarshall("jti", string(uuid), &response)
	return response
}

// Generates long term access token from valid pop
func generateLTAgt(popToken utils.PopToken) string {
	claims, ok := ChallengeCache[popToken.Claims["jti"]]
	if !ok {
		utils.Error.Printf("generateLTAgt: Jti auth expired or invalid")
		return `{"error": "JTI expired or invalid"}`
	}

	if claims.Vin != popToken.Claims["vin"] || claims.Context != popToken.Claims["context"] {
		utils.Error.Printf("generate LTAgt: Claims are not the same associated with jti")
		return `{"error": "Claims received are not associated with that jti"}`
	}

	switch popToken.Alg() {
	case "RS256":
		if popToken.GetUnmarshalledPublicKey() != claims.Key {
			utils.Error.Printf("generate LTAgt: PubKey received is not the same as cached")
			return `{"error": "Key received is the associated with that jti"}`
		}
		if err := popToken.CheckSignature(); err != nil {
			utils.Error.Printf("generate LTAgt: Invalid signature")
			return `{"error": "Invalid signature"}`
		}

	//case "ES256":
	default:
		utils.Error.Printf("generate LTAgt: Invalid PopToken Algorithm")
		return `{"error": "Invalid signature algorithm"}`
	}

	return "well done"
}

func generateAgt(payload Payload) string {
	uuid, err := exec.Command("uuidgen").Output()
	if err != nil {
		utils.Error.Printf("generateAgt:Error generating uuid, err=%s", err)
		return `{"error": "Internal error"}`
	}
	uuid = uuid[:len(uuid)-1] // remove '\n' char
	iat := int(time.Now().Unix())
	exp := iat + 4*60*60 // 4 hours
	var jwtoken utils.JsonWebToken
	jwtoken.SetHeader("RS256")
	jwtoken.AddClaim("vin", payload.Vin)
	jwtoken.AddClaim("iat", strconv.Itoa(iat))
	jwtoken.AddClaim("exp", strconv.Itoa(exp))
	jwtoken.AddClaim("clx", payload.Context)
	jwtoken.AddClaim("aud", "w3org/gen2")
	jwtoken.AddClaim("jti", string(uuid))
	utils.Info.Printf("generateAgt:jwtHeader=%s", jwtoken.GetHeader())
	utils.Info.Printf("generateAgt:jwtPayload=%s", jwtoken.GetPayload())

	jwtoken.Encode()
	jwtoken.Sign(keySet.PrvKey)

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
	serverChan := make(chan string) // Communication between methods and dif process
	muxServer := http.NewServeMux() // ServeMux for routing
	initKey("security_keys/rsa_private_key.pem", "security_keys/rsa_public_key.pem")

	go initAgtServer(serverChan, muxServer)

	for {
		select {
		case request := <-serverChan:
			// Server is running concurrently, generateResponse is called when anything is received from it
			response := generateResponse(request)
			utils.Info.Printf("agtServer response=%s", response)
			serverChan <- response
		}
	}
}
