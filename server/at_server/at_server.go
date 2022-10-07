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
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/akamensky/argparse"
	"github.com/google/uuid"
	"github.com/nicslabdev/automotive-viss2/utils"
)

// #include <stdlib.h>
// #include <stdint.h>
// #include <stdio.h>
// #include <stdbool.h>
// #include "cparserlib.h"
import "C"

var VSSTreeRoot C.long

// Files that will be imported
const BINARY_TREE_DIR = "vss_vissv2.binary" // Vehicle data tree
const POLICIES_DIR = "at_config.json"       // Policies and keys of the AT server

// set to MAXFOUNDNODES in cparserlib.h
const MAXFOUNDNODES = 1500

type searchData_t struct { // searchData_t defined in cparserlib.h
	path            [512]byte // cparserlib.h: #define MAXCHARSPATH 512; typedef char path_t[MAXCHARSPATH];
	foundNodeHandle int64     // defined as long in cparserlib.h
}
type NoScopePayload struct {
	Context string `json:"context"`
}
type AtValidatePayload struct {
	Token      string   `json:"token"`
	Paths      []string `json:"paths"`
	Action     string   `json:"action"`
	Validation string   `json:"validation"`
}

type AtRequest struct { // Struct containing all received data in the request (AGT encoded + claims + DecodedAGT)
	Token   string `json:"token"`
	Purpose string `json:"purpose"`
	Pop     string `json:"pop"`
	Agt     utils.ExtendedJwt
	PopTk   utils.PopToken
}

// Data that will go in the channel
type ChannelData map[string]string

// Policies and claims to check AT Requests received
// Contains the key used to sign, to verify signatures and other contents
var Policies struct {
	Connection       utils.Connectivity     `json:"connectivity"`
	SigningKey       utils.Key              `json:"signing_key"`
	PopCheckPolicies utils.PopCheck         `json:"PoP_Policies"`
	AgtKeys          utils.KeySet           `json:"agt_keys"`
	AtGenPolicies    utils.ATGenerate       `json:"AT"`
	ManagerPolicies  utils.ManagementConfig `json:"Management"`
}

// Stores a cache of the POP Jwt ids received not to be reused
var popIDCache map[string]struct{}

var purposeList map[string]interface{}

var pList []PurposeElement

type PurposeElement struct {
	Short   string
	Long    string
	Context []ContextElement
	Access  []AccessElement
}

type ContextElement struct {
	Actor [3]RoleElement // User, App, Device
}

type RoleElement struct {
	Role []string
}

type AccessElement struct {
	Path       string
	Permission string
}

var scopeList map[string]interface{}

var sList []ScopeElement

type ScopeElement struct {
	Context  []ContextElement
	NoAccess []string
}

// ************* INITIALIZATION METHODS **************************
// Initializes the Binary Data Tree
func initVssFile() bool {
	filePath := BINARY_TREE_DIR
	cfilePath := C.CString(filePath)
	VSSTreeRoot = C.VSSReadTree(cfilePath)
	C.free(unsafe.Pointer(cfilePath))

	if VSSTreeRoot == 0 {
		utils.Error.Println("Tree file not found")
		return false
	}

	return true
}

// Loads the Key contained in the Policies, or generates a new one (default is HS256: symmetric key)
func initKey() {
	switch Policies.SigningKey.Algorithm {
	case "RS256":
		if err := utils.ImportRsaKey(Policies.SigningKey.PrivKeyDir, &Policies.SigningKey.RsaPrivKey); err != nil {
			utils.Error.Printf("Error importing key, generating one.")
			genSignKey("RS256", 0)
		}
	case "ES256":
		if err := utils.ImportEcdsaKey(Policies.SigningKey.PrivKeyDir, &Policies.SigningKey.EcdsaPrivKey); err != nil {
			utils.Error.Printf("Error importing key, generating one.")
			genSignKey("ES256", 0)
		}
	case "HS256": // symm key is just reading a file
		var err error
		Policies.SigningKey.SymmKey = make([]byte, 32)
		Policies.SigningKey.SymmKey, err = os.ReadFile(Policies.SigningKey.SymmKeyDir)
		if err != nil {
			utils.Error.Printf("Error importing key, generating one.")
			genSignKey("HS256", 0)
		}
	default:
		utils.Error.Printf("No matching algorithm or key found. Generating symmetric key")
		genSignKey("HS256", 0)
	}
}

func initPolicies() {
	content, err := ioutil.ReadFile(POLICIES_DIR)
	if err != nil {
		utils.Error.Printf("Error reading %s file", POLICIES_DIR)
		log.Fatal(err)
	}
	err = json.Unmarshal(content, &Policies)
	if err != nil {
		utils.Error.Printf("Error unmarshalling content of %s file", POLICIES_DIR)
		log.Fatal(err)
	}
	initKey()
}

// Channels for communication between methods will send a string map. This method generates an error string map that is then parsed by the Method that receives the string map.
func genErrorMap(code string, message string) map[string]string {
	errMap := make(map[string]string)
	errMap["type"] = "error"
	errMap["errorMessage"] = message
	errMap["errorCode"] = code
	return errMap
}

// ************* END OF INITIALIZATION *************

// ************* HTTP REQUESTS MANAGEMENT METHODS *************

// Generates a handler for the URL "/ats"
func makeAtServerHandler(serverChannel chan ChannelData) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		//utils.Info.Printf("atServer:url=%s", req.URL.Path)
		bodyBytes, err := ioutil.ReadAll(req.Body)
		if err != nil {
			http.Error(w, "400 request unreadable.", 400)
			utils.Info.Printf("atServer: Received unreadable request")
			return
		}
		utils.Info.Printf("atServer: Received AT request: %s", string(bodyBytes))
		switch req.Method {
		case "POST":
			reqMap := make(map[string]string)
			reqMap["type"] = "atRequest"
			reqMap["body"] = string(bodyBytes)
			reqMap["pop"] = req.Header.Get("PoP")
			serverChannel <- reqMap
			response := <-serverChannel
			if response["type"] == "error" {
				errCode, _ := strconv.Atoi(response["errorCode"])
				http.Error(w, response["errorMessage"], errCode)
				utils.Info.Printf("atServer: Sending error Response: %s", response["errorCode"])
				return
			} else {
				w.Header().Set("Content-Type", "application/json")
				utils.Info.Printf("atServer: Sending Response: %s", response["response"])
				w.Write([]byte(response["response"]))
			}
		case "OPTIONS":
			w.Header().Set("Access-Control-Allow-Methods", "POST")
			w.Header().Set("Access-Control-Max-Age", "57600")
			//w.Header().Set("Access-Control-Allow-Headers", "") //- Not using any not-standar header
		default:
			http.Error(w, "400 bad request method", 400)
			utils.Info.Println("atServer: Sending 400 Error, bad method")
		}
	}
}

// Generates a handler for the URL "/management". It allows the POST method and OPTIONS for Cors Responses.
func makeMgmServerHandler(managementChannel chan ChannelData) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		utils.Info.Printf("atServer:url=%s", req.URL.Path)
		bodyBytes, err := ioutil.ReadAll(req.Body)
		if err != nil {
			http.Error(w, "400 request unreadable.", 400)
			utils.Info.Printf("atServer: Received unreadable body request")
			return
		}
		utils.Info.Printf("atServer: Received Management request: %s", string(bodyBytes))

		switch req.Method {
		case "POST":
			reqMap := make(map[string]string)
			reqMap["type"] = "management"
			reqMap["body"] = string(bodyBytes)
			managementChannel <- reqMap
			response := <-managementChannel
			if response["type"] == "error" {
				errCode, _ := strconv.Atoi(response["errorCode"])
				http.Error(w, response["errorMessage"], errCode)
				utils.Info.Printf("atServer: Sending error Response: %s", response["errorMessage"])
				return
			} else {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Access-Control-Allow-Origin", "*")
				utils.Info.Printf("atServer: Sending Response: %s", response["response"])
				w.Write([]byte(response["response"]))
			}
		case "OPTIONS":
			utils.Info.Printf("atServer: Sending OPTIONS Response")
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization")
			w.Header().Set("Access-Control-Allow-Methods", "POST, GET")
			w.Header().Set("Access-Control-Max-Age", "57600")
		default:
			http.Error(w, "400 bad request method.", 400)
			utils.Info.Printf("atServer: Sending 400 Error, bad Method")
			return
		}
	}
}

// Generates a handler for any URL. It just allows the OPTIONS method for Cors responses. In any other case, it throws 404 error
func makeGenServerHandler() func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		switch req.Method {
		case "OPTIONS":
			utils.Info.Printf("atServer: Received OPTIONS Request, Sending OPTIONS Response")
			w.Header().Set("Access-Control-Allow-Origin", "*")
			//w.Header().Set("Access-Control-Allow-Headers", "")
			w.Header().Set("Access-Control-Allow-Methods", "POST")
			w.Header().Set("Access-Control-Max-Age", "57600")
			return
		default:
			http.Error(w, "404 Not found.", 404)
			return
		}
	}
}

func initAtServer(serverChannel chan ChannelData, mgmChannel chan ChannelData, muxServer *http.ServeMux) {
	utils.Info.Printf("initAtServer(): :%s/ats", Policies.Connection.ServingPort)
	atServerHandler := makeAtServerHandler(serverChannel)
	mgmServerHandler := makeMgmServerHandler(mgmChannel)
	generalServerHandler := makeGenServerHandler()
	muxServer.HandleFunc("/ats", atServerHandler)
	muxServer.HandleFunc("/management", mgmServerHandler)
	muxServer.HandleFunc("/", generalServerHandler)
	if !Policies.Connection.TlsManagement.Use { // NO TLS
		utils.Error.Fatal(http.ListenAndServe(":"+Policies.Connection.ServingPort, muxServer))
	} else {
		utils.Error.Fatal(http.ListenAndServeTLS(Policies.Connection.ServingPort, Policies.Connection.TlsManagement.CertDir,
			Policies.Connection.TlsManagement.KeyDir, muxServer))
	}
}

func generateResponse(data ChannelData) ChannelData {
	input := data["body"]
	response := make(ChannelData)
	if strings.Contains(input, "purpose") {
		return generateAtResponse(data)
	} else if strings.Contains(input, "context") {
		response["type"] = "response"
		response["response"] = noScopeResponse(input)
	} else {
		response["type"] = "response"
		response["response"] = tokenValidationResponse(input)
	}
	return response
}

// ************* END OF HTTP REQUESTS MANAGEMENT *************

// ************* CONTEXT NO SCOPE REQUEST HANDLER *************
//
func getPathLen(path string) int {
	for i := 0; i < len(path); i++ {
		if path[i] == 0x00 { // the path buffer defined in searchData_t is initiated with all zeros
			return i
		}
	}
	return len(path)
}

func validateRequestAccess(purpose string, action string, paths []string) int {
	numOfPaths := len(paths)
	var pathSubList []string
	for i := 0; i < numOfPaths; i++ {
		numOfWildcardPaths := 1
		if strings.Contains(paths[i], "*") {
			searchData := [MAXFOUNDNODES]searchData_t{}
			// call int VSSSearchNodes(char* searchPath, long rootNode, int maxFound, searchData_t* searchData, bool anyDepth, bool leafNodesOnly, int listSize, noScopeList_t* noScopeList, int* validation);
			cpath := C.CString(paths[i])
			numOfWildcardPaths := int(C.VSSSearchNodes(cpath, VSSTreeRoot, MAXFOUNDNODES, (*C.struct_searchData_t)(unsafe.Pointer(&searchData)), true, true, 0, nil, nil))
			C.free(unsafe.Pointer(cpath))
			pathSubList = make([]string, numOfWildcardPaths)
			for j := 0; j < numOfWildcardPaths; j++ {
				pathLen := getPathLen(string(searchData[j].path[:]))
				pathSubList[j] = string(searchData[j].path[:pathLen])
			}
		} else {
			pathSubList = make([]string, 1)
			pathSubList[0] = paths[i]
		}
		for j := 0; j < numOfWildcardPaths; j++ {
			status := validatePurposeAndAccessPermission(purpose, action, pathSubList[j])
			if status != 0 {
				return status
			}
		}
	}
	return 0
}

func validatePurposeAndAccessPermission(purpose string, action string, path string) int {
	for i := 0; i < len(pList); i++ {
		if pList[i].Short == purpose {
			for j := 0; j < len(pList[i].Access); j++ {
				if pList[i].Access[j].Path == path {
					if action == "set" && pList[i].Access[j].Permission == "read-only" {
						return -16
					} else {
						return 0
					}
				}
			}
		}
	}
	return -8
}

// Checks if given client context matches with the context of the member of sList (ScopeList)
func matchingContext(index int, context string) bool { // identical to checkAuthorization(), using sList instead of pList
	clientContext := strings.Split(context, "+")
	// Iterates each one of the contents of the Scope List
	for i := 0; i < len(sList[index].Context); i++ {
		actorValid := [3]bool{false, false, false}
		// Iterates each one of the Subactors
		for j := 0; j < len(sList[index].Context[i].Actor); j++ {
			if j > 2 {
				return false // only three subactors supported
			}
			// Iterates each one of the possible contexts in each subactor
			for k := 0; k < len(sList[index].Context[i].Actor[j].Role); k++ {
				fmt.Printf("IT: %d, CONTEXT: %d, VAL: %s, CLIENT: %s\n%s\n%s", i, j, sList[index].Context[i].Actor[j].Role[k], clientContext[j], sList[index].Context[i].Actor[j].Role[k], clientContext[j])
				if clientContext[j] == sList[index].Context[i].Actor[j].Role[k] {
					actorValid[j] = true
					break
				}
			}
		}
		if actorValid[0] && actorValid[1] && actorValid[2] {
			return true
		}
	}
	return false
}

// Returns the set of signals to not access contained in the given index. Uses SList (ScopeList: context + signals prohibited)
func synthesizeNoScope(index int) string {
	if len(sList[index].NoAccess) == 1 {
		return `"` + sList[index].NoAccess[0] + `"`
	}
	noScope := "["
	for i := 0; i < len(sList[index].NoAccess); i++ {
		noScope += `"` + sList[index].NoAccess[i] + `", `
	}
	return noScope[:len(noScope)-2] + "]"
}

// Gets context, returns the
func getNoAccessScope(context string) string {
	for i := 0; i < len(sList); i++ {
		if matchingContext(i, context) {
			return synthesizeNoScope(i)
		}
	}
	return `""`
}

// Returns the set of signals a client can not access
func noScopeResponse(input string) string {
	var payload NoScopePayload
	err := json.Unmarshal([]byte(input), &payload)
	if err != nil {
		utils.Error.Printf("noScopeResponse:error input=%s", input)
		return `{"no_access":"invalid Request"}`
	}
	res := getNoAccessScope(payload.Context)
	utils.Info.Printf("getNoAccessScope result=%s", res)
	return `{"no_access":` + res + `}`
}

// ************* END CONTEXT NO SCOPE REQUEST *************

// ************* ACCESS TOKEN VALIDATION CHECKING METHODS *************

// Receives the body of a request from VISS Server containing an Access Token To verify
func tokenValidationResponse(input string) string { // TO DO: VERIFY EXPIRATION TIMES
	var inputMap map[string]interface{}
	err := json.Unmarshal([]byte(input), &inputMap)
	if err != nil {
		utils.Error.Printf("tokenValidationResponse:error input=%s", input)
		return `{"validation":"-128"}`
	}
	var atValidatePayload AtValidatePayload
	extractAtValidatePayloadLevel1(inputMap, &atValidatePayload)
	// Gets the signing key
	if Policies.SigningKey.Algorithm == "HS256" {
		err = utils.VerifyTokenSignature(atValidatePayload.Token, getSymmSignKey())
	} else {
		err = utils.VerifyTokenSignature(atValidatePayload.Token, getSignKey())
	}
	if err != nil {
		utils.Info.Printf("tokenValidationResponse:invalid signature, error= %s, token=%s", err, atValidatePayload.Token)
		return `{"validation":"-2"}`
	}
	purpose := utils.ExtractFromToken(atValidatePayload.Token, "scp")
	res := validateRequestAccess(purpose, atValidatePayload.Action, atValidatePayload.Paths)
	if res != 0 {
		utils.Info.Printf("validateRequestAccess fails with result=%d", res)
		return `{"validation":"` + strconv.Itoa(res) + `"}`
	}
	return `{"validation":"0"}`
}

// Extracts Access Token received from claim map to token
func extractAtValidatePayloadLevel1(atValidateMap map[string]interface{}, atValidatePayload *AtValidatePayload) {
	for k, v := range atValidateMap {
		switch vv := v.(type) {
		case []interface{}:
			utils.Info.Println(k, "is an array:, len=", strconv.Itoa(len(vv)))
			extractAtValidatePayloadLevel2(vv, atValidatePayload)
		case string:
			utils.Info.Println(k, "is a string:")
			if k == "token" {
				atValidatePayload.Token = v.(string)
			} else if k == "action" {
				atValidatePayload.Action = v.(string)
			} else if k == "validation" {
				atValidatePayload.Validation = v.(string)
			} else if k == "paths" {
				atValidatePayload.Paths = make([]string, 1)
				atValidatePayload.Paths[0] = v.(string)
			}
		default:
			utils.Info.Println(k, "is of an unknown type")
		}
	}
}
func extractAtValidatePayloadLevel2(pathList []interface{}, atValidatePayload *AtValidatePayload) {
	atValidatePayload.Paths = make([]string, len(pathList))
	i := 0
	for k, v := range pathList {
		switch typ := v.(type) {
		case string:
			utils.Info.Println(k, "is a string:")
			atValidatePayload.Paths[i] = v.(string)
		default:
			utils.Info.Println(k, "is of an unknown type:", typ)
		}
		i++
	}
}

// ************* END ACCESS TOKEN VALIDATION CHECKING *************

// ************* ACCESS TOKEN GENERATION AND REQUEST CHECKING METHODS *************

// Calls methods to generate and Check Acces Token
func generateAtResponse(input ChannelData) ChannelData {
	var payload AtRequest // struct containing encodedAGT + claims received
	err := json.Unmarshal([]byte(input["body"]), &payload)
	if err != nil {
		utils.Info.Printf("generateAtResponse:error input=%s", input)
		return genErrorMap("400", `{"error": "Client request malformed"}`)
	}
	if payload.Token == "" {
		utils.Info.Printf("generateAtResponse: No Access Grant Token included")
		return genErrorMap("400", `{"error":"AGT Not included"}`)
	}
	err = payload.Agt.DecodeFromFull(payload.Token)
	if err != nil {
		utils.Info.Printf("generateAtResponse: error decoding token=%s", payload.Token)
		return genErrorMap("400", `{"error":"AGT Malformed"}`)
	}
	if payload.Pop != "" {
		err = payload.PopTk.Unmarshal(payload.Pop)
		if err != nil {
			utils.Info.Printf("generateAtResponse: error decoding pop, error=%s, pop=%s", err, payload.Agt.PayloadClaims["pop"])
			return genErrorMap("400", `{"error":"POP malformed"}`)
		}
	}
	valid, errResponse := validateAtRequest(payload)
	if valid {
		resp := make(ChannelData)
		resp["type"] = "response"
		resp["response"] = generateAt(payload)
		return resp
	}
	return genErrorMap("400", errResponse)
}

// Compares the token timestamps
func validateTokenTimestamps(iat int, exp int) bool {
	now := time.Now()
	if now.Before(time.Unix(int64(iat), 0)) {
		return false
	}
	if now.After(time.Unix(int64(exp), 0)) {
		return false
	}
	return true
}

// Gets the Purpose and the context, checks the purpose list and validates.
func validatePurpose(purpose string, context string) bool { // TODO: learn how to code to parse the purpose list, then use it to validate the purpose
	valid := false
	for i := 0; i < len(pList); i++ {
		//utils.Info.Printf("validatePurpose:purposeList[%d].Short=%s", i, pList[i].Short)
		if pList[i].Short == purpose {
			//utils.Info.Printf("validatePurpose:purpose match=%s", pList[i].Short)
			valid = checkAuthorization(i, context)
			if valid {
				break
			}
		}
	}
	return valid
}

// Checks if the context given of the client matches with the purpose with the given index
func checkAuthorization(index int, context string) bool {
	//utils.Info.Printf("checkAuthorization:context=%s, len(pList[index].Context)=%d", context, len(pList[index].Context))
	for i := 0; i < len(pList[index].Context); i++ {
		actorValid := [3]bool{false, false, false}
		//utils.Info.Printf("checkAuthorization:len(pList[index].Context[%d].Actor)=%d", i, len(pList[index].Context[i].Actor))
		for j := 0; j < len(pList[index].Context[i].Actor); j++ {
			if j > 2 {
				return false // only three subactors supported
			}
			for k := 0; k < len(pList[index].Context[i].Actor[j].Role); k++ {
				//utils.Info.Printf("checkAuthorization:getActorRole(%d, context)=%s vs pList[index].Context[%d].Actor[%d].Role[%d])=%s", j, getActorRole(j, context), i, j, k, pList[index].Context[i].Actor[j].Role[k])
				if getActorRole(j, context) == pList[index].Context[i].Actor[j].Role[k] {
					actorValid[j] = true
					break
				}
			}
		}
		if actorValid[0] && actorValid[1] && actorValid[2] {
			return true
		}
	}
	return false
}

// Given an index, obtains the role linked with it (user+app+device)
func getActorRole(actorIndex int, context string) string {
	delimiter1 := strings.Index(context, "+")
	if actorIndex == 0 {
		return context[:delimiter1]
	}
	delimiter2 := strings.Index(context[delimiter1+1:], "+")
	if actorIndex == 1 {
		return context[delimiter1+1 : delimiter1+1+delimiter2]
	}
	return context[delimiter1+1+delimiter2+1:]
}

// Check Vin. Might be disabled, AT might not need to check the VIN
func checkVin(vin string) bool {
	if vin == "" && len(Policies.AtGenPolicies.VehicleIds) == 0 {
		return true
	} else {
		for _, goodVin := range Policies.AtGenPolicies.VehicleIds {
			if goodVin == vin {
				return true
			}
		}
	}
	return false
}

// After a JTI received expires, it is deleted from the cache
func deleteJti(jti string) {
	time.Sleep((time.Duration(Policies.PopCheckPolicies.TimeMargin) + time.Duration(Policies.PopCheckPolicies.TimeExp)) * time.Second)
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

// Validates the Proof of Possession of the Client
func validatePop(payload AtRequest) (bool, string) {
	// Check jti
	if !addCheckJti(payload.PopTk.PayloadClaims["jti"]) {
		utils.Error.Printf("validateAtRequest: JTI used")
		return false, `{"error": "Repeated JTI"}`
	}
	// Check signaure
	if err := payload.PopTk.CheckSignature(); err != nil {
		utils.Info.Printf("validateAtRequest: Invalid POP signature: %s", err)
		return false, `{"error": "Cannot validate POP signature"}`
	}
	// Check exp: no need, iat will be used instead
	// Check iat
	if ok, cause := payload.PopTk.CheckIat(Policies.PopCheckPolicies.TimeMargin, Policies.PopCheckPolicies.TimeExp); !ok {
		utils.Info.Printf("validateAtRequest: Invalid POP iat: %s", cause)
		return false, `{"error": "Cannot validate POP iat"}`
	}
	// Check that pub (thumprint) corresponds with pop key
	if ok, _ := payload.PopTk.CheckThumb(payload.Agt.PayloadClaims["pub"]); !ok {
		utils.Info.Printf("validateAtRequest: PubKey in POP is not same as in AGT")
		return false, `{"error": "Keys in POP and AGToken are not matching"}`
	}
	// Check aud
	if ok, _ := payload.PopTk.CheckAud("vissv2/ats"); !ok {
		utils.Info.Printf("validateAtRequest: Aud in POP not valid")
		return false, `{"error": "Invalid aud"}`
	}
	//utils.Info.Printf("validateAtRequest:Proof of possession of key pair failed")
	//return false, `{"error": "Proof of possession of key pair failed"}`
	return true, ""
}

// Validates the AGT and the purpose of the request
func validateAtRequest(payload AtRequest) (bool, string) {
	if !checkVin(payload.Agt.HeaderClaims["vin"]) {
		utils.Info.Printf("validateAtRequest:incorrect VIN=%s", payload.Agt.HeaderClaims["vin"])
		return false, `{"error": "Incorrect vehicle identifiction"}`
	}
	// Verifies the AGT Signature with all the Keys Stored.
	verifySign := false
	for _, key := range Policies.AgtKeys {
		var err error
		if key.Algorithm == "RS256" {
			err = payload.Agt.Token.CheckAssymSignature(key.RsaPubKey)
		} else if key.Algorithm == "ES256" {
			err = payload.Agt.Token.CheckAssymSignature(key.EcdsaPrivKey)
		}
		if err == nil {
			verifySign = true
			utils.Info.Printf("validateAtRequest:valid signature, token:%s", payload.Token)
			break
		} else {
			utils.Info.Printf("validateAtRequest:invalid signature, error: %s, token:%s", err, payload.Token)
		}
	}
	if !verifySign {
		return false, `{"error": "AG token signature validation failed"}`
	}
	// Validates the Expiration of the token
	iat, err := strconv.Atoi(payload.Agt.PayloadClaims["iat"])
	if err != nil {
		return false, `{"error": AG token iat timestamp malformed"}`
	}
	exp, err := strconv.Atoi(payload.Agt.PayloadClaims["exp"])
	if err != nil {
		return false, `{"error": "AG token exp timestamp malformed"}`
	}
	if !validateTokenTimestamps(iat, exp) {
		utils.Info.Printf("validateAtRequest:invalid token timestamps, iat=%d, exp=%d", payload.Agt.PayloadClaims["iat"], payload.Agt.PayloadClaims["exp"])
		return false, `{"error": "AG token timestamp validation failed"}`
	}
	// Verifies the POP, in case it is present
	if payload.Agt.PayloadClaims["pub"] != "" { // That means the agt is associated with a public key
		if ok, errmsj := validatePop(payload); !ok {
			return ok, errmsj
		}
	}
	if !validatePurpose(payload.Purpose, payload.Agt.PayloadClaims["clx"]) {
		utils.Info.Printf("validateAtRequest:invalid purpose=%s, context=%s", payload.Purpose, payload.Agt.PayloadClaims["clx"])
		return false, `{"error": "Purpose validation failed"}`
	}
	return true, ""
}

// Generates the Access Token using the claims in the request
func generateAt(payload AtRequest) string {
	unparsedId, err := uuid.NewRandom()
	if err != nil { // Better way to generate uuid than calling an ext program
		utils.Error.Printf("generateAgt:Error generating uuid, err=%s", err)
		return `{"error": "Internal error"}`
	}
	iat := int(time.Now().Unix())
	exp := iat + 1*60*60 // 1 hour
	var jwtoken utils.JsonWebToken
	jwtoken.SetHeader("HS256")
	//jwtoken.AddClaim("vin", AtRequest.Agt.Vin)
	jwtoken.AddClaim("iat", strconv.Itoa(iat))
	jwtoken.AddClaim("exp", strconv.Itoa(exp))
	jwtoken.AddClaim("pur", payload.Purpose)
	jwtoken.AddClaim("clx", payload.Agt.PayloadClaims["clx"])
	jwtoken.AddClaim("aud", "w3org/gen2")
	jwtoken.AddClaim("jti", unparsedId.String())
	utils.Info.Printf("generateAt:jwtHeader=%s", jwtoken.GetHeader())
	utils.Info.Printf("generateAt:jwtPayload=%s", jwtoken.GetPayload())
	jwtoken.Encode()
	// The signature method might be symm or asym. Use of get... allows to check the exp of the key and generate one if neccesary
	if Policies.SigningKey.Algorithm != "HS256" {
		jwtoken.AssymSign(getSignKey())
	} else {
		jwtoken.SymmSign(getSymmSignKey())
	}
	return `{"token":"` + jwtoken.GetFullToken() + `"}`
}

// ************* END AT GENERATION AND CHECKING *************

// ************* POLICIES AND KEY MANAGEMENT METHODS *************

// Returns the assym key used for sign
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

// Returns the symm key used for sign
func getSymmSignKey() string {
	actTime := time.Now().Unix()
	if actTime > int64(Policies.SigningKey.Expiration) && Policies.SigningKey.Expiration != 0 {
		genSignKey(Policies.SigningKey.Algorithm, 0)
	}
	if Policies.SigningKey.Algorithm == "HS256" {
		return string(Policies.SigningKey.SymmKey)
	}
	return ""
}

// Generates a new signing key given an algorithm.
// The lifetime of that key can be set so once that time arrives it stops using it and generates a new one.
func genSignKey(alg string, lifetime int) bool {
	switch alg {
	case "RS256":
		if err := utils.GenRsaKey(256, &Policies.SigningKey.RsaPrivKey); err != nil {
			utils.Error.Printf("Error generating RSA private key: %s. Signature not avaliable", err)
			return false
		} else { // Key generated correctly, saving it
			utils.Info.Printf("RSA key generated correctly")
			keyUuid := uuid.New()
			if err := utils.ExportKeyPair(Policies.SigningKey.RsaPrivKey, keyUuid.String()+".rsa", keyUuid.String()+".rsa.pub"); err != nil {
				utils.Error.Printf("Error exporting key: %s", err)
				return false
			} else {
				Policies.SigningKey.Algorithm = "RS256"
				Policies.SigningKey.PrivKeyDir = keyUuid.String() + ".rsa"
				Policies.SigningKey.PubKeyDir = keyUuid.String() + ".rsa.pub"
			}
		}
	case "ES256":
		if err := utils.GenEcdsaKey(elliptic.P256(), &Policies.SigningKey.EcdsaPrivKey); err != nil {
			utils.Error.Printf("Error generating EC private key: %s. Signature not avaliable", err)
			return false
		} else { // Key generated correctly, saving it
			utils.Info.Printf("ECDSA key generated correctly")
			keyUuid := uuid.New()
			if err := utils.ExportKeyPair(Policies.SigningKey.RsaPrivKey, keyUuid.String()+".ec", keyUuid.String()+".ec.pub"); err != nil {
				utils.Error.Printf("Error exporting key: %s", err)
				return false
			} else {
				Policies.SigningKey.Algorithm = "ES256"
				Policies.SigningKey.PrivKeyDir = keyUuid.String() + ".rsa"
				Policies.SigningKey.PubKeyDir = keyUuid.String() + ".rsa.pub"
			}
		}
	case "HS256": // Generates a random 32 byte array
		Policies.SigningKey.SymmKey = make([]byte, 32)
		_, err := rand.Read(Policies.SigningKey.SymmKey)
		if err != nil {
			utils.Error.Printf("Error symm generating key: %s. Signature not avaliable", err)
			return false
		} else { // If no error, changes everything
			Policies.SigningKey.Algorithm = "HS256"
			keyUuid := uuid.New()
			//Saves the key in file
			pubFile, err := os.Create(keyUuid.String() + ".key")
			if err != nil {
				utils.Error.Printf("Error exporting key: %s", err)
				return false
			} else {
				Policies.SigningKey.SymmKeyDir = keyUuid.String() + ".key"
				defer pubFile.Close()
				_, err := fmt.Fprint(pubFile, Policies.SigningKey.SymmKey)
				if err != nil {
					Policies.SigningKey.SymmKeyDir = ""
					utils.Error.Printf("Error exporting key: %s", err)
					return false
				}

			}
		}
	}
	Policies.SigningKey.Expiration = 0
	if lifetime != 0 {
		Policies.SigningKey.Expiration = int(time.Now().Unix()) + lifetime
	}
	return writePolicies()
}

// Writes the Policies struct holded by the server to the JSON file used for storage of those policies.
func writePolicies() bool {
	content, err := json.Marshal(Policies)
	if err != nil {
		utils.Error.Printf("Could not write policies: %s", err)
		return false
	}
	err = ioutil.WriteFile(POLICIES_DIR, content, 0644)
	if err != nil {
		utils.Error.Printf("Could not write policies: %s", err)
		return false
	}
	utils.Info.Printf("Policies updated and saved")
	return true
}

// Obtains the route of the data managed
func getRoute(fullwithMethod []string) string {
	route := fullwithMethod[0]
	for i := 1; i < len(route)-1; i++ {
		route = route + "." + fullwithMethod[i]
	}
	return route
}

// Receives the body of a management request, generates the response and changes whatever it should
func generateManagementResponse(request map[string]string) ChannelData {
	var body map[string]interface{}
	if err := json.Unmarshal([]byte(request["body"]), &body); err != nil {
		return genErrorMap("400", `{"error":"Request body is not a JSON structure"}`)
	}
	var response string

	for claim, value := range body {
		claimList := strings.Split(claim, ".")
		switch claimList[0] {
		case "Policies":
			reflectPointer := reflect.ValueOf(&Policies).Elem()
			reflectType := reflectPointer.Type()
			for routeIterator := 1; routeIterator < len(claimList)-1; routeIterator++ { // Iterates route of the petition
				found := false                               // Used to check if each one of the iterations were ok, if not request is not valid
				if reflectPointer.Kind() == reflect.Struct { // Check if what is asked to iterate is a struct
					for structIterator := 0; structIterator < reflectPointer.NumField(); structIterator++ { // Iterates each field of the struct searching for the one asked
						if reflectType.Field(structIterator).Name == claimList[routeIterator] { // If both names are the same, iteration stops
							reflectPointer = reflectPointer.Field(structIterator)
							found = true
							break
						}
					}
				}
				if !found {
					utils.JsonRecursiveMarshall(claim, "error: Not a valid route", &response)
					break
				}
			}
			switch reflectPointer.Kind() { // Depending on the type of variable to change, one thing or another must be done
			// String supports only "SET" method
			case reflect.String:
				switch claimList[len(claimList)-1] { // Last part is the method
				case "SET":
					if reflect.TypeOf(value).Kind() == reflect.String {
						val, _ := value.(string)
						reflectPointer.SetString(val)
						utils.JsonRecursiveMarshall(claim, "success: Value "+val, &response)
					} else {
						utils.JsonRecursiveMarshall(claim, "error: Invalid value", &response)
					}
				default:
					utils.JsonRecursiveMarshall(claim, "error: Invalid Method", &response)
				}
			// Bool supports only "SET" method
			case reflect.Bool:
				switch claimList[len(claimList)-1] { // Last part is the method
				case "SET":
					if reflect.TypeOf(value).Kind() == reflect.Bool {
						val, _ := value.(bool)
						reflectPointer.SetBool(val)
						utils.JsonRecursiveMarshall(claim, "success: Value "+fmt.Sprintf("%t", val), &response)
					} else {
						utils.JsonRecursiveMarshall(claim, "error: Invalid value", &response)
					}
				default:
					utils.JsonRecursiveMarshall(claim, "error: Invalid Method", &response)
				}

			case reflect.Int:
				switch claimList[len(claimList)-1] { // Last part is the method
				case "SET":
					if reflect.TypeOf(value).Kind() == reflect.Int {
						reflectPointer.SetInt(value)
						utils.JsonRecursiveMarshall(claim, "success: Value "+value, &response)
					} else {
						utils.JsonRecursiveMarshall(claim, "error: Invalid value", &response)
					}
				default:
					utils.JsonRecursiveMarshall(claim, "error: Invalid Method", &response)
				}

			case reflect.Slice:
				if reflect.TypeOf(value).Kind() == reflect.String {
					values := strings.Split(value, ",")
					switch claimList[len(claimList)-1] {
					case "SET":
						reflectPointer.Set(reflect.ValueOf(values))
					case "ADD":
						reflectPointer.Set(reflect.Append(reflectPointer, reflect.ValueOf(values)))
					//case "DELETE":
					// Complex, will be filled in the future
					default:
						utils.JsonRecursiveMarshall(claim, "error: Invalid Method", &response)
					}
				} else {
					utils.JsonRecursiveMarshall(claim, "error: Invalid value", &response)
				}
			}
			// If everything was fine, reflectPointer must be a Pointer to int, bool, string or Slice

		case "PurposeList":
			utils.JsonRecursiveMarshall(claim, "error: Not supported already", &response)
		case "ScopeList":

		default:
			utils.JsonRecursiveMarshall(claim, "error: Not supported already", &response)
		}
	}
	responseMap := make(ChannelData)
	responseMap["response"] = response
	return responseMap

	/*for i := 1; i < len(claimList); i++ {
			fmt.Println(i)
			typ := reflect.TypeOf(pointer)
			switch typ {
			case reflect.TypeOf(int{}):

			default:

			}

			pointer
			switch typ := pointer.(type) {
			case *Policies:

			case *utils.Connectivity:

			case *utils.TlsUse:

			case *utils.Key:

			case *utils.KeySet:

			case *utils.PopCheck:

			case *utils.AGTGenerate:

			case *utils.ATGenerate:

			case *utils.ClientCtx:

			case *utils.ManagementConfig:

			}

		}
	}
	/*
		var body map[string]string
		if err := json.Unmarshal([]byte(request["body"]), &body); err != nil {
			return genErrorMap("400", `{"error":"Not a JSON structure"}`)
		}
		var response string

		// Iterates all the claims received in the body of the request
		for claim, value := range body {
			claimMap := strings.Split(claim, ".")
			switch claimMap[0] { // Gets type of Request, then iterates to it
			case "PurposeList":

			case "ScopeList":

			// No way to iterate the route, must do it all manually
			case "Policies":
				if len(claimMap) >= 2 {
					switch claimMap[1] {
					// Connectivity claims. Not managed, those must be set before deployment.
					/*case "conectivity":
					switch claimMap[2]{
						case "serving_port":
						case "tls":
							switch claimMap[3]{
								case "use":
								case "certificate_dir":
								case "key_dir":
							}
					}*/
	// Signing key related methods
	/*
					case "signing_key":
						switch claimMap[2] {
						case "expiration":
							switch claimMap[3] {
							case "GET": // Sends the exp time of the signing key to the manager
								utils.JsonRecursiveMarshall(getRoute(claimMap), strconv.Itoa(Policies.SigningKey.Expiration), &response)
							case "SET": // Sets a new exp claim for the signing key
								exp, err := strconv.Atoi(value)
								if err != nil {
									utils.JsonRecursiveMarshall(claim, "error: Bad syntax", &response)
								} else {
									Policies.SigningKey.Expiration = exp
									utils.JsonRecursiveMarshall(getRoute(claimMap), strconv.Itoa(Policies.SigningKey.Expiration), &response)
								}
							default:
								utils.JsonRecursiveMarshall(claim, "error: Bad Route", &response)
							}
						case "algorithm":
							switch claimMap[3] {
							case "GET": // Sends the algorithm to the manager
								utils.JsonRecursiveMarshall(getRoute(claimMap), Policies.SigningKey.Algorithm, &response)
							case "SET": // Sets a new algorithm to use. Receiving this generates a new key.
								ok := genSignKey(value, 0)
								if !ok {
									utils.JsonRecursiveMarshall(claim, "error: Cannot generate New Key", &response)
								} else {
									utils.JsonRecursiveMarshall(claim, Policies.SigningKey.Algorithm, &response)
								}
							default:
								utils.JsonRecursiveMarshall(claim, "error: Bad syntax", &response)
							}
							// ************************************ FILL *******************************************************************************
						case "GET": // Returns the JSON WEB KEY representing the assymetric key or the symmetric key in base64URL encoding
							switch Policies.SigningKey.Algorithm {
							case "HS256":
							case "ES256":
							case "RS256":
							}
						default:
							utils.JsonRecursiveMarshall(claim, "error: Bad syntax", &response)
						}

					case "PoP_Policies":
						switch claimMap[2] {
						case "time_exp":
							switch claimMap[3] {
							case "GET":
								utils.JsonRecursiveMarshall(getRoute(claimMap), strconv.Itoa(Policies.PopCheckPolicies.TimeExp), &response)
							case "SET":
								exp, err := strconv.Atoi(value)
								if err != nil {
									utils.JsonRecursiveMarshall(claim, "error: Bad syntax", &response)
								} else {
									Policies.PopCheckPolicies.TimeExp = exp
									utils.JsonRecursiveMarshall(getRoute(claimMap), strconv.Itoa(Policies.PopCheckPolicies.TimeExp), &response)
								}
							default:
								utils.JsonRecursiveMarshall(claim, "error: Bad syntax", &response)
							}
						case "time_error_margin":
							switch claimMap[3] {
							case "GET":
								utils.JsonRecursiveMarshall(getRoute(claimMap), strconv.Itoa(Policies.PopCheckPolicies.TimeMargin), &response)
							case "SET":
								margin, err := strconv.Atoi(value)
								if err != nil {
									utils.JsonRecursiveMarshall(claim, "error: Bad syntax", &response)
								} else {
									Policies.PopCheckPolicies.TimeMargin = margin
									utils.JsonRecursiveMarshall(getRoute(claimMap), strconv.Itoa(Policies.PopCheckPolicies.TimeMargin), &response)
								}
							default:
								utils.JsonRecursiveMarshall(claim, "error: Bad syntax", &response)
							}
						case "banned_thumbprints":
							switch claimMap[3] {
							case "ADD":
								thumbprints := strings.Split(value, ",")
								Policies.PopCheckPolicies.BannedKeys = append(Policies.PopCheckPolicies.BannedKeys, thumbprints...)
								claimMap[3] = "GET"
								fallthrough
							case "DELETE":
								for index, thumbprint := range Policies.PopCheckPolicies.BannedKeys {
									if thumbprint == value {
										Policies.PopCheckPolicies.BannedKeys = append(Policies.PopCheckPolicies.BannedKeys[:index], Policies.PopCheckPolicies.BannedKeys[index+1:]...)
										break
									}
								}
								claimMap[3] = "GET"
								fallthrough
							case "GET":
								var thumbprintList string
								for index, thumbprint := range Policies.PopCheckPolicies.BannedKeys {
									if index > 0 {
										thumbprintList += ","
									}
									thumbprintList += thumbprint
								}
								utils.JsonRecursiveMarshall(getRoute(claimMap), thumbprintList, &response)
							}
						case "audience":
							switch claimMap[3] {
							case "GET":
								utils.JsonRecursiveMarshall(getRoute(claimMap), Policies.PopCheckPolicies.Audience, &response)
							case "SET":
								Policies.PopCheckPolicies.Audience = value
								utils.JsonRecursiveMarshall(claim, Policies.PopCheckPolicies.Audience, &response)
							}
						case "GET":
						default:
						}
					case "AT":
						switch claimMap[2] {
						case "vehicles":
							switch claimMap[3] {
							case "ADD":
							case "GET":
							case "DELETE":
							}
						case "GET":
						default:
						}
					case "Management":
						switch claimMap[2] {
						case "allowed_keys":
							switch claimMap[3] {
							case "ADD":
							case "GET":
							case "DELETE":
							}
						case "GET":
						default:
						}
					// Methods
					case "GET":
					case "ADD":
					case "SET":
					case "DELETE":
					default:
						return genErrorMap("400", `{"error":"Invalid Request"}`)
					}
				}
			default: // Not
				utils.JsonRecursiveMarshall(claim, "error: Bad Route", &response)
			}
		}
		writePolicies()
		resp := make(ChannelData)
		resp["response"] = response
		return resp
		/*
			// Iterates the route
			for i := 1; i < len(claimMap); i++ {
				switch pointer.(type) {
				case struct{}:
					structPointer, _ := pointer.(*struct)
					pointer = &structPointer[claimMap[i]]
				case []string:
				case string:
				case int:
				case bool:

				}
			}

			for claim, value := range body {
				switch value.(type) {
				case int:

				case string:
				}
			}*/

	/*
		var managementToken utils.ExtendedJwt
		managementToken.DecodeFromFull(body)

		// Token checking
		if iat, err := strconv.Atoi(managementToken.PayloadClaims["iat"]); err != nil || iat > int(time.Now().Unix()) {
			return genErrorMap("400", `{"error":"Bad Iat"}`)
		}
		if exp, err := strconv.Atoi(managementToken.PayloadClaims["exp"]); err != nil || exp < int(time.Now().Unix()) {
			if err != nil {
				return genErrorMap("400", `{"error":"Invalid exp"}`)
			}
			return genErrorMap("400", `{"error":"Token expired"}`)
		}
		if managementToken.PayloadClaims["aud"] != "ats/management" {
			return genErrorMap("400", `{"error":"Invalid Audience"}`)
		}

		for claim, content := range managementToken.PayloadClaims {
			if claim == "iat" || claim == "exp" || claim == "aud" {
				continue
			}
			fmt.Printf(content)
			claimURL := strings.Split(claim, ".")
			for _, content := range claimURL {
				if content == "" {
					// RETURN VALUES
				} else {
					// CHANGE VALUES
					fmt.Printf(content)
				}
			}
		}
		response := make(map[string]string)
		response["type"] = "response"
		response["response"] = "Server management URL not avaliable already"
		return response */

}

// ************* POLICIES AND KEY MANAGEMENT METHODS *************

// ************* PURPOSE LIST AND SCOPE LIST INITALIZATION *************

// Initializes the purposelist map using the file
func initPurposelist() {
	data, err := ioutil.ReadFile("purposelist.json")
	if err != nil {
		utils.Error.Printf("Error reading purposelist.json; %s\n", err)
		os.Exit(-1)
	}
	err = json.Unmarshal([]byte(data), &purposeList)
	if err != nil {
		utils.Error.Printf("initPurposelist:error data=%s, err=%s", data, err)
		os.Exit(-1)
	}
	extractPurposeElementsLevel1(purposeList)
}

func extractPurposeElementsLevel1(purposeList map[string]interface{}) {
	for k, v := range purposeList {
		switch vv := v.(type) {
		case []interface{}:
			utils.Info.Println(k, "is an array:, len=", strconv.Itoa(len(vv)))
			extractPurposeElementsLevel2(vv)
		case map[string]interface{}:
			utils.Info.Println(k, "is a map:")
			extractPurposeElementsLevel3(0, vv)
		default:
			utils.Info.Println(k, "is of an unknown type")
		}
	}
}

func extractPurposeElementsLevel2(purposeList []interface{}) {
	pList = make([]PurposeElement, len(purposeList))
	i := 0
	for k, v := range purposeList {
		switch vv := v.(type) {
		case map[string]interface{}:
			utils.Info.Println(k, "is a map:")
			extractPurposeElementsLevel3(i, vv)
		default:
			utils.Info.Println(k, "is of an unknown type")
		}
		i++
	}
}

func extractPurposeElementsLevel3(index int, purposeElem map[string]interface{}) {
	for k, v := range purposeElem {
		switch vv := v.(type) {
		case string:
			utils.Info.Println(k, "is string", vv)
			if k == "short" {
				pList[index].Short = vv
			} else {
				pList[index].Long = vv
			}
		case []interface{}:
			utils.Info.Println(k, "is an array:, len=", strconv.Itoa(len(vv)))
			if k == "contexts" {
				pList[index].Context = make([]ContextElement, len(vv))
				extractPurposeElementsL4ContextL1(index, vv)
			} else {
				pList[index].Access = make([]AccessElement, len(vv))
				extractPurposeElementsL4SignalAccessL1(index, vv)
			}
		case map[string]interface{}:
			utils.Info.Println(k, "is a map:")
			if k == "contexts" {
				pList[index].Context = make([]ContextElement, 1)
				extractPurposeElementsL4ContextL2(0, index, vv)
			} else {
				pList[index].Access = make([]AccessElement, 1)
				extractPurposeElementsL4SignalAccessL2(0, index, vv)
			}
		default:
			utils.Info.Println(k, "is of an unknown type")
		}
	}
}

func extractPurposeElementsL4ContextL1(index int, contextElem []interface{}) {
	for k, v := range contextElem {
		switch vv := v.(type) {
		case map[string]interface{}:
			utils.Info.Println(k, "is a map:")
			extractPurposeElementsL4ContextL2(k, index, vv)
		default:
			utils.Info.Println(k, "is of an unknown type")
		}
	}
}

func extractPurposeElementsL4ContextL2(k int, index int, contextElem map[string]interface{}) {
	for i, u := range contextElem {
		utils.Info.Println(i, u)
		switch vvv := u.(type) {
		case string:
			if i == "user" {
				pList[index].Context[k].Actor[0].Role = make([]string, 1)
				pList[index].Context[k].Actor[0].Role[0] = u.(string)
			} else if i == "app" {
				pList[index].Context[k].Actor[1].Role = make([]string, 1)
				pList[index].Context[k].Actor[1].Role[0] = u.(string)
			} else {
				pList[index].Context[k].Actor[2].Role = make([]string, 1)
				pList[index].Context[k].Actor[2].Role[0] = u.(string)
			}
		case []interface{}:
			m := 0
			for l, t := range vvv {
				utils.Info.Println(l, t)
				switch typ := t.(type) {
				case string:
					if i == "user" {
						if m == 0 {
							pList[index].Context[k].Actor[0].Role = make([]string, len(vvv))
						}
						pList[index].Context[k].Actor[0].Role[m] = t.(string)
					} else if i == "app" {
						if m == 0 {
							pList[index].Context[k].Actor[1].Role = make([]string, len(vvv))
						}
						pList[index].Context[k].Actor[1].Role[m] = t.(string)
					} else {
						if m == 0 {
							pList[index].Context[k].Actor[2].Role = make([]string, len(vvv))
						}
						pList[index].Context[k].Actor[2].Role[m] = t.(string)
					}
				default:
					utils.Info.Println(k, "is of an unknown type: ", typ)
				}
				m++
			}
		default:
			utils.Info.Println(k, "is of an unknown type")
		}
	}
}

func extractPurposeElementsL4SignalAccessL1(index int, accessElem []interface{}) {
	for k, v := range accessElem {
		switch vv := v.(type) {
		case map[string]interface{}:
			utils.Info.Println(k, "is a map:")
			extractPurposeElementsL4SignalAccessL2(k, index, vv)
		default:
			utils.Info.Println(k, "is of an unknown type")
		}
	}
}

func extractPurposeElementsL4SignalAccessL2(k int, index int, accessElem map[string]interface{}) {
	for i, u := range accessElem {
		utils.Info.Println(i, u)
		if i == "path" {
			pList[index].Access[k].Path = u.(string)
		} else {
			pList[index].Access[k].Permission = u.(string)
		}
	}
}

// Initializes the Scope List to the map in the server
func initScopeList() {
	data, err := ioutil.ReadFile("scopelist.json")
	if err != nil {
		utils.Info.Printf("scopelist.json not found")
		return
	}
	err = json.Unmarshal([]byte(data), &scopeList)
	if err != nil {
		utils.Error.Printf("initScopeList:error data=%s, err=%s", data, err)
		os.Exit(-1)
	}
	extractScopeElementsLevel1(scopeList)
}

func extractScopeElementsLevel1(scopeList map[string]interface{}) {
	for k, v := range scopeList {
		switch vv := v.(type) {
		case []interface{}:
			utils.Info.Println(k, "is an array:, len=", strconv.Itoa(len(vv)))
			extractScopeElementsLevel2(vv)
		case map[string]interface{}:
			utils.Info.Println(k, "is a map:")
			extractScopeElementsLevel3(0, vv)
		default:
			utils.Info.Println(k, "is of an unknown type")
		}
	}
}

func extractScopeElementsLevel2(scopeList []interface{}) {
	sList = make([]ScopeElement, len(scopeList))
	i := 0
	for k, v := range scopeList {
		switch vv := v.(type) {
		case map[string]interface{}:
			utils.Info.Println(k, "is a map:")
			extractScopeElementsLevel3(i, vv)
		default:
			utils.Info.Println(k, "is of an unknown type")
		}
		i++
	}
}

func extractScopeElementsLevel3(index int, scopeElem map[string]interface{}) {
	for k, v := range scopeElem {
		switch vv := v.(type) {
		case string:
			sList[index].NoAccess = make([]string, 1)
			sList[index].NoAccess[0] = vv
		case []interface{}:
			utils.Info.Println(k, "is an array:, len=", strconv.Itoa(len(vv)))
			if k == "contexts" {
				sList[index].Context = make([]ContextElement, len(vv))
				extractScopeElementsL4ContextL1(index, vv)
			} else {
				sList[index].NoAccess = make([]string, len(vv))
				extractScopeElementsL4NoAccessL1(index, vv)
			}
		case map[string]interface{}:
			utils.Info.Println(k, "is a map:")
			sList[index].Context = make([]ContextElement, 1)
			extractScopeElementsL4ContextL2(0, index, vv)
		default:
			utils.Info.Println(k, "is of an unknown type")
		}
	}
}

func extractScopeElementsL4ContextL1(index int, contextElem []interface{}) {
	for k, v := range contextElem {
		switch vv := v.(type) {
		case map[string]interface{}:
			utils.Info.Println(k, "is a map:")
			extractScopeElementsL4ContextL2(k, index, vv)
		default:
			utils.Info.Println(k, "is of an unknown type")
		}
	}
}

func extractScopeElementsL4ContextL2(k int, index int, contextElem map[string]interface{}) {
	for i, u := range contextElem {
		utils.Info.Println(i, u)
		switch vvv := u.(type) {
		case string:
			if i == "user" {
				sList[index].Context[k].Actor[0].Role = make([]string, 1)
				sList[index].Context[k].Actor[0].Role[0] = u.(string)
			} else if i == "app" {
				sList[index].Context[k].Actor[1].Role = make([]string, 1)
				sList[index].Context[k].Actor[1].Role[0] = u.(string)
			} else {
				sList[index].Context[k].Actor[2].Role = make([]string, 1)
				sList[index].Context[k].Actor[2].Role[0] = u.(string)
			}
		case []interface{}:
			m := 0
			for l, t := range vvv {
				utils.Info.Println(l, t)
				switch typ := t.(type) {
				case string:
					if i == "user" {
						if m == 0 {
							sList[index].Context[k].Actor[0].Role = make([]string, len(vvv))
						}
						sList[index].Context[k].Actor[0].Role[m] = t.(string)
					} else if i == "app" {
						if m == 0 {
							sList[index].Context[k].Actor[1].Role = make([]string, len(vvv))
						}
						sList[index].Context[k].Actor[1].Role[m] = t.(string)
					} else {
						if m == 0 {
							sList[index].Context[k].Actor[2].Role = make([]string, len(vvv))
						}
						sList[index].Context[k].Actor[2].Role[m] = t.(string)
					}
				default:
					utils.Info.Println(k, "is of an unknown type:", typ)
				}
				m++
			}
		default:
			utils.Info.Println(k, "is of an unknown type")
		}
	}
}

func extractScopeElementsL4NoAccessL1(index int, noAccessElem []interface{}) {
	for k, v := range noAccessElem {
		switch vv := v.(type) {
		case string:
			utils.Info.Println(vv)
			sList[index].NoAccess[k] = vv
		default:
			utils.Info.Println(k, "is of an unknown type")
		}
	}
}

// ************* END PURPOSE LIST AND SCOPE LIST INITALIZATION *************

func main() {
	// Create new parser object
	parser := argparse.NewParser("print", "AT Server")
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

	// Channels for processes communication and Server Mux
	serverChan := make(chan ChannelData)
	mgmChan := make(chan ChannelData)
	muxServer := http.NewServeMux()

	utils.InitLog("atserver-log.txt", "./logs", *logFile, *logLevel)
	initPurposelist()
	initScopeList()
	initVssFile()
	initPolicies()

	go initAtServer(serverChan, mgmChan, muxServer)

	for {
		select {
		case ATrequest := <-serverChan:
			response := generateResponse(ATrequest)
			//utils.Info.Printf("atServer response=%s", response)
			serverChan <- response
		case mgmRequest := <-mgmChan:
			response := generateManagementResponse(mgmRequest)
			utils.Info.Printf("atServer management response", response)
			mgmChan <- response
		}
	}
}
