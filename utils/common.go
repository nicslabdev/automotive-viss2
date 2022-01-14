/**
* (C) 2021 Geotab Inc
*
* All files and artifacts in the repository at https://github.com/MEAE-GOT/WAII
* are licensed under the provisions of the license provided by the LICENSE file in this repository.
*
**/

package utils

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

const IpModel = 0 // IpModel = [0,1,2] = [localhost,extIP,envVarIP]
const IpEnvVarName = "GEN2MODULEIP"

type SvcRegResponse struct {
	Portnum int
	Urlpath string
}

type TranspRegResponse struct {
	Portnum int
	Urlpath string
	Mgrid   int
}

type JsonWebToken struct {
	Header           string
	Payload          string
	EncodedHeader    string
	EncodedPayload   string
	EncodedSignature string
	EncodedToken     string
}

func GetServerIP() string {
	if value, ok := os.LookupEnv(IpEnvVarName); ok {
		Info.Println("ServerIP:", value)
		return value
	}
	Error.Printf("Environment variable %s is not set defaulting to localhost.", IpEnvVarName)
	return "localhost" //fallback
}

func GetModelIP(ipModel int) string {
	if ipModel == 0 {
		return "localhost"
	}
	if ipModel == 2 {
		if value, ok := os.LookupEnv(IpEnvVarName); ok {
			Info.Println("Host IP:", value)
			return value
		}
		Error.Printf("Environment variable %s error.", IpEnvVarName)
		return "localhost" //fallback
	}
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		Error.Fatal(err.Error())
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	Info.Println("Host IP:", localAddr.IP)

	return localAddr.IP.String()
}

func MapRequest(request string, rMap *map[string]interface{}) int {
	decoder := json.NewDecoder(strings.NewReader(request))
	err := decoder.Decode(rMap)
	if err != nil {
		Error.Printf("extractPayload: JSON decode failed for request:%s\n", request)
		return -1
	}
	return 0
}

func UrlToPath(url string) string {
	var path string = strings.TrimPrefix(strings.Replace(url, "/", ".", -1), ".")
	return path[:]
}

func PathToUrl(path string) string {
	var url string = strings.Replace(path, ".", "/", -1)
	return "/" + url
}

func (token *JsonWebToken) SetHeader(algorithm string) {
	token.Header = `{"alg":"` + algorithm + `","typ":"JWT"}`
}

func (token *JsonWebToken) AddClaim(key string, value string) {
	if token.Payload == "" {
		token.Payload = `{"` + key + `":"` + value + `"}`
	} else {
		token.Payload = token.Payload[:len(token.Payload)-1] + `,"` + key + `":"` + value + `"}`
	}
}

func (token *JsonWebToken) Encode() {
	token.EncodedHeader = base64.RawURLEncoding.EncodeToString([]byte(token.Header))
	token.EncodedPayload = base64.RawURLEncoding.EncodeToString([]byte(token.Payload))
}

func (token *JsonWebToken) Sign(key string) error {
	token.Encode()
	token.EncodedToken = token.EncodedHeader + "." + token.EncodedPayload
	if strings.Contains(token.Header, `HS256`) {
		token.EncodedSignature = base64.RawURLEncoding.EncodeToString([]byte(GenerateHmac(token.EncodedToken, key)))
	} else if strings.Contains(token.Header, `RS256`) { //RSASSA-PKCS1-v1_5 + SHA-256
		// Obtains private key in format rsa.PrivateKey from string in PEM format. Includes error managing
		pem_block, _ := pem.Decode([]byte(key))
		if pem_block == nil {
			return errors.New("Private key not found or is not in pem format")
		}
		if pem_block.Type != "RSA PRIVATE KEY" {
			return errors.New("Invalid private key, wrong type")
		}
		privKey, err := x509.ParsePKCS1PrivateKey(pem_block.Bytes)
		if err != nil {
			parsedKey_gen, err := x509.ParsePKCS8PrivateKey(pem_block.Bytes)
			if err != nil {
				return err //errors.New("Unable to parse RSA private key")
			}
			privKey = parsedKey_gen.(*rsa.PrivateKey)
		}
		// Hashes header + payload
		msgHasher := sha256.New()
		msgHasher.Write([]byte(token.EncodedToken))
		msgHash := msgHasher.Sum(nil)
		// privKey is our rsa.PrivateKey. Proceeds to sign
		signature, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, msgHash)
		if err != nil {
			return err
		}
		token.EncodedSignature = base64.RawURLEncoding.EncodeToString(signature)
		//} else if strings.Contains(token.Header, `ES256`) { //ECDSA: P-256 + SHA-256
		//block, _ := pem.Decode([]byte(key))
		//parseResult, _ := x509.ParsePKCS8PrivateKey(block.Bytes)
		//priv_key := parseResult.(*rsa.PrivateKey)
	} else {
		return errors.New("Token signature failed. No compatible alg found on header")
	}
	token.EncodedToken = token.EncodedToken + "." + token.EncodedSignature
	return nil
}

func (token JsonWebToken) GetFullToken() string {
	return token.EncodedToken
}

func (token JsonWebToken) GetHeader() string {
	return token.Header
}

func (token JsonWebToken) GetPayload() string {
	return token.Payload
}

func (token *JsonWebToken) DecodeFromFull(input string) error {
	parts := strings.Split(input, ".")
	if len(parts) != 3 {
		return errors.New("JWT not composed by 3 parts")
	}
	token.EncodedToken = input
	token.EncodedHeader = parts[0]
	token.EncodedPayload = parts[1]
	token.EncodedSignature = parts[2]
	header, err := base64.RawURLEncoding.DecodeString(token.EncodedHeader)
	if err != nil {
		return err
	}
	token.Header = string(header)
	payload, err := base64.RawURLEncoding.DecodeString(token.EncodedPayload)
	if err != nil {
		return err
	}
	token.Payload = string(payload)
	return nil
}

func (token JsonWebToken) CheckSignature(key string) error {
	if strings.Contains(token.Header, `HS256`) {
		if base64.RawURLEncoding.EncodeToString([]byte(GenerateHmac(token.EncodedHeader+"."+token.EncodedPayload, key))) == token.EncodedSignature {
			return nil
		} else {
			return errors.New("Invalid HS256 Signature")
		}
	} else if strings.Contains(token.Header, `RS256`) {
		// Obtains public key block from string
		pubBlock, _ := pem.Decode([]byte(key))
		if pubBlock == nil {
			return errors.New("Private key not found or is not in pem format")
		}
		if pubBlock.Type != "PUBLIC KEY" {
			return errors.New("Invalid public key, wrong type")
		}
		// Parses PKCS1 and PKIX public keys
		pubKey, err := x509.ParsePKCS1PublicKey(pubBlock.Bytes)
		if err != nil {
			parsedKeyGen, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
			if err != nil {
				return errors.New("Unable to parse PublicKey")
			}
			pubKey = parsedKeyGen.(*rsa.PublicKey)
		}
		//Checks signature ParsePKIXPublicKey
		msgHasher := sha256.New()
		msgHasher.Write([]byte(token.EncodedHeader + "." + token.EncodedPayload))
		msgHash := msgHasher.Sum(nil)
		signature, err := base64.RawURLEncoding.DecodeString(token.EncodedSignature)
		if err != nil {
			return err
		}
		err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, msgHash, signature)
		if err != nil {
			return err
		}
		return nil
	}
	return errors.New("Used signing algorithm not compatible")
}

func GenerateHmac(input string, key string) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(input))
	return string(mac.Sum(nil))
}

func VerifyTokenSignature(token string, key string) error { // compatible with result from generateHmac()
	var jwt JsonWebToken
	err := jwt.DecodeFromFull(token)
	if err != nil {
		return err
	}
	return jwt.CheckSignature(key)
}

func ExtractFromToken(token string, claim string) string { // TODO remove white space sensitivity
	delimiter1 := strings.Index(token, ".")
	delimiter2 := strings.Index(token[delimiter1+1:], ".") + delimiter1 + 1
	header := token[:delimiter1]
	payload := token[delimiter1+1 : delimiter2]
	decodedHeaderByte, _ := base64.RawURLEncoding.DecodeString(header)
	decodedHeader := string(decodedHeaderByte)
	claimIndex := strings.Index(decodedHeader, claim)
	if claimIndex != -1 {
		startIndex := claimIndex + len(claim) + 2
		endIndex := strings.Index(decodedHeader[startIndex:], ",") + startIndex // ...claim":abc,...  or ...claim":"abc",... or See next line
		if endIndex == startIndex-1 {                                           // ...claim":abc}  or ...claim":"abc"}
			endIndex = len(decodedHeader) - 1
		}
		if string(decodedHeader[endIndex-1]) == `"` {
			endIndex--
		}
		if string(decodedHeader[startIndex]) == `"` {
			startIndex++
		}
		return decodedHeader[startIndex:endIndex]
	}
	decodedPayloadByte, _ := base64.RawURLEncoding.DecodeString(payload)
	decodedPayload := string(decodedPayloadByte)
	claimIndex = strings.Index(decodedPayload, claim)
	if claimIndex != -1 {
		startIndex := claimIndex + len(claim) + 2
		endIndex := strings.Index(decodedPayload[startIndex:], ",") + startIndex // ...claim":abc,...  or ...claim":"abc",... or See next line
		if endIndex == startIndex-1 {                                            // ...claim":abc}  or ...claim":"abc"}
			endIndex = len(decodedPayload) - 1
		}
		if string(decodedPayload[endIndex-1]) == `"` {
			endIndex--
		}
		if string(decodedPayload[startIndex]) == `"` {
			startIndex++
		}
		return decodedPayload[startIndex:endIndex]
	}
	return ""
}

func SetErrorResponse(reqMap map[string]interface{}, errRespMap map[string]interface{}, number string, reason string, message string) {
	if reqMap["RouterId"] != nil {
		errRespMap["RouterId"] = reqMap["RouterId"]
	}
	if reqMap["action"] != nil {
		errRespMap["action"] = reqMap["action"]
	}
	if reqMap["requestId"] != nil {
		errRespMap["requestId"] = reqMap["requestId"]
	}
	if reqMap["subscriptionId"] != nil {
		errRespMap["subscriptionId"] = reqMap["subscriptionId"]
	}
	errMap := map[string]interface{}{
		"number":  number,
		"reason":  reason,
		"message": message,
	}
	errRespMap["error"] = errMap
	errRespMap["ts"] = GetRfcTime()
}

func FinalizeMessage(responseMap map[string]interface{}) string {
	response, err := json.Marshal(responseMap)
	if err != nil {
		Error.Print("Server core-FinalizeMessage: JSON encode failed. ", err)
		return `{"error":{"number":400,"reason":"JSON marshal error","message":""}}` //???
	}
	return string(response)
}

func AddKeyValue(message string, key string, value string) string { // to avoid Marshal() to reformat using \"
	if len(value) > 0 {
		if value[0] == '{' {
			return message[:len(message)-1] + ", \"" + key + "\":" + value + "}"
		}
		return message[:len(message)-1] + ", \"" + key + "\":\"" + value + "\"}"
	}
	return message
}

func GetRfcTime() string {
	withTimeZone := time.Now().Format(time.RFC3339) // 2020-05-01T15:34:35+02:00
	if withTimeZone[len(withTimeZone)-6] == '+' {
		return withTimeZone[:len(withTimeZone)-6] + "Z"
	} else {
		return withTimeZone
	}
}

func FileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

type FilterObject struct {
	Type  string
	Value string
}

func UnpackFilter(filter interface{}, fList *[]FilterObject) { // See VISSv CORE, Filtering chapter for filter structure
	switch vv := filter.(type) {
	case []interface{}:
		Info.Println(filter, "is an array:, len=", strconv.Itoa(len(vv)))
		*fList = make([]FilterObject, len(vv))
		unpackFilterLevel1(vv, fList)
	case map[string]interface{}:
		Info.Println(filter, "is a map:")
		*fList = make([]FilterObject, 1)
		unpackFilterLevel2(0, vv, fList)
	default:
		Info.Println(filter, "is of an unknown type")
	}
}

func unpackFilterLevel1(filterArray []interface{}, fList *[]FilterObject) {
	i := 0
	for k, v := range filterArray {
		switch vv := v.(type) {
		case map[string]interface{}:
			Info.Println(k, "is a map:")
			unpackFilterLevel2(i, vv, fList)
		default:
			Info.Println(k, "is of an unknown type")
		}
		i++
	}
}

func unpackFilterLevel2(index int, filterExpression map[string]interface{}, fList *[]FilterObject) {
	for k, v := range filterExpression {
		switch vv := v.(type) {
		case string:
			Info.Println(k, "is string", vv)
			if k == "type" {
				(*fList)[index].Type = vv
			} else if k == "value" {
				(*fList)[index].Value = vv
			}
		case []interface{}:
			Info.Println(k, "is an array:, len=", strconv.Itoa(len(vv)))
			arrayVal, err := json.Marshal(vv)
			if err != nil {
				Error.Print("UnpackFilter(): JSON array encode failed. ", err)
			} else if k == "value" {
				(*fList)[index].Value = string(arrayVal)
			}
		case map[string]interface{}:
			Info.Println(k, "is a map:")
			opValue, err := json.Marshal(vv)
			if err != nil {
				Error.Print("UnpackFilter(): JSON map encode failed. ", err)
			} else {
				(*fList)[index].Value = string(opValue)
			}
		default:
			Info.Println(k, "is of an unknown type")
		}
	}
}
