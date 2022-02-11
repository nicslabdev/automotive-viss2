/************
*	Grand Touring Client: AGT, AT and VissV2 client.
*
*
*	Author: Jose Jesus Sanchez Gomez (sanchezg@lcc.uma.es)
*	2021, NICS Lab (University of Malaga)
*
*************/

package main

import (
	"bufio"
	"bytes"
	"crypto/rsa"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"

	"github.com/MEAE-GOT/WAII/utils"
)

const AGT_URL = "http://127.0.0.1:7500/agtserver"
const AT_URL = "http://127.0.0.1:8600/atserver"

type StringMap map[string]string

func getUserInput() string {
	reader := bufio.NewReader(os.Stdin)
	// Disable input buffer
	exec.Command("stty", "-F", "/dev/tty", "cbreak", "min", "1").Run()
	//Get the character
	input, err := reader.ReadByte()
	//Clear the line
	fmt.Println("\r     \r")
	if err != nil {
		return fmt.Sprint(err)
	}
	return fmt.Sprintf("%c", input)
}

// SERVER POST REQUESTER: From the URL (depending on the server) and the request to make, it post a request and returns the response
func postRequest(url string, request string) (response string, err error) {
	/*req, err := http.NewRequest("POST", agt_url, bytes.NewBufferString([]byte(request)))
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)*/

	buf := bytes.NewBufferString(request)
	resp, err := http.Post(url, "application/json", buf)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), err
}

// AGT REQUEST MANAGEMENT METHODS
func (claimMap StringMap) initAGTClaim() {
	claimMap[`vin`] = `GEO001`
	claimMap[`context`] = `Independent+OEM+Cloud`
	claimMap[`proof`] = `ABC`
}
func (claimMap StringMap) deleteAGTClaim(key string) {
	delete(claimMap, key)
}
func (claimMap StringMap) addAGTClaim(key string, value string) {
	claimMap[key] = value
}
func (claimMap StringMap) getFull() string {
	str := `{\n`
	for key, element := range claimMap {
		str = str + `\t"` + key + `" : "` + element + `",\n`
	}
	str = str + `}`
	return str
}
func (claimMap StringMap) generateAgt() string {
	var strAGT string
	for key, value := range claimMap {
		utils.JsonRecursiveMarshall(key, value, &strAGT)
	}
	return strAGT
}

// Generates a JWT being the pop of certain key
func generatePopToken(privKey *rsa.PrivateKey) (string, error) {
	// var token utils.JsonWebToken
	// token.SetHeader("RS256")
	// // These claims are also sent but not inside the jwt
	// // AGT.Payload = claimMap.generateAgt()
	// token.AddClaim("iat", strconv.Itoa(int(time.Now().Unix())))
	// // Create jwk which will add to jwt
	// var jwk utils.JsonWebKey
	// jwk.Use = "sig"
	// jwk.Type = "RSA"
	// jwk.PubExp = strconv.Itoa(privKey.PublicKey.E)
	// jwk.PubMod = privKey.PublicKey.N.String()
	// strJwk, err := jwk.Marshall()
	// if err != nil {
	// 	return "", err
	// }
	// // CNF claim, including the public key is needed https://datatracker.ietf.org/doc/html/rfc7800#section-3.2
	// token.AddClaim(`cnf`, `{"jwk":`+strJwk+`}`) //// BASSE 64 ENCODING
	// // NEED TO ENCODE JWK IN BASE 64!!!!!!!!!!!!!!!!!!!!!!!!!!
	// err = token.Sign(privKey)
	// if err != nil {
	// 	return "", err
	// }
	// return token.GetFullToken(), nil
	var popToken utils.PopToken
	return popToken.GenerateToken(*privKey)
}

func main() {
	var privKey1 *rsa.PrivateKey
	//var pubKey1 rsa.PublicKey
	//var privKey2 rsa.PrivateKey
	//var pubKey2 rsa.PublicKey

	AGTClaims := make(StringMap)
	AGTClaims.initAGTClaim()

	for true {
		fmt.Println("---   GT CLIENT   ---\n\t1 - Initialize client\n\t2 - AGT Server Communication\n\t3 - AT Server Communication \n\t4 - VISSv2 Server Communication")
		var Opt string
		Opt = "1"
		Opt = getUserInput()
		switch Opt {
		case "1": // Client initialization
			fmt.Println("CLIENT INITIALIZATION")
			fmt.Println("\t1 - Configure RSA Authentication\n\t2 - Configure AGT claims")
			var initOpt string
			initOpt = "1"
			initOpt = getUserInput()
			switch initOpt {
			case "1": // RSA configuration
				var agtOpt string
				fmt.Printf("RSA AUTHENTICATION CONFIGURATION -----\n  - RSA configured: %v", privKey1 != nil)
				for agtOpt != "0" {
					fmt.Printf("\n\t1 - Generate new RSA KeyPair\n\t2 - Print RSA KeyPair\n\t3 - Export RSA Keys\n\t0 - Back to main menu\n")
					agtOpt = getUserInput()
					//fmt.Scanln(&initOpt)
					switch agtOpt {
					case "1": // New RSA Keypair
						err := utils.GenRsaKey(2048, &privKey1)
						if err != nil {
							fmt.Println("Couldn't generate RSA KeyPair")
						} else {
							fmt.Println("Key Generated correctly. RSA Configured Correctly")
						}
					case "2": // Print RSA Keys
						privStr, pubStr, err := utils.PemEncodeRSA(privKey1)
						if err != nil {
							fmt.Println("Couldn't get keys")
						} else {
							fmt.Printf("%s\n%s\n", privStr, pubStr)
						}
					case "3": // Export keys to file
						prvKeyFile := "rsa_priv"
						pubKeyFile := "rsa_pub"
						fmt.Print("Private key filename (w/o ext.): ")
						fmt.Scanln(&prvKeyFile)
						fmt.Print("Public key filename: ")
						fmt.Scanln(&pubKeyFile)
						err := utils.ExportKeyPair(privKey1, prvKeyFile, pubKeyFile)
						if err != nil {
							fmt.Printf("Could not export keys, error: %s", err)
						} else {
							fmt.Println("Keys exported correctly")
						}
					case "4": // Import keys from file
						fmt.Println("Still not implemented. Will implement when needed to use with second client signature")
					case "0":
						fmt.Println()
					default:
						fmt.Printf("Unknown input: %s", agtOpt)
					}
				}
			}
		case "2": // AGT Communication
			fmt.Println("AGT Communication\n\t1 - Send token request\n\t2 - Claims Management\n\t0 - Back to main menu")
			var agtOpt string
			for agtOpt != "0" {
				agtOpt = "1"
				agtOpt = getUserInput()
				switch agtOpt {
				case "1": // Send token Request
					useRSA := false
					if privKey1 != nil {
						fmt.Println("- Looks like you have configurated a RSA KeyPair, Want to use it? (y/n)")
						resp := getUserInput()
						//resp = "n"
						if resp == "y" || resp == "1" {
							useRSA = true
						}
					}
					// If not using RSA signature for authentication, the request will be quite easy, just JSON plain text including the claims
					if useRSA {
						token, err := generatePopToken(privKey1)
						if err != nil {
							fmt.Printf("Could not generate authentication token. RSA signature will not be used, error: %s\n", err)
						} else {
							AGTClaims.addAGTClaim("token", token)
						}
					}
					PostContent := AGTClaims.generateAgt()
					fmt.Printf("Using RSA authentication: %v\nSending POST Request to %s: \n%s\n", useRSA, AGT_URL, PostContent)
					// SEND POST REQUEST
					resp, err := postRequest(AGT_URL, PostContent)
					if err != nil {
						fmt.Printf("Error sending POST Request: %s\n", err)
					} else {
						fmt.Printf("\nPOST Response received: \n%s \n", resp)
					}
				case "2": // Claims management
					fmt.Printf("\t\t Actual claims:\n%s", AGTClaims.getFull())
					fmt.Println("\t\t Want to make any changes? (y/n)")
					var option string
					fmt.Scanln(option)
					if option == "y" {
						fmt.Println("\t\t1 - Default values\n\t\t2 - Add/Change Claim\n\t\t3 - Remove Claim")
						fmt.Scanln(option)
						switch option {
						case "1":
							fmt.Println("\t\t Initialized to default values")
							AGTClaims.initAGTClaim()
						case "2":
							var key, value string
							fmt.Println("\t\t")
							fmt.Println("\t\t\tKey: ")
							fmt.Scanln(key)
							fmt.Println("\t\t\tNew Value: ")
							fmt.Scanf(value)
							AGTClaims.addAGTClaim(key, value)
						case "3":
							var key string
							fmt.Println("\t\t\tKey to delete: ")
							fmt.Scanf(key)
							AGTClaims.deleteAGTClaim(key)
						default:
							fmt.Println("Wrong Option")
						}
					}
				}
			}
		}
	}
}
