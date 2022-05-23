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
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/MEAE-GOT/WAII/utils"
)

const AGT_URL = "http://127.0.0.1:7500/agtserver"

//const AGT_URL = "http://150.214.47.151:61057/agtserver"
const AT_URL = "http://127.0.0.1:8600/atserver"

type StringMap map[string]string
type TokenMap map[string]*utils.JsonWebToken

func getUserInput() string {
	var input string
	fmt.Scanln(&input)
	return input
	/*
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
		return fmt.Sprintf("%c", input)*/
}

// Makes a post request on the url given. Body must be given as string, header must be passed as map[string]string
func postRequest(url string, reqBody string, reqHeader StringMap) (string, error) {
	client := &http.Client{}
	// Creates a new request, body filled
	request, err := http.NewRequest("POST", AGT_URL, bytes.NewBufferString(reqBody))
	if err != nil {
		return "", err
	}
	// Fills header
	request.Header.Add("content", "application/json") // Should be filled by the caller
	for param, content := range reqHeader {
		request.Header.Add(param, content)
	}
	// Sends the request
	response, err := client.Do(request)
	if err != nil {
		return "", err
	}
	// Waits for func finalization to close the body
	defer response.Body.Close()
	// Reads the body and returns it
	body, err := io.ReadAll(response.Body)
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
func (claimMap StringMap) generateAgtReq() string {
	var strAGT string
	for key, value := range claimMap {
		utils.JsonRecursiveMarshall(key, value, &strAGT)
	}
	return strAGT
}

func (tokenMap *TokenMap) Add(id string, res string) string {
	(*tokenMap)[id] = new(utils.JsonWebToken)
	tempMap := make(map[string]string)
	err := json.Unmarshal([]byte(res), &tempMap)
	err2 := (*tokenMap)[id].DecodeFromFull(tempMap["token"])
	if err != nil || err2 != nil {
		delete((*tokenMap), id)
		return fmt.Sprintf("Token may not be valid, cannot decode: %s\n", err)
	}
	return fmt.Sprintf("Token with id %s saved \n", id)
}

func main() {
	var privRsaKey1 *rsa.PrivateKey
	var privEcdsaKey1 *ecdsa.PrivateKey
	//var pubKey1 rsa.PublicKey
	//var privKey2 rsa.PrivateKey
	//var pubKey2 rsa.PublicKey

	AGTClaims := make(StringMap)
	AGTClaims.initAGTClaim()
	AGTPOPClaims := make(StringMap)
	AGTPOPClaims.addAGTClaim("aud", "vissv2/Agt")
	AgTokenList := make(TokenMap)

	// FAST INITIALIZATION
	fmt.Println("---   GT CLIENT   ---\n\tPress 1 for fast initialization")
	if getUserInput() == "1" {
		fmt.Println("\tTrying to import keys ----")
		err := utils.ImportRsaKey("rsa_priv.rsa", &privRsaKey1)
		if err != nil {
			fmt.Println("\tRSA not imported, generating key")
			err = utils.GenRsaKey(256, &privRsaKey1)
			if err != nil {
				panic("Could not either generate key,")
			} else {
				fmt.Println("\tRSA key generated")
			}
		} else {
			fmt.Println("\tRSA key imported")
		}

		err = utils.ImportEcdsaKey("ecdsa_priv.ec", &privEcdsaKey1)
		if err != nil {
			fmt.Println("\tECDSA not imported, generating key")
			err = utils.GenEcdsaKey(elliptic.P256(), &privEcdsaKey1)
			if err != nil {
				panic("Could not either generate key,")
			} else {
				fmt.Println("\tECDSA key generated")
			}
		} else {
			fmt.Println("\tECDSA key imported\n ")
		}
	}

	for true {
		fmt.Println("---   GT CLIENT   ---\n\t1 - Initialize client\n\t2 - AGT Server Communication\n\t3 - AT Server Communication \n\t4 - VISSv2 Server Communication")
		var Opt string
		Opt = "1"
		Opt = getUserInput()
		switch Opt {
		// Client initialization
		case "1":
			fmt.Println("CLIENT INITIALIZATION")
			fmt.Println("\t1 - Configure RSA Authentication\n\t2 - Configure ECDSA Authentication\n\t0 - Back to Main Menu")
			initOpt := "1"
			initOpt = getUserInput()
			switch initOpt {
			case "1": // RSA configuration
				var rsaOpt string
				for rsaOpt != "0" {
					fmt.Printf("RSA AUTHENTICATION CONFIGURATION -----\n  - RSA configured: %v", privRsaKey1 != nil)
					fmt.Printf("\n\t1 - Generate new RSA KeyPair\n\t2 - Print RSA KeyPair\n\t3 - Export RSA Keys\n\t4 - Import keys from file (name: rsa_priv.rsa)\n\t0 - Back to main menu\n")
					rsaOpt = getUserInput()
					//fmt.Scanln(&initOpt)
					switch rsaOpt {
					case "1": // New RSA Keypair
						err := utils.GenRsaKey(2048, &privRsaKey1)
						if err != nil {
							fmt.Println("Couldn't generate RSA KeyPair")
						} else {
							fmt.Println("Key Generated correctly. RSA Configured Correctly")
						}
					case "2": // Print RSA Keys
						privStr, pubStr, err := utils.PemEncodeRSA(privRsaKey1)
						if err != nil {
							fmt.Println("Couldn't get keys")
						} else {
							fmt.Printf("%s\n%s\n", privStr, pubStr)
						}
					case "3": // Export keys to file
						prvKeyFile := "rsa_priv"
						pubKeyFile := "rsa_pub"
						//fmt.Print("Private key filename (w/o ext.): ")
						//fmt.Scanln(&prvKeyFile)
						//fmt.Print("Public key filename: ")
						///fmt.Scanln(&pubKeyFile)
						err := utils.ExportKeyPair(privRsaKey1, prvKeyFile, pubKeyFile)
						if err != nil {
							fmt.Printf("Could not export keys, error: %s", err)
						} else {
							fmt.Println("Keys exported correctly")
						}
					case "4": // Import keys from file
						err := utils.ImportRsaKey("rsa_priv.rsa", &privRsaKey1)
						if err != nil {
							fmt.Printf("Could not import keys, error: %s\n", err)
						} else {
							fmt.Println("Keys imported correctly. RSA Configured\n ")
						}
					case "0":
						fmt.Println()
					default:
						fmt.Printf("Unknown input: %s", rsaOpt)
					}
				}
			case "2":
				var ecdsaOpt string
				for ecdsaOpt != "0" {
					fmt.Printf("ECDSA AUTHENTICATION CONFIGURATION -----\n  - ECDSA configured: %v", privEcdsaKey1 != nil)
					fmt.Printf("\n\t1 - Generate new ECDSA KeyPair\n\t2 - Print ECDSA KeyPair\n\t3 - Export ECDSA Keys\n\t4 - Import keys from file (name: ecdsa_priv.ec)\n\t0 - Back to main menu\n")
					ecdsaOpt = "1"
					ecdsaOpt = getUserInput()
					//fmt.Scanln(&initOpt)
					switch ecdsaOpt {
					case "1": // New Keypair
						err := utils.GenEcdsaKey(elliptic.P256(), &privEcdsaKey1)
						if err != nil {
							fmt.Println("Couldn't generate ECDSA KeyPair")
						} else {
							fmt.Println("Key Generated correctly. ECDSA Configured")
						}
					case "2": // Print Keys
						privStr, pubStr, err := utils.PemEncodeECDSA(privEcdsaKey1)
						if err != nil {
							fmt.Println("Couldn't get keys")
						} else {
							fmt.Printf("%s\n%s\n", privStr, pubStr)
						}
					case "3": // Export keys to file
						prvKeyFile := "ecdsa_priv"
						pubKeyFile := "ecdsa_pub"
						//fmt.Print("Private key filename (w/o ext.): ")
						//fmt.Scanln(&prvKeyFile)
						//fmt.Print("Public key filename: ")
						//fmt.Scanln(&pubKeyFile)
						err := utils.ExportKeyPair(privEcdsaKey1, prvKeyFile, pubKeyFile)
						if err != nil {
							fmt.Printf("Could not export keys, error: %s", err)
						} else {
							fmt.Println("Keys exported correctly")
						}
					case "4": // Import keys from file
						err := utils.ImportEcdsaKey("ecdsa_priv.ec", &privEcdsaKey1)
						if err != nil {
							fmt.Printf("\nCould not import keys, error: %s\n", err)
						} else {
							fmt.Println("Keys imported correctly. ECDSA Configured\n ")
						}
					case "0":
						fmt.Println()
					default:
						fmt.Printf("Unknown input: %s", ecdsaOpt)
					}
				}
			}
		case "2": // AGT Communication
			var agtOpt string
			for agtOpt != "0" {
				fmt.Println("AGT Communication\n\t1 - Send token request\n\t2 - Claims Management\n\t3 - Tokens received\n\t0 - Back to main menu")
				agtOpt = "1"
				agtOpt = getUserInput()
				switch agtOpt {
				case "1": // Send token Request
					var response, signMethod string
					var err error
					// Checks for signing methods avaliable
					if privRsaKey1 != nil || privEcdsaKey1 != nil {
						fmt.Printf("Request for long term is avaliable, what signature method do you want to use?")
						fmt.Printf("\n 1 - Not using LT")
						if privRsaKey1 != nil {
							fmt.Printf("\n 2 - RSA")
						}
						if privEcdsaKey1 != nil {
							fmt.Printf("\n 3 - ECDSA")
						}
						fmt.Printf("\n")
						signMethod = getUserInput()
					}
					switch signMethod {
					case "1", "n", "": // No long term
						postContent := AGTClaims.generateAgtReq()
						fmt.Printf("No authentication being used \nSending POST Request to %s: \n%s\n", AGT_URL, postContent)
						response, err = postRequest(AGT_URL, postContent, nil)
						if err != nil {
							fmt.Printf("Error during POST Request sending: %s\n", err)
						}
					case "2", "r": // RSA long term
						fmt.Println("RSA authentication being used. Generating POP Token")
						var popToken utils.PopToken
						var token string
						fmt.Printf("\n\nGT: POPCLAIMS: %s\n\n", AGTPOPClaims)
						err = popToken.Initialize(nil, AGTPOPClaims, &privRsaKey1.PublicKey)
						if err != nil {
							fmt.Printf("Could not generate POP token: %s", err)
							break
						}
						token, err = popToken.GenerateToken(privRsaKey1)
						if err != nil {
							fmt.Printf("\nCould not generate POP token: %s", err)
							break
						}
						fmt.Printf("\nPOP Token (in header): \n%s\n", token)
						AGTClaims.addAGTClaim("key", popToken.Jwk.Thumb)
						postContent := AGTClaims.generateAgtReq()
						AGTClaims.deleteAGTClaim("key")
						fmt.Printf("\n Sending POST Request to %s: \n%s\n", AGT_URL, postContent)
						response, err = postRequest(AGT_URL, postContent, map[string]string{"PoP": token})
						if err != nil {
							fmt.Printf("\nError during POST Request sending: %s\n", err)
						}
					case "3", "e": // ECDSA long term
						fmt.Println("ECDSA authentication being used. Generating POP Token")
						var popToken utils.PopToken
						var token string
						err = popToken.Initialize(nil, map[string]string{"aud": "viss2/Agt"}, &privEcdsaKey1.PublicKey)
						if err != nil {
							fmt.Printf("\nCould not generate POP token: %s", err)
							break
						}
						token, err = popToken.GenerateToken(privEcdsaKey1)
						if err != nil {
							fmt.Printf("\nCould not generate POP token: %s", err)
							break
						}
						fmt.Printf("\nPOP Token (in header): \n%s\n", token)
						AGTClaims.addAGTClaim("key", popToken.Jwk.Thumb)
						postContent := AGTClaims.generateAgtReq()
						AGTClaims.deleteAGTClaim("key")
						fmt.Printf("\n Sending POST Request to %s: \n%s\n", AGT_URL, postContent)
						response, err = postRequest(AGT_URL, postContent, map[string]string{"PoP": token})
						if err != nil {
							fmt.Printf("\nError during POST Request sending: %s\n", err)
						}
					default: // Nothing
						fmt.Println("Nothing done")
					}
					if response != "" {
						fmt.Printf("\nPOST Response received: \n%s\nSave post response? y/n\n", response)
						if input := getUserInput(); input == "y" || input == "1" {
							fmt.Printf("ID: ")
							id := getUserInput()
							fmt.Printf(AgTokenList.Add(id, response))
						}
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
				case "3": // Tokens management
					tokenOpt := "1"
					for tokenOpt != "0" {
						fmt.Println("AuthTokens\n\t1 - See all tokens\n\t2 - Delete by id\n\t3 - Manual Input\n\t0 - Back to main menu\n ")
						tokenOpt = getUserInput()
						switch tokenOpt {
						case "1":
							for key, value := range AgTokenList {
								fmt.Printf("AUTH TOKEN (%s)\n", key)
								HeadMap := make(StringMap)
								PaylMap := make(StringMap)
								err := json.Unmarshal([]byte(value.Header), &HeadMap)
								indentedHead, err2 := json.MarshalIndent(HeadMap, "\t", "\t")
								if err != nil || err2 != nil {
									fmt.Printf("Cannot marshal token %s, It may not be valid.\n%s\n", key, value.GetFullToken())
								} else {
									err := json.Unmarshal([]byte(value.Payload), &PaylMap)
									indentedPayl, err2 := json.MarshalIndent(PaylMap, "\t", "\t")
									if err != nil || err2 != nil {
										fmt.Printf("Cannot marshal token %s, It may not be valid.\n%s\n", key, value.GetFullToken())
									} else {
										fmt.Printf("Header: \n\t%s\n", indentedHead)
										fmt.Printf("Payload: \n\t%s\n", indentedPayl)
									}
								}
							}
						case "2":
							fmt.Println("ID to delete: ")
							id := getUserInput()
							_, exist := AgTokenList[id]
							if exist {
								delete(AgTokenList, id)
								fmt.Println("Deleted\n ")
							} else {
								fmt.Println("Id not found\n ")
							}
						case "3": // Manual input
							fmt.Println("Token ID: ")
							id := getUserInput()
							token := getUserInput()
							fmt.Printf(AgTokenList.Add(id, token))
						}
					}
				}
			}
		case "3": // AT Communication

		}
	}
}
