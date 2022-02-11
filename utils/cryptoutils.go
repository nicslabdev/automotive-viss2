/************
*	File implementing multiple cryptographic support for the implementation
*
*	Author: Jose Jesus Sanchez Gomez (sanchezg@lcc.uma.es)
*	2021, NICS Lab (University of Malaga)
*
*************/

package utils

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"time"
)

// Gets rsa key in pem format and decodes it into rsa.privatekey
func PemDecodeRSA(pemKey string, privKey *rsa.PrivateKey) error {
	pemBlock, _ := pem.Decode([]byte(pemKey)) // Gets pem_block from raw key
	// Checking key type and correct decodification
	if pemBlock == nil {
		return errors.New("Private key not found or is not in pem format")
	}
	if pemBlock.Type != "RSA PRIVATE KEY" {
		return errors.New("Invalid private key, wrong type")
	}
	// Parses obtained pem block
	var parsedKey interface{} //Still dont know what key type we need to parse
	parsedKey, err := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	if err != nil {
		parsedKey, err = x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
		if err != nil {
			return err //errors.New("Unable to parse RSA private key")
		}
	}
	// Gets private key from parsed key
	privKey = parsedKey.(*rsa.PrivateKey)
	return nil
}

// Generates RSA private key of given size
func GenRsaKey(size int, privKey **rsa.PrivateKey) error {
	if size%8 != 0 || size < 2048 {
		size = 2048
	}
	auxKey, err := rsa.GenerateKey(rand.Reader, size)
	*privKey = auxKey
	if err != nil {
		return err
	}
	return nil
}

// Returns RSA Keys as string in PEM format
func PemEncodeRSA(privKey *rsa.PrivateKey) (strPrivKey string, strPubKey string, err error) {
	// Creates pem block from given key
	privBlock := pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	}
	// Encodes pem block to byte buffer, then gets the string from it
	privBuf := new(bytes.Buffer)
	err = pem.Encode(privBuf, &privBlock)
	if err != nil {
		return
	}
	strPrivKey = privBuf.String()

	// Same with public key
	pubBlock := pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(&privKey.PublicKey),
	}
	pubBuf := new(bytes.Buffer)
	err = pem.Encode(pubBuf, &pubBlock)
	if err != nil {
		return
	}
	strPubKey = pubBuf.String()
	return
}

// Export RSA KeyPair to files named as given
func ExportKeyPair(privKey *rsa.PrivateKey, privFileName string, pubFileName string) error {
	privBlock := pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	}
	privFile, err := os.Create(privFileName + ".rsa")
	if err != nil {
		return err
	}
	err = pem.Encode(privFile, &privBlock)
	if err != nil {
		return err
	}

	pubBlock := pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(&privKey.PublicKey),
	}
	pubFile, err := os.Create(pubFileName + ".rsa.pub")
	if err != nil {
		return err
	}
	err = pem.Encode(pubFile, &pubBlock)
	if err != nil {
		return err
	}

	return nil
}

// Implements all methods to create a "correct" Json Web Key according to RFC7517
type Cnf struct {
	Jwt JsonWebKey `json:"jwk"`
}
type JsonWebKey struct {
	Type   string `json:"kty"`
	Use    string `json:"use"`
	PubMod string `json:"n"`
	PubExp string `json:"e"`
}

//	Gets the received JWK and unmarshalls it into the defined struct, returns error if fails to unmarshall
func (jkey *JsonWebKey) Unmarshall(rcv string) error {
	return json.Unmarshal([]byte(rcv), jkey)
}

// From JsonWebKey struct, returns marshalled text
func (jkey *JsonWebKey) Marshall() string {
	marsh, err := json.Marshal(jkey)
	if err != nil {
		return ""
	}
	return string(marsh[:])
}

// Pop token sent will contain: iat + cnf. Cnf, at the same time contains "jwk", which contains kty + use + n + e
// Cnf claim is a proof of possession as described in RFC 7800
type PopToken struct {
	alg        string
	Claims     map[string]string // Iat + cnf...
	jsonWebKey JsonWebKey        //
	jwt        JsonWebToken
}

// Gets the received argument as string, and unmarshalls it. Pop token has methods to
func (popToken *PopToken) Unmarshal(token string) error {
	popToken.jwt.DecodeFromFull(token)
	// This is necesary to get all claims from payload as string
	var payloadMap map[string]json.RawMessage
	err := json.Unmarshal([]byte(popToken.jwt.Payload), &payloadMap)
	if err != nil {
		return err
	}
	var iat string
	err = json.Unmarshal(payloadMap["iat"], &iat)
	if err != nil {
		return err
	}
	popToken.Claims = make(map[string]string)
	popToken.Claims["iat"] = iat

	var cnf Cnf // Cnf struct for unmarshalling
	err = json.Unmarshal(payloadMap["cnf"], &cnf)
	if err != nil {
		return err
	}
	popToken.jsonWebKey = cnf.Jwt
	// Get Alg
	var headerMap map[string]json.RawMessage
	err = json.Unmarshal([]byte(popToken.jwt.Header), &headerMap)
	if err != nil {
		return err
	}
	err = json.Unmarshal(headerMap["alg"], &popToken.alg)
	if err != nil {
		return err
	}
	return err
}

func (popToken PopToken) GenerateToken(privKey crypto.PrivateKey) (string, error) {
	var pubKey crypto.PublicKey
	switch typ := privKey.(type) {
	// In case of rsa
	case rsa.PrivateKey:
		priv, _ := privKey.(rsa.PrivateKey)
		pubKey = priv.PublicKey
		if popToken.alg == "" {
			err := popToken.SetPublicKey(pubKey)
			if err != nil {
				return "", err
			}
		}
		if popToken.Claims == nil {
			popToken.Claims = make(map[string]string)
		}
		popToken.Claims["iat"] = strconv.Itoa(int(time.Now().Unix()))
		popToken.jwt.SetHeader(popToken.alg)
		for key, value := range popToken.Claims {
			popToken.jwt.AddClaim(key, value)
		}
		// CNF claim, including the public key: https://datatracker.ietf.org/doc/html/rfc7800#section-3.2
		popToken.jwt.AddClaim(`cnf`, `{"jwk":`+popToken.jsonWebKey.Marshall()+`}`)
		err := popToken.jwt.Sign(&priv)
		if err != nil {
			return "", err
		}
	case ecdsa.PrivateKey:
		return "", errors.New("ECDSA not supported still")
	default:
		return "", errors.New(fmt.Sprintf("PopToken.GenerateToken: %T type not supported", typ))
	}

	return popToken.jwt.GetFullToken(), nil
}

func (popToken *PopToken) GetPublicKey() (rsa.PublicKey, error) {
	var pubKey rsa.PublicKey
	// Decode n and e
	byteN, err := base64.RawURLEncoding.DecodeString(popToken.jsonWebKey.PubMod)
	if err != nil {
		return pubKey, err
	}
	byteE, err := base64.RawURLEncoding.DecodeString(popToken.jsonWebKey.PubExp)
	if err != nil {
		return pubKey, err
	}
	// Converts n and e to big int and int
	n := new(big.Int)
	n.SetBytes(byteN)
	// n, ok = n.SetString(popToken.jsonWebKey.PubMod, 10)
	pubKey.N = n
	pubKey.E, err = strconv.Atoi(string(byteE))
	if err != nil {
		return pubKey, err
	}
	return pubKey, nil
}

func (popToken *PopToken) CheckSignature() error {
	if popToken.alg == "" {
		return errors.New("Cannot check signature of Unmarshalled PopToken")
	}
	pubKey, err := popToken.GetPublicKey()
	if err != nil {
		return err
	}
	return popToken.jwt.CheckSignature(&pubKey)
}

// Assigns a public key to the PopToken
func (popToken *PopToken) SetPublicKey(pubKey crypto.PublicKey) error {
	switch typ := pubKey.(type) {
	case rsa.PublicKey:
		rsaPubKey, _ := pubKey.(rsa.PublicKey)
		popToken.alg = ("RS256")
		popToken.jsonWebKey.Type = "RSA"
		popToken.jsonWebKey.Use = "sig"
		// // To make "E"
		// buf := new(bytes.Buffer)
		// enc := gob.NewEncoder(buf)
		// err := binary.Write(buf, binary.LittleEndian, rsaPubKey.E)
		// if err != nil {
		// 	return err
		// }
		popToken.jsonWebKey.PubExp = base64.RawURLEncoding.EncodeToString([]byte(strconv.Itoa(rsaPubKey.E)))
		popToken.jsonWebKey.PubMod = base64.RawURLEncoding.EncodeToString(rsaPubKey.N.Bytes())
	case ecdsa.PublicKey:
		return errors.New("ECDSA not supported already")
	default:
		return errors.New(fmt.Sprintf("Unknown type of public key: %T", typ))
	}
	return nil
}

// Marshall Jwk would generate a signed jwt used for pop using the claims and the key contained in the token
// Actually pubkey can only be rsa.PublicKey. Code could be extended for using ECDSA signature.
func (popToken *PopToken) MarshallJwk() string {
	return popToken.jsonWebKey.Marshall()
}
