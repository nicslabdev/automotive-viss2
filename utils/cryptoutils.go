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
	"crypto/elliptic"
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
		return errors.New(fmt.Sprintf("Invalid private key, wrong type: %T", pemBlock.Type))
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

// Gets ECDSA key in pem format and decodes it into ecdsa.PrivateKey
func PemDecodeECDSA(pemKey string, privKey *ecdsa.PrivateKey) error {
	pemBlock, _ := pem.Decode([]byte(pemKey))
	if pemBlock == nil {
		return errors.New("Private key not found or is not in pem format")
	}
	if pemBlock.Type != "RSA PRIVATE KEY" {
		return errors.New(fmt.Sprintf("Invalid private key, wrong type: %T", pemBlock.Type))
	}
	var parsedKey interface{}
	parsedKey, err := x509.ParseECPrivateKey(pemBlock.Bytes)
	if err != nil {
		parsedKey, err = x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
	}
	privKey = parsedKey.(*ecdsa.PrivateKey)
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

func GenEcdsaKey(size int, privKey **ecdsa.PrivateKey) error {
	if size%8 != 0 || size < 2048 {
		size = 2048
	}

	auxKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	*privKey = auxKey
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

// Returns ECDSA Keys as string in PEM format
func PemEncodeECDSA(privKey *ecdsa.PrivateKey) (strPrivKey string, strPubKey string, err error) {
	byteKey, _ := x509.MarshalECPrivateKey(privKey)
	privBlock := pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: byteKey,
	}
	buf := bytes.NewBuffer(nil)
	if err = pem.Encode(buf, &privBlock); err != nil {
		return
	}
	strPrivKey = buf.String()

	byteKey, _ = x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	pubBlock := pem.Block{
		Type:  "EC PUBLIC KEY",
		Bytes: byteKey,
	}
	if err = pem.Encode(buf, &pubBlock); err != nil {
		return
	}
	strPubKey = buf.String()
	return
}

// Export KeyPair to files named as given (ECDSA and RSA supported, pointers to privKey must be given)
func ExportKeyPair(privKey interface{}, privFileName string, pubFileName string) error {
	switch typ := privKey.(type) {
	case *rsa.PrivateKey:
		rsaPriv, _ := privKey.(*rsa.PrivateKey)
		privBlock := pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(rsaPriv),
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
			Bytes: x509.MarshalPKCS1PublicKey(&rsaPriv.PublicKey),
		}
		pubFile, err := os.Create(pubFileName + ".rsa.pub")
		if err != nil {
			return err
		}
		err = pem.Encode(pubFile, &pubBlock)
		if err != nil {
			return err
		}
	case *ecdsa.PrivateKey:
		ecdsaPriv, _ := privKey.(*ecdsa.PrivateKey)
		ecdsaByt, _ := x509.MarshalECPrivateKey(ecdsaPriv)
		privBlock := pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: ecdsaByt,
		}
		privFile, err := os.Create(privFileName + ".rsa")
		if err != nil {
			return err
		}
		err = pem.Encode(privFile, &privBlock)
		if err != nil {
			return err
		}
		ecdsaByt, _ = x509.MarshalPKIXPublicKey(&ecdsaPriv.PublicKey)
		pubBlock := pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: ecdsaByt,
		}
		pubFile, err := os.Create(pubFileName + ".rsa.pub")
		if err != nil {
			return err
		}
		err = pem.Encode(pubFile, &pubBlock)
		if err != nil {
			return err
		}
	default:
		return (errors.New(fmt.Sprintf("Cannot generate key of type: %T", typ)))
	}
	return nil
}

// Implements all methods to create a "correct" Json Web Key according to RFC7517
type Cnf struct {
	Jwt JsonWebKey `json:"jwk"`
}
type JsonWebKey struct {
	Thumb  string `json:"-"`
	Type   string `json:"kty"`
	Use    string `json:"use,omitempty"`
	PubMod string `json:"n,omitempty"`     // RSA
	PubExp string `json:"e,omitempty"`     // RSA
	Curve  string `json:"curve,omitempty"` //ECDSA
	Xcoord string `json:"x,omitempty"`     //ECDSA
	Ycoord string `json:"y,omitempty"`     //ECDSA
}

// Initializes json web key from public key
func (jkey *JsonWebKey) Initialize(pubKey crypto.PublicKey, use string) error {
	//jkey.Use = "sig"
	jkey.Use = use
	jkey.Type = ""
	if _, ok := pubKey.(rsa.PublicKey); ok {
		jkey.Type = "RSA"
	}
	if _, ok := pubKey.(ecdsa.PublicKey); ok {
		jkey.Type = "ECDSA"
	}
	switch jkey.Type {
	case "RSA":
		rsaPubKey, _ := pubKey.(rsa.PublicKey)
		jkey.PubExp = base64.RawURLEncoding.EncodeToString([]byte(strconv.Itoa(rsaPubKey.E)))
		jkey.PubMod = base64.RawURLEncoding.EncodeToString(rsaPubKey.N.Bytes())
		// Generates thumberprint
		JsonRecursiveMarshall("e", jkey.PubExp, &jkey.Thumb)
		JsonRecursiveMarshall("kty", jkey.Type, &jkey.Thumb)
		JsonRecursiveMarshall("n", jkey.PubMod, &jkey.Thumb)
		fmt.Printf("\n" + jkey.Thumb + "\n")
	case "ECDSA":
		ecdsaPubKey, _ := pubKey.(ecdsa.PublicKey)
		jkey.Curve = fmt.Sprintf("P-%v", ecdsaPubKey.Curve.Params().BitSize)
		jkey.Xcoord = ecdsaPubKey.X.String()
		jkey.Ycoord = ecdsaPubKey.Y.String()
		// Generates thumberprint
		JsonRecursiveMarshall("crv", jkey.Curve, &jkey.Thumb)
		JsonRecursiveMarshall("kty", jkey.Type, &jkey.Thumb)
		JsonRecursiveMarshall("x", jkey.Xcoord, &jkey.Thumb)
		JsonRecursiveMarshall("y", jkey.Ycoord, &jkey.Thumb)
		fmt.Printf("\n" + jkey.Thumb + "\n")
	default:
		return errors.New("Invalid Key type, cannot initialize JWK")
	}
	return nil
}

//	Gets the received JWK and unmarshalls it, returns error if fails to unmarshall
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

func (popToken PopToken) GetPublicKey() (rsa.PublicKey, error) {
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

func (popToken PopToken) GetUnmarshalledPublicKey() JsonWebKey {
	return popToken.jsonWebKey
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

func (popToken PopToken) Alg() string {
	return popToken.alg
}

// Marshall Jwk returns the key marshalled
func (popToken PopToken) MarshallJwk() string {
	return popToken.jsonWebKey.Marshall()
}
