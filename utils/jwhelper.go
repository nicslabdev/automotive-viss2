/************
*	File implementing some methods and variables that makes using JsonWebToken easier and more intuitive
*
*	Author: Jose Jesus Sanchez Gomez (sanchezg@lcc.uma.es)
*	2021, NICS Lab (University of Malaga)
*
*************/

package utils

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"reflect"
	"strings"
)

// Gets Json string (or nothing) and adds received key and value, if it doesnt receive a value or key, it does nothing
func JsonRecursiveMarshall(key string, value string, jplain *string) {
	if key == "" || value == "" {
		return
	}
	if !strings.HasPrefix(value, "{") { // If the value of the claim starts with "{", that means the claim has another json inside, wich must not be included between commas
		value = `"` + value + `"`
	}
	if *jplain == "" {
		*jplain = `{"` + key + `":` + value + `}`
	} else {
		*jplain = (*jplain)[:len(*jplain)-1] + `,"` + key + `":` + value + `}`
	}
}

type JsonWebToken struct {
	Header           string
	Payload          string
	EncodedHeader    string
	EncodedPayload   string
	EncodedSignature string
	EncodedToken     string
}

func (token *JsonWebToken) SetHeader(algorithm string) {
	token.Header = `{"alg":"` + algorithm + `","typ":"JWT"}`
}

func (token *JsonWebToken) AddClaim(key string, value string) {
	JsonRecursiveMarshall(key, value, &token.Payload)
}

func (token *JsonWebToken) Encode() {
	token.EncodedHeader = base64.RawURLEncoding.EncodeToString([]byte(token.Header))
	token.EncodedPayload = base64.RawURLEncoding.EncodeToString([]byte(token.Payload))
}

// Signs the token. In case of HS signature, string key must be given. In case of RSA signature, string must be PEM format text or *rsa/ecdsa.privateKey
func (token *JsonWebToken) Sign(key interface{}) error {
	token.Encode()
	token.EncodedToken = token.EncodedHeader + "." + token.EncodedPayload
	if strings.Contains(token.Header, `HS256`) {
		strKey, ok := key.(string)
		if ok {
			token.EncodedSignature = base64.RawURLEncoding.EncodeToString([]byte(GenerateHmac(token.EncodedToken, strKey)))
		} else {
			return errors.New(fmt.Sprintf("JsonWebToken.Sign error. Key type given is not correct for HS: %T", reflect.TypeOf(key)))
		}
	} else if strings.Contains(token.Header, `RS256`) { //RSASSA-PKCS1-v1_5 + SHA-256
		var privKey *rsa.PrivateKey
		switch typ := key.(type) {
		case *rsa.PrivateKey:
			privKey, _ = key.(*rsa.PrivateKey)
		case string:
			// Obtains private key in format rsa.PrivateKey from string in PEM format. Includes error managing
			strKey, _ := key.(string)
			err := PemDecodeRSA(strKey, privKey)
			if err != nil {
				return err
			}
		default:
			return errors.New(fmt.Sprintf("File jwhelper.go: JsonWebToken.Sign: Error. Key type given is not correct: %T", typ))
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
	} else if strings.Contains(token.Header, `ES256`) { //ECDSA: P-256 + SHA-256
		var privKey *ecdsa.PrivateKey
		switch typ := key.(type) {
		case *ecdsa.PrivateKey:
			privKey, _ = key.(*ecdsa.PrivateKey)
		case string:
			strKey, _ := key.(string)
			err := PemDecodeECDSA(strKey, privKey)
			if err != nil {
				return err
			}
		default:
			return errors.New(fmt.Sprintf("File jwthelper.go: JsonWebToken.Sign: Error. Key type given is not correct: %T", typ))
		}
		msgHasher := md5.New()
		msgHasher.Write([]byte(token.EncodedToken))
		msgHash := msgHasher.Sum(nil)
		// Must be one of those or both
		sign, err := ecdsa.SignASN1(rand.Reader, privKey, msgHash)
		if err != nil {
			return err
		}
		token.EncodedSignature = base64.RawURLEncoding.EncodeToString(sign)
		//Signature acording to RFC7518: https://datatracker.ietf.org/doc/html/rfc7518#section-3.4
		// rCoordx, sProof, err := ecdsa.Sign(rand.Reader, privKey, msgHash)
		// if err != nil {
		// 	return err
		// }
		// rBytes := rCoordx.Bytes() // Returns big endian octet seq
		// sBytes := sProof.Bytes()
		// buf := bytes.NewBuffer(rBytes)
		// buf.Write(sBytes)
		// var sign []byte
		// buf.Read(sign)
		// token.EncodedSignature = base64.RawURLEncoding.EncodeToString(sign)

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

// From a signed jwt received, gets header and payload
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

// Checks if the token is signed correctly. In case of HS, key as string must be given. In case of RSA, rsa.PubKey or PEM string can be given
func (token JsonWebToken) CheckSignature(key interface{}) error {
	var err error
	if strings.Contains(token.Header, `HS256`) {
		strKey, ok := key.(string)
		if ok && base64.RawURLEncoding.EncodeToString([]byte(GenerateHmac(token.EncodedHeader+"."+token.EncodedPayload, strKey))) == token.EncodedSignature {
			return nil
		} else {
			return errors.New("Invalid HS256 Signature")
		}
	} else if strings.Contains(token.Header, `RS256`) { //RSASSA-PKCS1-v1_5 + SHA-256
		strKey, isStr := key.(string)
		var pubKey *rsa.PublicKey
		if isStr {
			// Obtains public key block from string
			pubBlock, _ := pem.Decode([]byte(strKey))
			if pubBlock == nil {
				return errors.New("Private key not found or is not in pem format")
			}
			if pubBlock.Type != "PUBLIC KEY" {
				return errors.New("Invalid public key, wrong type")
			}
			// Parses PKCS1 and PKIX public keys
			pubKey, err = x509.ParsePKCS1PublicKey(pubBlock.Bytes)
			if err != nil {
				parsedKeyGen, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
				if err != nil {
					return errors.New("Unable to parse PublicKey")
				}
				pubKey = parsedKeyGen.(*rsa.PublicKey)
			}
		} else {
			pubKey = key.(*rsa.PublicKey)
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
