package utils

import (
	"crypto/ecdsa"
	"crypto/rsa"
)

type Connectivity struct {
	ServingPort   string `json:"serving_port"`
	TlsManagement TlsUse `json:"tls"`
}
type TlsUse struct {
	Use     bool   `json:"use"`
	CertDir string `json:"certificate_dir"`
	KeyDir  string `json:"key_dir"`
}

type KeySet []Key
type Key struct {
	Algorithm    string            `json:"algorithm"`
	PrivKeyDir   string            `json:"private_key_dir,omitempty"`
	PubKeyDir    string            `json:"public_key_dir,omitempty"`
	SymmKeyDir   string            `json:"symm_key_dir,omitempty"`
	RsaPrivKey   *rsa.PrivateKey   `json:"-"`
	RsaPubKey    rsa.PublicKey     `json:"-"`
	EcdsaPrivKey *ecdsa.PrivateKey `json:"-"`
	EcdsaPubKey  ecdsa.PublicKey   `json:"-"`
	SymmKey      []byte            `json:"-"`
	Expiration   int               `json:"expiration"`
}

type PopCheck struct {
	TimeExp    int      `json:"time_exp"`
	TimeMargin int      `json:"time_error_margin"`
	BannedKeys []string `json:"banned_thumbprints"`
	Audience   string   `json:"audience"`
}

type AGTGenerate struct {
	ClientContext ClientCtx `json:"client_ctx"`
	VehicleIds    []string  `json:"vehicles"`
	TimeExpST     int       `json:"time_exp"`
	TimeExpLT     int       `json:"time_exp_LT"`
	Audience      string    `json:"audience"`
}

type ATGenerate struct {
	VehicleIds []string `json:"vehicles"`
}
type ClientCtx struct {
	User        []string `json:"user"`
	Application []string `json:"application"`
	Device      []string `json:"device"`
}

type ManagementConfig struct {
	TrustKeys map[string]Key `json:"allowed_keys"`
}

//*** TYPE SWITCH FOR ALL THE STRUCTS
/*
switch typ := pointer.(type){
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
*/
