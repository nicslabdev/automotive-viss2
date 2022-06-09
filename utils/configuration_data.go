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
	SymmKeyDir   string            `json:"symm_key,omitempty"`
	RsaPrivKey   *rsa.PrivateKey   `json:"-"`
	RsaPubKey    rsa.PublicKey     `json:"-"`
	EcdsaPrivKey *ecdsa.PrivateKey `json:"-"`
	EcdsaPubKey  ecdsa.PublicKey   `json:"-"`
	SymmKey      string            `json:"-"`
	Expiration   int               `json:"expiration"`
}

type PopCheck struct {
	TimeExp    int      `json:"time_exp"`
	TimeMargin int      `json:"time_error_margin"`
	BannedKeys []string `json:"banned_thumbprints"`
}

type AGTGenerate struct {
	ClientContext ClientCtx `json:"client_ctx"`
	VehicleIds    []string  `json:"vehicles"`
	TimeExpST     int       `json:"time_exp"`
	TimeExpLT     int       `json:"time_exp_LT"`
	Audience      string    `json:"audience"`
}

type AGTCheck struct {
	ClientContext ClientCtx `json:"client_ctx"`
}
type ClientCtx struct {
	User        []string `json:"user"`
	Application []string `json:"application"`
	Device      []string `json:"device"`
}

type ManagementConfig struct {
	TrustKeys map[string]Key `json:"allowed_keys"`
}
