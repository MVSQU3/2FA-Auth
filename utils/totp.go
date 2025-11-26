package utils

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/hex"
	"net/url"
	"time"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// func GenerateTOTPKey(email string) (*otp.Key, error) {
// 	return totp.Generate(totp.GenerateOpts{
// 		Issuer:      "Auth",
// 		AccountName: email,
// 	})
// }

// GenerateTOTPProvisioning retourne l'URI de provisioning (otpauth://) et le secret base32
// Cette fonction génère un URI de provisionnement de mot de passe à usage unique basé sur le temps (TOTP) pour une adresse e-mail donnée.
func GenerateTOTPProvisioning(email string) (string, string, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Auth",
		AccountName: email,
	})
	if err != nil {
		return "", "", err
	}
	return key.URL(), key.Secret(), nil
}

func ValidateTOTP(passcode string, secret string) bool {
	// Valider avec une tolérance de +/- 1 période (fenêtre)
	// Utilise ValidateCustom pour définir Skew=1 (valide code précédent, courant ou suivant)
	ok, err := totp.ValidateCustom(passcode, secret, time.Now(), totp.ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	// totp.ValidateCustom retourne (bool, error). On considère valide uniquement
	// si ok==true et err==nil.
	return ok && err == nil
}

func GenerateTOTPCode(secret string) (string, error) {
	return totp.GenerateCode(secret, time.Now())
}

// GenerateTOTPProvisioningFromSecret construit l'URI otpauth à partir d'un secret existant
func BuildProvisioningURI(secret string, email string) string {
	issuer := "Auth"
	// format: otpauth://totp/Issuer:email?secret=SECRET&issuer=Issuer&algorithm=SHA1&digits=6&period=30
	// s'assurer que les composants sont encodés
	account := url.QueryEscape(email)
	issuerEsc := url.QueryEscape(issuer)
	return "otpauth://totp/" + issuerEsc + ":" + account + "?secret=" + url.QueryEscape(secret) + "&issuer=" + issuerEsc + "&algorithm=SHA1&digits=6&period=30"
}

// GenerateBackupCodes génère N codes aléatoires (hex) lisibles par l'utilisateur
func GenerateBackupCodes(n int) ([]string, error) {
	codes := make([]string, 0, n)
	for i := 0; i < n; i++ {
		b := make([]byte, 6) // 6 bytes -> 12 hex chars
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		// hex string, plus make it uppercase
		codes = append(codes, hex.EncodeToString(b))
	}
	return codes, nil
}

// EncodeSecretToBase32 encodes random bytes to base32 secret for TOTP if needed
func EncodeSecretToBase32(b []byte) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
}
