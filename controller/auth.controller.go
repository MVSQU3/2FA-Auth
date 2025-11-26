package controller

import (
	"auth-sys/models"
	"auth-sys/repo"
	"auth-sys/utils"
	"fmt"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/skip2/go-qrcode"
	"golang.org/x/crypto/bcrypt"
)

type AuthController struct {
	repo *repo.AuthRepository
}

func NewAuthController(repo *repo.AuthRepository) *AuthController {
	return &AuthController{
		repo: repo,
	}
}

// Register crée un nouvel utilisateur.
//   - Attend un JSON correspondant au modèle `models.User`.{fullname: "...", email:"...", password:"..."}
//   - Hash le mot de passe reçu avant de le sauvegarder via le repository.
//   - Retourne un `models.AuthResponse` (sans le mot de passe) en cas de succès
//     ou un statut d'erreur HTTP approprié en cas d'échec.
func (ctrl *AuthController) Register(c *gin.Context) {
	// fmt.Println("=== DÉBUT REGISTER ===")

	var user models.User
	if err := c.BindJSON(&user); err != nil {
		fmt.Println("Erreur BindJSON:", err)
		c.JSON(http.StatusBadRequest, gin.H{"Error": err.Error()})
		return
	}

	fmt.Printf("1. Password reçu: %s\n", user.Password)

	// Hashage avec gestion d'erreur
	hash, _ := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)

	user.Password = string(hash)
	// fmt.Printf("2. Password hashé: %s\n", user.Password)

	createdUser, err := ctrl.repo.SignUp(&user)
	if err != nil {
		fmt.Println("Erreur SignUp:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"Error": err.Error()})
		return
	}

	// fmt.Printf("3. User créé - Password final: %s\n", createdUser.Password)
	// fmt.Println("=== FIN REGISTER ===")

	authResponse := models.AuthResponse{
		ID:       createdUser.ID,
		FullName: createdUser.FullName,
		Email:    createdUser.Email,
	}

	c.JSON(http.StatusOK, authResponse)
}

// Login authentifie un utilisateur.
//   - Attend un JSON `models.Input` contenant `email` et `password` (et
//     optionnellement `totp_code`).
//   - Vérifie le mot de passe, puis valide le TOTP si configuré (ou tente de
//     consommer un backup code en cas d'échec TOTP).
//   - Génère un JWT et renvoie `AuthResponse` ainsi que le `token` en cas de
//     succès. Les erreurs renvoient des statuts HTTP appropriés.
func (ctrl *AuthController) Login(c *gin.Context) {
	var input models.Input

	if err := c.BindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"Error": err.Error()})
		return
	}
	password := input.Password
	fmt.Printf("log de password claire %s\n", input.Password)
	credentials, err := ctrl.repo.SignIn(&input)
	// fmt.Printf("log de password claire %s\n", input.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"Error": err.Error()})
		return
	}
	fmt.Printf("log de credentials password %+v", credentials)

	err = bcrypt.CompareHashAndPassword([]byte(credentials.Password), []byte(password))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"Error": err.Error()})
		return
	}

	// Si l'utilisateur a configuré un TOTP, valider le code fourni.
	// Comportement:
	// 1) On tente d'abord de valider `totp_code` comme code TOTP normal (temps basé).
	// 2) Si la validation TOTP échoue, on tente de l'utiliser comme *backup code*.
	//    - Si un backup code correspond, il est consommé (supprimé en base) et l'authentification réussit.
	//    - Si aucun backup code ne correspond, l'authentification échoue.
	if credentials.TotpSecret != "" {
		if input.TotpCode == "" {
			c.JSON(http.StatusBadRequest, gin.H{"Error": "TOTP code required"})
			return
		}
		if !utils.ValidateTOTP(input.TotpCode, credentials.TotpSecret) {
			// tentative de consommation en tant que backup code
			ok, err := ctrl.repo.ConsumeBackupCode(credentials.ID, input.TotpCode)
			if err != nil {
				// erreur interne lors de la vérification/consommation
				c.JSON(http.StatusInternalServerError, gin.H{"Error": "Erreur interne lors de la vérification du backup code"})
				return
			}
			if !ok {
				// ni TOTP valide ni backup code valide
				c.JSON(http.StatusUnauthorized, gin.H{"Error": "Invalid TOTP code"})
				return
			}
			// Si ok==true, le backup code a été consommé et l'utilisateur est authentifié
		}
	}

	token, err := utils.GenerateTokenJWT(credentials.Email, credentials.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"Error": "Impossible de générer votre token!"})
	}

	var authResponse = models.AuthResponse{
		ID:       credentials.ID,
		FullName: credentials.FullName,
		Email:    credentials.Email,
	}

	c.JSON(http.StatusOK, gin.H{"user": authResponse, "token": token})
}

// RequestTOTPSetup génère une clé TOTP (URI de provisioning + secret) pour l'utilisateur
// Le client doit scanner l'URI (QR) puis appeler ConfirmTOTP avec le secret et un code de vérification
// {"email": "...","password": "...","code": "..."}
func (ctrl *AuthController) RequestTOTPSetup(c *gin.Context) {
	var input models.Input
	if err := c.BindJSON(&input); err != nil {
		if err == io.EOF {
			c.JSON(http.StatusBadRequest, gin.H{"Error": "Request body empty: expected JSON with 'email' and 'password'"})
			return

		}
		c.JSON(http.StatusBadRequest, gin.H{"Error": err.Error()})
		return
	}

	// conserver le mot de passe en clair avant que SignIn n'écrase input.Password
	plainPassword := input.Password
	creds, err := ctrl.repo.SignIn(&input)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"Error": "Invalid credentials"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(creds.Password), []byte(plainPassword)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"Error": "Invalid credentials"})
		return
	}

	// Générer provisioning URI + secret
	// NOTE: GenerateTOTPProvisioning crée une nouvelle clé secrète côté serveur.
	// Nous stockons ensuite cette clé en base avec SetTOTPSecret (le client ne la reçoit pas),
	// puis on retourne uniquement l'URI de provisioning (à scanner avec Google Authenticator).
	uri, secret, err := utils.GenerateTOTPProvisioning(input.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"Error": "Impossible de générer la clé TOTP"})
		return
	}

	// Stocker le secret côté serveur (ne pas le renvoyer au client)
	if err := ctrl.repo.SetTOTPSecret(creds.ID, secret); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"Error": "Impossible de sauvegarder le secret TOTP"})
		return
	}
	var png []byte
	png, err = qrcode.Encode(uri, qrcode.Medium, 200)

	// Ne PAS renvoyer l'URI de provisioning car elle contient le secret.
	// Le secret est stocké côté serveur ; pour récupérer le QR, le client
	// doit appeler l'endpoint `/api/totp/qrcode` en POST avec {"email": "..."}.

	c.Writer.Write(png)
}

// ConfirmTOTP valide un code TOTP avec le secret fourni et sauvegarde le secret si correct
// POST body: { "email": "...", "password": "...", "totp_code": "..." }
// RESPONSE o
func (ctrl *AuthController) ConfirmTOTP(c *gin.Context) {
	var req struct {
		Email    string `json:"email"`
		TotpCode string `json:"totp_code"`
	}
	if err := c.BindJSON(&req); err != nil {
		if err == io.EOF {
			c.JSON(http.StatusBadRequest, gin.H{"Error": "Request body empty: expected JSON with 'email','secret' and 'code'"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"Error": err.Error()})
		return
	}

	// Récupérer l'utilisateur (vérifier qu'il existe)
	var input models.Input
	input.Email = req.Email
	creds, err := ctrl.repo.SignIn(&input)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"Error": "Utilisateur introuvable"})
		return
	}

	// Valider le code avec le secret stocké en base
	if creds.TotpSecret == "" {
		c.JSON(http.StatusBadRequest, gin.H{"Error": "Aucun secret TOTP trouvé pour cet utilisateur"})
		return
	}

	if !utils.ValidateTOTP(req.TotpCode, creds.TotpSecret) {
		c.JSON(http.StatusUnauthorized, gin.H{"Error": "Code TOTP invalide"})
		return
	}

	// Générer des backup codes (ex: 10 codes) pour récupération d'accès
	// Ces codes sont renvoyés une seule fois au client en clair et leurs hashes
	// sont stockés en base. Chaque backup code est 'one-time' : consommé à la
	// première utilisation.
	codes, err := utils.GenerateBackupCodes(10)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"Error": "Impossible de générer les backup codes"})
		return
	}
	// Hasher les codes avant stockage pour ne pas garder les codes en clair en DB
	hashed := make([]string, 0, len(codes))
	for _, pc := range codes {
		h, _ := bcrypt.GenerateFromPassword([]byte(pc), bcrypt.DefaultCost)
		hashed = append(hashed, string(h))
	}
	if err := ctrl.repo.SetBackupCodes(creds.ID, hashed); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"Error": "Impossible de sauvegarder les backup codes"})
		return
	}

	// Retourner au client les backup codes en clair (affichez/stockez-les en lieu sûr)
	c.JSON(http.StatusOK, gin.H{"message": "TOTP activé avec succès", "backup_codes": codes})
}

// RegenerateBackupCodes regénère de nouveaux backup codes après vérification password + TOTP
// POST body: { "email": "...", "password": "...", "totp_code": "..." }
func (ctrl *AuthController) RegenerateBackupCodes(c *gin.Context) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		TotpCode string `json:"totp_code"`
	}
	if err := c.BindJSON(&req); err != nil {
		if err == io.EOF {
			c.JSON(http.StatusBadRequest, gin.H{"Error": "Request body empty: expected JSON with 'email','password','totp_code'"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"Error": err.Error()})
		return
	}

	var input models.Input
	input.Email = req.Email
	creds, err := ctrl.repo.SignIn(&input)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"Error": "Invalid credentials"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(creds.Password), []byte(req.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"Error": "Invalid credentials"})
		return
	}

	// Vérifier le code TOTP avant de régénérer des backup codes
	if !utils.ValidateTOTP(req.TotpCode, creds.TotpSecret) {
		c.JSON(http.StatusUnauthorized, gin.H{"Error": "Invalid TOTP code"})
		return
	}

	// Générer et stocker de nouveaux backup codes (hashés en base)
	codes, err := utils.GenerateBackupCodes(10)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"Error": "Impossible de générer les backup codes"})
		return
	}
	hashed := make([]string, 0, len(codes))
	for _, pc := range codes {
		h, _ := bcrypt.GenerateFromPassword([]byte(pc), bcrypt.DefaultCost)
		hashed = append(hashed, string(h))
	}
	if err := ctrl.repo.SetBackupCodes(creds.ID, hashed); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"Error": "Impossible de sauvegarder les backup codes"})
		return
	}

	// Retourner les nouveaux backup codes en clair (à stocker par l'utilisateur)
	c.JSON(http.StatusOK, gin.H{"message": "Backup codes régénérés", "backup_codes": codes})
}

// DisableTOTP désactive le TOTP pour l'utilisateur après vérification password + TOTP
// POST body: { "email":"...","password":"...","totp_code":"..." }
func (ctrl *AuthController) DisableTOTP(c *gin.Context) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		TotpCode string `json:"totp_code"`
	}
	if err := c.BindJSON(&req); err != nil {
		if err == io.EOF {
			c.JSON(http.StatusBadRequest, gin.H{"Error": "Request body empty: expected JSON with 'email','password','totp_code'"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"Error": err.Error()})
		return
	}

	var input models.Input
	input.Email = req.Email
	creds, err := ctrl.repo.SignIn(&input)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"Error": "Invalid credentials"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(creds.Password), []byte(req.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"Error": "Invalid credentials"})
		return
	}

	// Vérifier le code TOTP avant d'autoriser la désactivation
	if !utils.ValidateTOTP(req.TotpCode, creds.TotpSecret) {
		c.JSON(http.StatusUnauthorized, gin.H{"Error": "Invalid TOTP code"})
		return
	}

	// Suppression du secret et des backup codes en base
	if err := ctrl.repo.ClearTOTP(creds.ID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"Error": "Impossible de désactiver le TOTP"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "TOTP désactivé avec succès"})
}
