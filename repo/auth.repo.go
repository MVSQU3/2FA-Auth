package repo

import (
	"auth-sys/models"
	"database/sql"
	"encoding/json"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

type AuthRepository struct {
	db *sql.DB
}

func NewAuthRepository(db *sql.DB) *AuthRepository {
	return &AuthRepository{
		db: db,
	}
}

func (r *AuthRepository) SignUp(user *models.User) (*models.User, error) {
	SelectQuery := `
		SELECT email
		FROM users
		WHERE email = $1
	`

	var existingEmail string
	SelectErr := r.db.QueryRow(SelectQuery, user.Email).Scan(&existingEmail)

	// Vérifier si l'email existe déjà
	if SelectErr == nil {
		// Email trouvé = existe déjà
		return nil, fmt.Errorf("ce compte existe déjà")
	}

	if SelectErr != sql.ErrNoRows {
		// Autre erreur (connexion, etc.)
		return nil, fmt.Errorf("erreur lors de la vérification : %w", SelectErr)
	}

	// Email n'existe pas, on continue l'insertion
	InsertQuery := `
		INSERT INTO users (fullname, email, password)
		VALUES ($1, $2, $3)
		RETURNING id
	`

	InsertErr := r.db.QueryRow(InsertQuery, user.FullName, user.Email, user.Password).Scan(&user.ID)
	if InsertErr != nil {
		return nil, fmt.Errorf("erreur lors de l'insertion : %w", InsertErr)
	}

	return user, nil
}

func (r *AuthRepository) SignIn(input *models.Input) (*models.Input, error) {
	// SignIn récupère les informations de l'utilisateur par email.
	// Le champ `totp_secret` peut être NULL en base ; nous le scannons
	// dans un sql.NullString pour éviter une erreur de conversion NULL->string.
	var user models.User
	var totpNull sql.NullString
	query := "SELECT id, fullname, email, password, totp_secret FROM users WHERE email = $1"
	err := r.db.QueryRow(query, input.Email).Scan(&user.ID, &user.FullName, &user.Email, &user.Password, &totpNull)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("Utilisateur introuvable")
	}
	if err != nil {
		return nil, err
	}

	// Copier les champs pertinents dans l'Input pour compatibilité avec le controller
	input.ID = user.ID
	input.FullName = user.FullName
	input.Email = user.Email
	input.Password = user.Password
	if totpNull.Valid {
		input.TotpSecret = totpNull.String
	} else {
		input.TotpSecret = ""
	}

	return input, nil
}

func (r *AuthRepository) SetTOTPSecret(userID int, secret string) error {
	// Stocke en clair le secret TOTP pour l'utilisateur. Pour la production,
	// il est recommandé de chiffrer ce secret avant stockage.
	query := "UPDATE users SET totp_secret = $1 WHERE id = $2"
	_, err := r.db.Exec(query, secret, userID)
	if err != nil {
		return fmt.Errorf("erreur lors de l'enregistrement du TOTP: %w", err)
	}
	return nil
}

// SetBackupCodes stocke les codes hashés (JSON) dans la colonne backup_codes de la table users
func (r *AuthRepository) SetBackupCodes(userID int, hashedCodes []string) error {
	data, err := json.Marshal(hashedCodes)
	if err != nil {
		return err
	}
	query := "UPDATE users SET backup_codes = $1 WHERE id = $2"
	_, err = r.db.Exec(query, string(data), userID)
	if err != nil {
		return fmt.Errorf("erreur lors de l'enregistrement des backup codes: %w", err)
	}
	return nil
}

// GetBackupCodes récupère la liste hashée de backup codes (JSON) depuis la colonne backup_codes
func (r *AuthRepository) GetBackupCodes(userID int) ([]string, error) {
	var raw sql.NullString
	query := "SELECT backup_codes FROM users WHERE id = $1"
	err := r.db.QueryRow(query, userID).Scan(&raw)
	if err != nil {
		return nil, err
	}
	if !raw.Valid || raw.String == "" {
		return []string{}, nil
	}
	var codes []string
	if err := json.Unmarshal([]byte(raw.String), &codes); err != nil {
		return nil, err
	}
	return codes, nil
}

// ConsumeBackupCode vérifie un code en clair contre les hashés en base; si valide, le supprime (consommé)
func (r *AuthRepository) ConsumeBackupCode(userID int, code string) (bool, error) {
	codes, err := r.GetBackupCodes(userID)
	if err != nil {
		return false, err
	}
	for i, hashed := range codes {
		// Compare le code fourni en clair au hash stocké en DB
		if bcrypt.CompareHashAndPassword([]byte(hashed), []byte(code)) == nil {
			// supprimer le code consommé (one-time)
			codes = append(codes[:i], codes[i+1:]...)
			if err := r.SetBackupCodes(userID, codes); err != nil {
				return false, err
			}
			return true, nil
		}
	}
	return false, nil
}

// ClearTOTP supprime le secret TOTP et les backup codes pour l'utilisateur
func (r *AuthRepository) ClearTOTP(userID int) error {
	// Supprime le secret TOTP et les backup codes (utilisé pour désactiver TOTP)
	query := "UPDATE users SET totp_secret = NULL, backup_codes = NULL WHERE id = $1"
	_, err := r.db.Exec(query, userID)
	if err != nil {
		return fmt.Errorf("erreur lors de la suppression du TOTP: %w", err)
	}
	return nil
}
