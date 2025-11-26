package models

type User struct {
	ID       int    `json:"id" db:"id"`
	FullName string `json:"fullname" db:"fullname"`
	// Phone      string `json:"phone" db:"phone"`
	Email    string `json:"email" db:"email"`
	Password string `json:"password" db:"password"`
	// TotpSecret: secret TOTP (base32) stocké en base. Peut être NULL si TOTP non configuré.
	// Pour la production, envisagez de chiffrer ce champ avant stockage.
	TotpSecret string `json:"-" db:"totp_secret"`
}

type Input struct {
	ID         int    `json:"id" db:"id"`
	FullName   string `json:"fullname" db:"fullname"`
	Email      string `json:"email" db:"email"`
	Password   string `json:"password" db:"password"`
	TotpCode   string `json:"totp_code" db:"-"`
	TotpSecret string `json:"-" db:"totp_secret"`
}

type AuthResponse struct {
	ID       int    `json:"id"`
	FullName string `json:"fullname"`
	Email    string `json:"email"`
}
