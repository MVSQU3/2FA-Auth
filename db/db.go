package db

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	_ "github.com/lib/pq"
)

func InitDb() *sql.DB {
	connStr := os.Getenv("DATABASE_URL")
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal("Erreur ouverture DB", err)
	}

	if err := db.Ping(); err != nil {
		log.Fatal("Erreur de connexion DB", err)
	}

	fmt.Println("Connexion a la db réussite!")

	return db
}
