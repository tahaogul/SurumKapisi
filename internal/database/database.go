package database

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	_ "github.com/lib/pq"
)

// Config holds database configuration
type Config struct {
	Host     string
	Port     string
	Name     string
	User     string
	Password string
	SSLMode  string
}

// Connect establishes a database connection with retries
func Connect(cfg Config) (*sql.DB, error) {
	dsn := fmt.Sprintf(
		"host=%s port=%s dbname=%s user=%s password=%s sslmode=%s",
		cfg.Host, cfg.Port, cfg.Name, cfg.User, cfg.Password, cfg.SSLMode,
	)

	var db *sql.DB
	var err error

	// Retry connection up to 30 times (useful in Docker Compose startup)
	for i := 0; i < 30; i++ {
		db, err = sql.Open("postgres", dsn)
		if err != nil {
			log.Printf("DB connection attempt %d failed: %v", i+1, err)
			time.Sleep(2 * time.Second)
			continue
		}

		err = db.Ping()
		if err == nil {
			log.Println("Database connection established")
			db.SetMaxOpenConns(25)
			db.SetMaxIdleConns(5)
			db.SetConnMaxLifetime(5 * time.Minute)
			return db, nil
		}

		log.Printf("DB ping attempt %d failed: %v", i+1, err)
		time.Sleep(2 * time.Second)
	}

	return nil, fmt.Errorf("could not connect to database after 30 attempts: %w", err)
}
