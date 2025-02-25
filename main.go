package main

import (
	"context"
	"fmt"
	"log"
	"time"

	db "github.com/scott-mescudi/gAuth/database"
)

func main() {
	fmt.Println("Hello gAuth!")

	config := &db.Config{
		MaxConns: 100,
		MinConns: 1,
		MaxConnLifetime: 1 * time.Hour,
		MaxConnIdleTime: 10 * time.Minute,
	}

	conn, err := db.ConnectToDatabase("postgres", "postgres://admin:admin123@localhost:7323/gAuth", config)
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Println(conn.Ping(context.Background()))

	conn, err = db.ConnectToDatabase("sqlite", "./gAuth.sqlite", config)
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Println(conn.Ping(context.Background()))
}
