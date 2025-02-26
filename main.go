package main

import (
	"context"
	"fmt"
	"log"
	"time"

	db "github.com/scott-mescudi/gauth/database"
)

func main() {
	fmt.Println("Hello gauth!")

	config := &db.Config{
		MaxConns:        100,
		MinConns:        1,
		MaxConnLifetime: 1 * time.Hour,
		MaxConnIdleTime: 10 * time.Minute,
	}

	conn, err := db.ConnectToDatabase("postgres", "postgres://admin:admin123@localhost:7323/gauth", config)
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Println(conn.Ping(context.Background()))

	conn, err = db.ConnectToDatabase("sqlite", "./gauth.sqlite", config)
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Println(conn.Ping(context.Background()))
}

//  maybe for guest/anon logins we have a seperate db to gandle these with a table of max logins and if it excedes we delete the user and maybe block ip or sum,  maybe have device fingerprinting
