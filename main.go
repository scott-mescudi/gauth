package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"runtime/pprof"
	"time"

	_ "net/http/pprof" // Import pprof for profiling endpoints

	ph "github.com/scott-mescudi/gauth/api/plain_auth"
	coreplainauth "github.com/scott-mescudi/gauth/core/plain_auth"
	"github.com/scott-mescudi/gauth/database"
)

func main() {
	// Start pprof profiling server
	go func() {
		log.Println("Starting pprof server on localhost:6060")
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()

	// CPU profiling setup
	cpuFile, err := os.Create("cpu_profile.prof")
	if err != nil {
		log.Fatal("Error creating CPU profile file:", err)
	}
	defer cpuFile.Close()

	if err := pprof.StartCPUProfile(cpuFile); err != nil {
		log.Fatal("Error starting CPU profiling:", err)
	}
	defer pprof.StopCPUProfile() // Ensure profiling stops when function exits

	// Database connection
	con, err := database.ConnectToDatabase("postgres", "postgresql://admin:admin123@localhost:7323/gauth")
	if err != nil {
		log.Fatal("Database connection failed:", err)
	}

	pa := &coreplainauth.Coreplainauth{
		DB:                     con,
		AccessTokenExpiration:  1 * time.Hour,
		RefreshTokenExpiration: 1 * time.Hour,
	}

	a := &ph.PlainAuthAPI{
		AuthCore: pa,
	}

	// Simulate some load before starting the HTTP server
	pa.SignupHandler("jack", "jack@jack.com", "hey", "user")

	
	time.Sleep(20 * time.Second)

	// HTTP server setup
	mux := http.NewServeMux()
	mux.HandleFunc("/login", a.Login)

	server := &http.Server{
		Addr:    ":8000",
		Handler: mux,
	}

	log.Println("Starting API server on port 8000...")
	go func() {
		if err := server.ListenAndServe(); err != nil {
			log.Fatal("Server failed:", err)
		}
	}()

	// Allow the server to run for some time for profiling to be meaningful
	time.Sleep(30 * time.Second)

	// Memory profiling
	memFile, err := os.Create("mem_profile.prof")
	if err != nil {
		log.Fatal("Error creating memory profile file:", err)
	}
	defer memFile.Close()

	if err := pprof.WriteHeapProfile(memFile); err != nil {
		log.Fatal("Error writing memory profile:", err)
	}

	fmt.Println("Profiles saved: cpu_profile.prof, mem_profile.prof")
}


