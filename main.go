package main

import (
	"net/http"
	"simple_auth/auth/handlers"
)

func main() {
	http.HandleFunc("/auth/login", handlers.LoginHandler)
	http.HandleFunc("/auth/refresh", handlers.RefreshHandler)

	http.ListenAndServe(":8080", nil)
}
