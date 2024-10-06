package handlers

import (
	"encoding/json"
	_ "github.com/lib/pq"
	"net/http"
	"simple_auth/auth/service"
)

type LoginRequest struct {
	UserID  string
	Address string
}

type RefreshRequest struct {
	UserID       string
	Address      string
	RefreshToken string
	AccessToken  string
}

func LoginHandler(writer http.ResponseWriter, request *http.Request) {
	var loginRequest LoginRequest
	err := json.NewDecoder(request.Body).Decode(&loginRequest)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}

	tokensPair, err := service.GenerateTokens(loginRequest)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}

	err = json.NewEncoder(writer).Encode(tokensPair)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
	}
}

func RefreshHandler(writer http.ResponseWriter, request *http.Request) {
	var refreshRequest RefreshRequest
	err := json.NewDecoder(request.Body).Decode(&refreshRequest)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}

	tokensPair := service.TokensPair{AccessToken: refreshRequest.AccessToken, RefreshToken: refreshRequest.RefreshToken}
	err = service.ValidateTokens(tokensPair)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}

	tokensPair, err = service.GenerateTokens(LoginRequest{refreshRequest.UserID, refreshRequest.Address})
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
	}
	err = json.NewEncoder(writer).Encode(tokensPair)

}
