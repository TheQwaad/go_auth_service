package service

import (
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"simple_auth/auth/handlers"
	"simple_auth/auth/repositories"
	"simple_auth/utils"
	"time"
)

const (
	IpChangeEmailSubject = "Usage of your account from different IP"
	IpChangeEmailMessage = "Looks like somebody tried to use your account from different IP"
)

var JwtSecretWord = []byte("SECRET WORD IS PIZZA")
var AccessExpirationTime = time.Minute * 15
var ErrorInvalidToken = errors.New("invalid token")

type TokensPair struct {
	AccessToken  string
	RefreshToken string
}

type AccessPayload struct {
	jwt.RegisteredClaims
	UserID    string
	Address   string
	ExpireAt  time.Time
	RefreshId int64
}

type RefreshPayload struct {
	jwt.RegisteredClaims
	UserID   string
	Address  string
	ExpireAt time.Time
}

func GenerateTokens(loginRequest handlers.LoginRequest) (TokensPair, error) {
	refreshPayload := RefreshPayload{
		UserID:   loginRequest.UserID,
		Address:  loginRequest.Address,
		ExpireAt: time.Now(),
	}
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS512, &refreshPayload)
	strRefreshToken, err := refreshToken.SignedString(JwtSecretWord)

	if err != nil {
		return TokensPair{}, err
	}

	hashedRefreshToken, err := bcrypt.GenerateFromPassword([]byte(strRefreshToken), bcrypt.DefaultCost)
	if err != nil {
		return TokensPair{}, err
	}

	refreshId, err := repositories.SaveRefreshToken(loginRequest.UserID, string(hashedRefreshToken), loginRequest.Address)
	if err != nil {
		return TokensPair{}, err
	}

	accessPayload := AccessPayload{
		UserID:    loginRequest.UserID,
		Address:   loginRequest.Address,
		ExpireAt:  time.Now().Add(AccessExpirationTime),
		RefreshId: refreshId,
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS512, &accessPayload)

	strAccessToken, err := accessToken.SignedString(JwtSecretWord)

	if err != nil {
		return TokensPair{}, err
	}

	return TokensPair{AccessToken: strAccessToken, RefreshToken: strRefreshToken}, nil
}

func ParseToken(tokenString string, claims jwt.Claims) (*jwt.Token, error) {
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return JwtSecretWord, nil
	})
	if err != nil {
		return nil, err
	}
	return token, nil
}

func IsNotExpired(tm time.Time) bool {
	return tm.After(time.Now())
}

func ValidateTokens(tokensPair TokensPair) error {
	refreshPayload := &RefreshPayload{}
	accessPayload := &AccessPayload{}

	refreshToken, err := ParseToken(tokensPair.RefreshToken, refreshPayload)
	if err != nil {
		return err
	}

	byteRefreshToken, err := bcrypt.GenerateFromPassword([]byte(tokensPair.RefreshToken), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	IpAddress, err := repositories.GetUserIp(string(byteRefreshToken))
	if err != nil {
		return err
	}

	refreshId, err := repositories.RemoveRefreshToken(string(byteRefreshToken))
	if err != nil {
		return err
	}

	accessToken, err := ParseToken(tokensPair.AccessToken, accessPayload)
	if err != nil {
		return err
	}

	if !refreshToken.Valid || !IsNotExpired(refreshPayload.ExpireAt) {
		return ErrorInvalidToken
	}

	if !accessToken.Valid || !IsNotExpired(accessPayload.ExpireAt) || refreshId != accessPayload.RefreshId {
		return ErrorInvalidToken
	}

	if refreshPayload.Address != IpAddress {
		userEmail, err := repositories.GetUserEmail(string(byteRefreshToken))
		if err != nil {
			utils.SendEmail(userEmail, IpChangeEmailSubject, IpChangeEmailMessage)
		}
	}

	return nil
}
