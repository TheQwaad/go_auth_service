package repositories

import "database/sql"

var db *sql.DB

func SaveRefreshToken(userID, refreshToken, ipAddress string) (int64, error) {
	query := `INSERT INTO refresh_tokens (user_id, token_hash, ip_address) VALUES ($1, $2, $3, $4) RETURNING token_id`
	var tokenID int64
	err := db.QueryRow(query, userID, refreshToken, ipAddress).Scan(&tokenID)
	if err != nil {
		return 0, err
	}

	return tokenID, nil
}
func RemoveRefreshToken(refreshToken string) (int64, error) {
	query := `DELETE FROM refresh_tokens WHERE token_hash = $1 RETURNING token_id`
	var tokenID int64
	err := db.QueryRow(query, refreshToken).Scan(&tokenID)
	if err != nil {
		return 0, err
	}

	return tokenID, nil
}

func GetUserIp(refreshToken string) (string, error) {
	query := `SELECT ip_address FROM refresh_tokens WHERE token_hash = $1`
	var ipAddress string
	err := db.QueryRow(query, refreshToken).Scan(&ipAddress)
	if err != nil {
		return "", err
	}

	return ipAddress, nil
}

func GetUserEmail(userId string) (string, error) {
	query := `SELECT email FROM users WHERE user_id = $1`
	var email string
	err := db.QueryRow(query, userId).Scan(&email)
	if err != nil {
		return "", err
	}

	return email, nil
}
