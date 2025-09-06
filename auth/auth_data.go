package auth

import (
	"slices"

	"github.com/golang-jwt/jwt/v5"
)

type AuthData struct {
	UserId         string
	OrganizationId string
	Roles          []string
}

const AdminGroup = "admin"

func (a *AuthData) IsAdmin() bool {
	return slices.Contains(a.Roles, AdminGroup)
}

func NewDataFromToken(t *jwt.Token) *AuthData {
	return &AuthData{
		UserId:         t.Claims.(jwt.MapClaims)["userId"].(string),
		OrganizationId: t.Claims.(jwt.MapClaims)["groupId"].(string),
		Roles:          t.Claims.(jwt.MapClaims)["groups"].([]string),
	}
}
