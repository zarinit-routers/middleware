package auth

import (
	"fmt"
	"slices"

	"github.com/charmbracelet/log"
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

func NewDataFromToken(t *jwt.Token) (*AuthData, error) {
	claims, ok := t.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("failed get jwt.MapClaims from token.Claims")
	}
	roles, ok := claims["roles"].([]string)
	if !ok {
		roles = []string{}
	}

	userId, ok := claims["userId"].(string)
	if !ok {
		return nil, fmt.Errorf("failed get userId from token claims")
	}

	orgId, ok := claims["groupId"].(string)
	if !ok {
		log.Warn("User has no organization (groupId) specified", "userId", userId)
		orgId = ""
	}

	return &AuthData{
		UserId:         userId,
		OrganizationId: orgId,
		Roles:          roles,
	}, nil
}
