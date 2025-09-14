package auth

import (
	"fmt"
	"slices"

	"github.com/charmbracelet/log"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

var (
	KeyOrganizationID = "groupId" // Change to organizationId ASAP
	KeyUserID         = "userId"
	KeyRoles          = "roles"
)

type AuthData struct {
	UserID         uuid.UUID
	OrganizationID uuid.UUID
	Roles          []string
}

const AdminRole = "admin"

func (a *AuthData) IsAdmin() bool {
	return slices.Contains(a.Roles, AdminRole)
}

func NewDataFromToken(t *jwt.Token) (*AuthData, error) {
	claims, ok := t.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("failed get jwt.MapClaims from token.Claims")
	}

	authData := &AuthData{}
	roles, ok := claims[KeyRoles].([]string)
	if !ok {
		log.Warn("User has no roles key specified", "key", KeyRoles)
	}
	authData.Roles = roles

	userId, err := getUUID(claims, KeyUserID)
	if err != nil {
		return nil, fmt.Errorf("failed get UserID from token claims: %s", err)
	} else {
		authData.UserID = userId
	}

	orgId, err := getUUID(claims, KeyOrganizationID)
	if err != nil {
		log.Warn("User has no organization key specified", "key", KeyOrganizationID, "userId", userId)
		authData.OrganizationID = uuid.Nil
	} else {
		authData.OrganizationID = orgId
	}

	return authData, nil
}

func getUUID(claims jwt.MapClaims, key string) (uuid.UUID, error) {
	value, ok := claims[key]
	if !ok {
		return uuid.Nil, fmt.Errorf("claim %s not found", key)
	}
	str, ok := value.(string)
	if !ok {
		return uuid.Nil, fmt.Errorf("claim %s is not a string", key)
	}
	id, err := uuid.Parse(str)
	if err != nil {
		return uuid.Nil, fmt.Errorf("claim %s is not a valid UUID", key)
	}
	return id, nil
}
