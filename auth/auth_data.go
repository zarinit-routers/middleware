package auth

import (
	"fmt"
	"reflect"
	"slices"

	"github.com/charmbracelet/log"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

var (
	KeyOrganizationID = "groupId" // TODO: Change to organizationId ASAP
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
	authData.Roles = getRoles(claims)

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

func getRoles(c jwt.MapClaims) []string {
	rolesClaims, ok := c["roles"]
	if !ok {
		log.Warn("User has no roles key specified", "key", KeyRoles)
		return []string{}
	}
	rolesArr, ok := rolesClaims.([]any)
	if !ok {
		log.Warn("Roles specified not as array", "key", KeyRoles, "type", reflect.TypeOf(rolesClaims).String())
	}

	var roles []string
	for _, role := range rolesArr {
		if r, ok := role.(string); ok {
			roles = append(roles, r)
		} else {
			log.Warn("Role is not a string", "key", KeyRoles, "type", reflect.TypeOf(role).String())
		}
	}
	return roles
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
