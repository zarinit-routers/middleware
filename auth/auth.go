package auth

import (
	"fmt"
	"net/http"
	"os"

	"github.com/charmbracelet/log"
	"github.com/gin-gonic/gin"

	jwt "github.com/golang-jwt/jwt/v5"
)

const AUTH_DATA_KEY = "middleware-auth-data"

const ENV_JWT_KEY = "JWT_SECURITY_KEY"

func getJwtKey() jwt.Keyfunc {

	return func(t *jwt.Token) (any, error) {
		key := os.Getenv(ENV_JWT_KEY)
		if key == "" {
			return nil, fmt.Errorf("environment variable %q not specified", ENV_JWT_KEY)
		}
		return []byte(key), nil
	}
}

var (
	ErrNoAuthData        = fmt.Errorf("no auth data in current request context")
	ErrCorruptedAuthData = fmt.Errorf("corrupted auth data in current request context")
)

// TODO: fix nested if statements
func GetUser(c *gin.Context, user *AuthData) (*AuthData, error) {
	if data, exists := c.Get(AUTH_DATA_KEY); !exists {
		return nil, ErrNoAuthData
	} else {
		authData, ok := data.(*AuthData)
		if !ok {
			return nil, ErrCorruptedAuthData
		} else {
			return authData, nil
		}
	}
}

func Middleware(validators ...AuthValidateFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.Request.Header.Get("Authorization")
		if tokenString == "" {
			log.Error("Authentication failed with no token specified in Authorization header")
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		token, err := jwt.Parse(tokenString, getJwtKey())
		if err != nil {
			log.Error("Authentication failed", "error", err)
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		data, err := NewDataFromToken(token)
		if err != nil {
			log.Error("Failed get authentication data from token", "error", err)
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		for _, v := range validators {
			if err := v(*data); err != nil {
				log.Error("Auth data validation failed, request aborted", "error", err)
				c.AbortWithStatus(http.StatusUnauthorized)
				return
			}
		}

		c.Set(AUTH_DATA_KEY, data)

		c.Next()
	}
}

type AuthValidateFunc func(AuthData) error

func AdminOnly() AuthValidateFunc {
	return func(ad AuthData) error {
		if !ad.IsAdmin() {
			return fmt.Errorf("current user is not an administrator")
		}
		return nil
	}
}
