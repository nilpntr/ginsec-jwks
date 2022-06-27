package ginsec

import (
	"errors"
	"github.com/MicahParks/keyfunc"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"net/http"
	"strings"
	"time"
)

// Errors
var (
	ErrIdentityHandlerEmpty = errors.New("idenity handler cannot be empty")
	ErrIdentityKeyEmpty     = errors.New("identity key cannot be empty")
	ErrEmptyAuthHeader      = errors.New("authentication header cannot be empty")
	ErrEmptyCookieToken     = errors.New("cookie cannot be empty")
	ErrInvalidAuthHeader    = errors.New("invalid authentication header")
	ErrMissingExpField      = errors.New("missing exp field")
	ErrWrongFormatOfExp     = errors.New("wrong exp field format")
	ErrExpiredToken         = errors.New("token expired")
	ErrClaimsIncorrect      = errors.New("you're claims are incorrect")
)

// Some constants used across GinSec.
const (
	SigningAlgorithm = "HS256"
	TokenHeadName    = "Bearer"
)

// MapClaims Default user claims
type MapClaims map[string]interface{}

// GinJWTMiddleware The Gin-JWT-Go middleware
type GinJWTMiddleware struct {
	// IdentityKey set the identity key. Required.
	IdentityKey string

	// IdentityHandler set the identity handler function. Required.
	IdentityHandler func(*gin.Context) interface{}

	// Callback function that should perform the authorization of the authenticated user. Called
	// only after an authentication success. Must return true on success, false on failure.
	// Optional, default to success.
	Authorizator func(data interface{}, c *gin.Context) bool

	// Unauthorized allow users to define a response. Optional.
	Unauthorized func(*gin.Context, int, string)

	// CookieName
	CookieName string

	// TokenLookup is a string in the form of "<source>:<name>" that is used
	// to extract token from the request.
	// Optional. Default value "header:Authorization".
	// Possible values:
	// - "header:<name>"
	// - "cookie:<name>"
	TokenLookup string

	// ClaimsKey allows users to define a context key where gin saves the payload in
	ClaimsKey string

	// jwks
	jwks *keyfunc.JWKS
}

func New(mw *GinJWTMiddleware, jwks *keyfunc.JWKS) (*GinJWTMiddleware, error) {
	if err := mw.MiddlewareInit(jwks); err != nil {
		return nil, err
	}
	return mw, nil
}

func (mw *GinJWTMiddleware) MiddlewareInit(jwks *keyfunc.JWKS) error {
	mw.jwks = jwks

	if mw.TokenLookup == "" {
		mw.TokenLookup = "header:Authorization"
	}

	if mw.ClaimsKey == "" {
		mw.ClaimsKey = "JWKS_PAYLOAD"
	}

	if mw.IdentityKey == "" {
		return ErrIdentityKeyEmpty
	}

	if mw.Authorizator == nil {
		mw.Authorizator = func(data interface{}, c *gin.Context) bool {
			return true
		}
	}

	if mw.CookieName == "" {
		mw.CookieName = "jwt"
	}

	if mw.IdentityHandler == nil {
		return ErrIdentityHandlerEmpty
	}

	return nil
}

func (mw *GinJWTMiddleware) MiddlewareFunc() gin.HandlerFunc {
	return func(c *gin.Context) {
		mw.middlewareImpl(c)
	}
}

func (mw *GinJWTMiddleware) middlewareImpl(c *gin.Context) {
	claims, err := mw.GetClaimsFromJWT(c)
	if err != nil {
		mw.unauthorized(c, http.StatusUnauthorized, err.Error())
		return
	}

	if claims["exp"] == nil {
		mw.unauthorized(c, http.StatusBadRequest, ErrMissingExpField.Error())
		return
	}

	if _, ok := claims["exp"].(float64); !ok {
		mw.unauthorized(c, http.StatusBadRequest, ErrWrongFormatOfExp.Error())
		return
	}

	if int64(claims["exp"].(float64)) < time.Now().Unix() {
		mw.unauthorized(c, http.StatusUnauthorized, ErrExpiredToken.Error())
		return
	}

	c.Set(mw.ClaimsKey, claims)
	identity := mw.IdentityHandler(c)

	if identity != nil {
		c.Set(mw.IdentityKey, identity)
	}

	if !mw.Authorizator(identity, c) {
		mw.unauthorized(c, http.StatusUnauthorized, ErrClaimsIncorrect.Error())
		return
	}

	c.Next()
}

func (mw *GinJWTMiddleware) GetClaimsFromJWT(c *gin.Context) (MapClaims, error) {
	token, err := mw.ParseToken(c)

	if err != nil {
		return nil, err
	}

	claims := MapClaims{}
	for key, value := range token.Claims.(jwt.MapClaims) {
		claims[key] = value
	}

	return claims, nil
}

func (mw *GinJWTMiddleware) ParseToken(c *gin.Context) (*jwt.Token, error) {
	var token string
	var err error

	methods := strings.Split(mw.TokenLookup, ",")
	for _, method := range methods {
		if len(token) > 0 {
			break
		}
		parts := strings.Split(strings.TrimSpace(method), ":")
		k := strings.TrimSpace(parts[0])
		v := strings.TrimSpace(parts[1])
		switch k {
		case "header":
			token, err = mw.jwtFromHeader(c, v)
		case "cookie":
			token, err = mw.jwtFromCookie(c, v)
		}
	}

	if err != nil {
		return nil, err
	}

	return jwt.Parse(token, mw.jwks.Keyfunc)
}

func (mw *GinJWTMiddleware) jwtFromHeader(c *gin.Context, key string) (string, error) {
	authHeader := c.Request.Header.Get(key)

	if authHeader == "" {
		return "", ErrEmptyAuthHeader
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if !(len(parts) == 2 && parts[0] == TokenHeadName) {
		return "", ErrInvalidAuthHeader
	}

	return parts[1], nil
}

func (mw *GinJWTMiddleware) jwtFromCookie(c *gin.Context, key string) (string, error) {
	cookie, _ := c.Cookie(key)

	if cookie == "" {
		return "", ErrEmptyCookieToken
	}

	return cookie, nil
}

func (mw *GinJWTMiddleware) unauthorized(c *gin.Context, code int, message string) {
	mw.Unauthorized(c, code, message)
}

func ExtractClaimsFromToken(token *jwt.Token) MapClaims {
	if token == nil {
		return make(MapClaims)
	}

	claims := MapClaims{}
	for key, value := range token.Claims.(jwt.MapClaims) {
		claims[key] = value
	}

	return claims
}

func ExtractClaims(c *gin.Context, claimsKey string) MapClaims {
	claims, exists := c.Get(claimsKey)
	if !exists {
		return make(MapClaims)
	}

	return claims.(MapClaims)
}

func (mw *GinJWTMiddleware) ParseTokenString(token string) (*jwt.Token, error) {
	return jwt.Parse(token, mw.jwks.Keyfunc)
}
