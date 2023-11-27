package main

import (
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"net/http"
	"strings"
	"time"
	"x-system/model"
)

var jwtSecret = []byte("secret-key")

func Login(c *gin.Context) {
	var u model.User
	err := c.ShouldBind(&u)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"code": 500, "msg": err.Error()})
		return
	}
	if u.Password != "123456" || u.Username != "admin" {
		c.JSON(http.StatusOK, gin.H{"code": 500, "msg": "用户名或密码错误"})
		return
	}

	token, err := GenerateToken(u.Username, u.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 500, "msg": "Token异常"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code":  200,
		"msg":   "success",
		"token": token,
	})
	return
}

type CustomClaims struct {
	Username string `json:"username"`
	Password string `json:"password"`
	jwt.RegisteredClaims
}

// GenerateToken 生成 JWT token
func GenerateToken(username, password string) (string, error) {
	expireTime := time.Now().Add(time.Minute * 15)

	claims := CustomClaims{
		username,
		password,
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expireTime), // 定义过期时间
			Issuer:    "somebody",                     // 签发人
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

func ParseToken(token string) (*CustomClaims, error) {
	// 解析token
	var mc = new(CustomClaims)
	tokenClaims, err := jwt.ParseWithClaims(token, mc, func(token *jwt.Token) (i interface{}, err error) {
		return jwtSecret, nil
	})
	if err != nil {
		return nil, err
	}
	// 对token对象中的Claim进行类型断言
	if tokenClaims.Valid { // 校验token
		return mc, nil
	}
	return nil, errors.New("invalid token")
}

func JWTMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		var code int
		var data interface{}

		code = e.SUCCESS
		token := c.Query("token")
		if token == "" {
			code = e.INVALID_PARAMS
		} else {
			// 解析token
			claims, err := ParseToken(token)
			if err != nil {
				code = e.ERROR_AUTH_CHECK_TOKEN_FAIL
			} else if time.Now().Unix() > claims.ExpiresAt.Unix() {
				code = e.ERROR_AUTH_CHECK_TOKEN_TIMEOUT
			}
		}

		if code != e.SUCCESS {
			c.JSON(http.StatusUnauthorized, gin.H{
				"code": code,
				"msg":  e.GetMsg(code),
				"data": data,
			})
			c.Abort()
			return
		}
		c.Next()
	}
}

func JWTAuthMiddleware() func(c *gin.Context) {
	return func(c *gin.Context) {
		//获取到请求头中的token
		authHeader := c.Request.Header.Get("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusOK, &model.ResponseData{
				Code: 200,
				Msg:  "访问失败,请登录!",
				Data: nil,
			})
			c.Abort()
			return
		}
		// 按空格分割
		parts := strings.SplitN(authHeader, " ", 2)
		if !(len(parts) == 2 && parts[0] == "Bearer") {
			c.JSON(http.StatusOK, &model.ResponseData{
				Code: 200,
				Msg:  "访问失败,无效的token,请登录!",
				Data: nil,
			})
			c.Abort()
			return
		}
		// parts[1]是获取到的tokenString，我们使用之前定义好的解析JWT的函数来解析它
		mc, err := util.ParseToken(parts[1])
		if err != nil {
			c.JSON(http.StatusOK, &model.ResponseData{
				Code: 200,
				Msg:  "访问失败,无效的token,请登录!",
				Data: nil,
			})
			c.Abort()
			return
		}
		// 将当前请求的userID信息保存到请求的上下文c上
		c.Set("userID", mc.UserID)
		c.Next() // 后续的处理函数可以用过c.Get("username")来获取当前请求的用户信息
	}
}
