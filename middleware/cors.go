package middleware

import (
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func CORS() gin.HandlerFunc {
	// 由于我们的本地测试环境使用了ngnix处理cors 所以先绕过原本的cors设置
	if true {
		return func(c *gin.Context) {
			c.Next()
		}
	}
	config := cors.DefaultConfig()
	config.AllowOrigins = []string{"http://www.test.local"} // 替换为允许的域名列表
	// config.AllowAllOrigins = true
	config.AllowCredentials = true
	config.AllowMethods = []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}
	config.AllowHeaders = []string{"*"} // []string{"Authorization", "Content-Type"}
	return cors.New(config)
}
