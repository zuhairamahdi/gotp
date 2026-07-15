package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/redis/go-redis/v9"

	"github.com/joho/godotenv"
	otp "github.com/zuhairamahdi/gotp"
	"github.com/zuhairamahdi/gotp/httpapi"
	"github.com/zuhairamahdi/gotp/webhook"
)

func main() {
	godotenv.Load("../gotp/.env") // optional, for local dev only

	rdb := redis.NewClient(&redis.Options{
		Addr: envOr("REDIS_ADDR", "localhost:6379"),
	})
	defer rdb.Close()

	// In production: load from a secret manager / env var, at least 32
	// random bytes, rotated periodically. Never hardcode like this.
	secret := []byte(os.Getenv("OTP_HMAC_SECRET"))
	if len(secret) == 0 {
		secret = []byte("dev-only-secret-change-me-32bytes!")
	}

	endpoints := map[string]webhook.Endpoint{
		"sms": {
			URL:    envOr("OTP_WEBHOOK_SMS_URL", "https://relay.example.com/hooks/sms-otp"),
			Secret: []byte(envOr("OTP_WEBHOOK_SMS_SECRET", "dev-only-sms-secret-32-bytes!!!")),
		},
		"email": {
			URL:    envOr("OTP_WEBHOOK_EMAIL_URL", "https://relay.example.com/hooks/email-otp"),
			Secret: []byte(envOr("OTP_WEBHOOK_EMAIL_SECRET", "dev-only-email-secret-32-bytes!!")),
		},
		// "default": {URL: ..., Secret: ...}, // catch-all for any other channel
	}
	notifier := webhook.New(endpoints)
	// 5 minutes
	svc, err := otp.New(rdb, secret, otp.Config{
		CodeLength:     6,
		TTL:            envOrDuration("OTP_TTL", 300) * time.Second,
		MaxAttempts:    envOrInt("OTP_MAX_ATTEMPTS", 5),
		ResendCooldown: envOrDuration("OTP_RESEND_COOLDOWN", 60) * time.Second,
		KeyPrefix:      envOr("OTP_KEY_PREFIX", "otp"),
	}, otp.WithNotifier(notifier))
	if err != nil {
		log.Fatal(err)
	}

	e := echo.New()
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	// Basic per-IP rate limiting on top of the service's own per-identifier
	// cooldown, to blunt cost-abuse / enumeration across many identifiers.
	e.Use(middleware.RateLimiter(middleware.NewRateLimiterMemoryStore(2)))

	h := httpapi.NewHandler(svc)
	h.Register(e.Group("/otp"))

	e.GET("/healthz", func(c echo.Context) error {
		return c.String(http.StatusOK, "ok")
	})

	e.Logger.Fatal(e.Start(":" + envOr("PORT", "8080")))
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
func envOrInt64(key string, fallback int64) int64 {
	if v := os.Getenv(key); v != "" {
		var i int64
		_, err := fmt.Sscanf(v, "%d", &i)
		if err == nil {
			return i
		}
	}
	return fallback
}
func envOrDuration(key string, fallback time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		d, err := time.ParseDuration(v)
		if err == nil {
			return d
		}
	}
	return fallback
}
func envOrInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		var i int
		_, err := fmt.Sscanf(v, "%d", &i)
		if err == nil {
			return i
		}
	}
	return fallback
}
