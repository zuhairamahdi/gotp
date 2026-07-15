package main

import (
	"log"
	"net/http"
	"os"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/redis/go-redis/v9"

	otp "github.com/zuhairamahdi/gotp"
	"github.com/zuhairamahdi/gotp/httpapi"
	"github.com/zuhairamahdi/gotp/webhook"
)

func main() {
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

	svc, err := otp.New(rdb, secret, otp.Config{
		CodeLength: 6,
		// TTL, MaxAttempts, ResendCooldown left as defaults (5m/5/60s)
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
