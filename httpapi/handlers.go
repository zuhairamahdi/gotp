// Package httpapi wires the otp.Service into Echo HTTP handlers.
package httpapi

import (
	"errors"
	"net/http"

	"github.com/labstack/echo/v4"

	otp "github.com/zuhairamahdi/gotp"
)

// Handler holds dependencies for the OTP HTTP endpoints.
type Handler struct {
	svc *otp.Service
}

func NewHandler(svc *otp.Service) *Handler {
	return &Handler{svc: svc}
}

func (h *Handler) Register(g *echo.Group) {
	g.POST("/generate", h.Generate)
	g.POST("/verify", h.Verify)
}

type generateRequest struct {
	Identifier string `json:"identifier" validate:"required"`
	Purpose    string `json:"purpose" validate:"required"`
	// Channel selects delivery method, e.g. "sms", "email", or any custom
	// value your configured webhook endpoints understand. Optional if a
	// "default" webhook endpoint is configured.
	Channel string `json:"channel"`
}

type generateResponse struct {
	Message string `json:"message"`
}

// Generate issues a new OTP and (in a real deployment) dispatches it via
// SMS/email — it never returns the plaintext code in the API response.
func (h *Handler) Generate(c echo.Context) error {
	var req generateRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	if req.Identifier == "" || req.Purpose == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "identifier and purpose are required")
	}

	_, err := h.svc.Generate(c.Request().Context(), req.Identifier, req.Purpose, req.Channel)
	if err != nil {
		switch {
		case errors.Is(err, otp.ErrCooldownActive):
			return echo.NewHTTPError(http.StatusTooManyRequests, "please wait before requesting another code")
		default:
			// Covers webhook delivery failures too (Generate rolls back
			// the stored code/cooldown in that case, so it's safe to let
			// the caller retry immediately).
			c.Logger().Errorf("otp generate failed: %v", err)
			return echo.NewHTTPError(http.StatusInternalServerError, "could not generate or send code")
		}
	}

	return c.JSON(http.StatusOK, generateResponse{Message: "code sent"})
}

type verifyRequest struct {
	Identifier string `json:"identifier" validate:"required"`
	Purpose    string `json:"purpose" validate:"required"`
	Code       string `json:"code" validate:"required"`
}

type verifyResponse struct {
	Verified bool `json:"verified"`
}

// Verify checks a submitted code against the stored hash.
func (h *Handler) Verify(c echo.Context) error {
	var req verifyRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	if req.Identifier == "" || req.Purpose == "" || req.Code == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "identifier, purpose, and code are required")
	}

	err := h.svc.Verify(c.Request().Context(), req.Identifier, req.Purpose, req.Code)
	if err != nil {
		switch {
		case errors.Is(err, otp.ErrInvalidCode):
			return echo.NewHTTPError(http.StatusBadRequest, "incorrect code")
		case errors.Is(err, otp.ErrTooManyAttempts):
			return echo.NewHTTPError(http.StatusTooManyRequests, "too many attempts, request a new code")
		case errors.Is(err, otp.ErrExpiredOrNotFound):
			return echo.NewHTTPError(http.StatusGone, "code expired or was never issued")
		default:
			c.Logger().Errorf("otp verify failed: %v", err)
			return echo.NewHTTPError(http.StatusInternalServerError, "could not verify code")
		}
	}

	return c.JSON(http.StatusOK, verifyResponse{Verified: true})
}
