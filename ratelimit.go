package ratelimit

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/redis/go-redis/v9"
)

type Config struct {
	// determines the window of time for which bans will be calculated before the deny counter is reset
	RefreshDuration time.Duration

	RedisConn redis.Conn

	// if the user is denied more than this number of times, they'll be banned for the specified period
	DenyThreshold int

	BanDuration time.Duration
}

func Middleware(cfg *Config) echo.MiddlewareFunc {
	identityFunc := func(ctx echo.Context) (string, error) {
		id := ctx.RealIP()
		return id, nil
	}
	identityErrorHandler := func(context echo.Context, err error) error {
		return context.String(http.StatusForbidden, "failed to extract user identity for rate-limiter")
	}

	config := middleware.RateLimiterConfig{
		Skipper: middleware.DefaultSkipper,
		// rate limiting is in-memory, but ban threshold is calculated using redis
		Store: middleware.NewRateLimiterMemoryStoreWithConfig(
			middleware.RateLimiterMemoryStoreConfig{Rate: 3, Burst: 10, ExpiresIn: 3 * time.Minute},
		),
		IdentifierExtractor: identityFunc,
		ErrorHandler:        identityErrorHandler,
		DenyHandler: func(ctx echo.Context, identifier string, err error) error {
			id, err := identityFunc(ctx)
			if err != nil {
				return identityErrorHandler(ctx, err)
			}
			err = incrDenies(cfg.RedisConn, id, cfg.DenyThreshold, cfg.BanDuration, cfg.RefreshDuration)
			if err != nil {
				// do something later?
			}

			return ctx.String(http.StatusTooManyRequests, "Rate limit exceeded.")
		},
	}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			id, err := config.IdentifierExtractor(c)
			if err != nil {
				return config.ErrorHandler(c, err)
			}

			if banned, err := isBanned(cfg.RedisConn, id, cfg.DenyThreshold); err != nil {
				return c.String(http.StatusInternalServerError, err.Error())
			} else if banned {
				return c.String(http.StatusForbidden, "You are banned from the service.")
			}

			// pass it along to the normal rate limiter
			return middleware.RateLimiterWithConfig(config)(next)(c)
		}
	}

}

func incrDenies(conn redis.Conn, identity string, denyThreshold int, banDuration, expireDuration time.Duration) error {
	res, err := conn.Incr(context.Background(), identityKey(identity)).Result()
	if err != nil {
		return err
	}

	ttl, err := conn.TTL(context.Background(), identityKey(identity)).Result()
	if err != nil {
		return err
	} else if ttl == -1 {
		// TTL hasn't been set, so we need to set it to the refresh period
		err = conn.Expire(context.Background(), identityKey(identity), expireDuration).Err()
		if err != nil {
			return err
		}
	}

	if res >= int64(denyThreshold) {
		// set the expire to the ban duration
		err = conn.Expire(context.Background(), identityKey(identity), banDuration).Err()
		if err != nil {
			return err
		}
	}

	return nil
}

func isBanned(conn redis.Conn, identity string, banThreshold int) (bool, error) {
	res, err := conn.Get(context.Background(), identityKey(identity)).Int()
	if err != nil {
		return false, err
	}

	return res >= banThreshold, nil
}

func identityKey(identity string) string {
	return fmt.Sprintf("ban:%s", identity)
}
