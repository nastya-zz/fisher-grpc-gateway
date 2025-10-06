package main

import (
	"context"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	authgw "github.com/nastya-zz/fisher-protocols/gen/auth_v1" // сгенерируй из [fisher-protocols](https://github.com/nastya-zz/fisher-protocols)
	postgw "github.com/nastya-zz/fisher-protocols/gen/post_v1"
	usergw "github.com/nastya-zz/fisher-protocols/gen/user_v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

type ctxUserIDKey struct{}
type ctxUserRolesKey struct{}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// publicPaths returns list of public path patterns from env PUBLIC_PATHS.
// Comma-separated, supports exact match ("/healthz") and prefix match with '*' ("/auth/*").
func publicPaths() []string {
	raw := getenv("PUBLIC_PATHS", "/v1/healthz,/v1/auth/login,/v1/posts")
	parts := strings.Split(raw, ",")
	res := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			res = append(res, p)
		}
	}
	return res
}

func isPublicPath(path string, patterns []string) bool {
	for _, pat := range patterns {
		if strings.HasSuffix(pat, "*") {
			prefix := strings.TrimSuffix(pat, "*")
			if strings.HasPrefix(path, prefix) {
				return true
			}
			continue
		}
		if path == pat {
			return true
		}
	}
	return false
}

func main() {
	authAddr := getenv("AUTH_GRPC_ADDR", "localhost:50051")
	userAddr := getenv("USER_GRPC_ADDR", "localhost:50052")
	postAddr := getenv("POST_GRPC_ADDR", "localhost:50053")

	// Коннект к gRPC auth для проверки токена
	authConn, _ := grpc.Dial(authAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	authClient := authgw.NewAuthV1Client(authConn)

	// Гейтвей: маппинг HTTP→gRPC и прокидка метаданных
	mux := runtime.NewServeMux(
		runtime.WithMetadata(func(ctx context.Context, r *http.Request) metadata.MD {
			token := r.Header.Get("Authorization")
			var pairs []string
			if token != "" {
				pairs = append(pairs, "authorization", token)
			}
			if uid, _ := ctx.Value(ctxUserIDKey{}).(string); uid != "" {
				pairs = append(pairs, "x-user-id", uid)
			}
			if roles, _ := ctx.Value(ctxUserRolesKey{}).(string); roles != "" {
				pairs = append(pairs, "x-user-roles", roles)
			}
			return metadata.Pairs(pairs...)
		}),
	)

	dial := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	_ = usergw.RegisterUserV1HandlerFromEndpoint(context.Background(), mux, userAddr, dial)
	_ = postgw.RegisterPostServiceHandlerFromEndpoint(context.Background(), mux, postAddr, dial)
	_ = authgw.RegisterAuthV1HandlerFromEndpoint(context.Background(), mux, authAddr, dial)

	pubs := publicPaths()

	// Middleware: проверка JWT через gRPC auth
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Пропусти публичные маршруты и preflight
		if r.Method == http.MethodOptions || isPublicPath(r.URL.Path, pubs) {
			mux.ServeHTTP(w, r)
			return
		}

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || !strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		token := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer"))

		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()

		// Подставь точные названия RPC из твоего auth_v1
		resp, err := authClient.ValidateToken(ctx, &authgw.ValidateTokenRequest{Token: token})
		if err != nil || resp.GetClaims().GetId() == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		// Клеймы в контекст → уйдут в gRPC метаданные через WithMetadata выше
		ctx = context.WithValue(r.Context(), ctxUserIDKey{}, resp.GetClaims().GetId())
		ctx = context.WithValue(ctx, ctxUserRolesKey{}, resp.GetClaims().GetRole())

		mux.ServeHTTP(w, r.WithContext(ctx))
	})

	_ = http.ListenAndServe(":8080", handler)
}
