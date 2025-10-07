package main

import (
	"context"
	"fmt"
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

	"grpc-gateway/internal/paths"
)

type ctxUserIDKey struct{}
type ctxUserRolesKey struct{}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	authAddr := getenv("AUTH_GRPC_ADDR", "localhost:50051")
	userAddr := getenv("USER_GRPC_ADDR", "localhost:50052")
	postAddr := getenv("POST_GRPC_ADDR", "localhost:50053")

	// Коннект к gRPC auth для проверки токена
	authConn, err := grpc.Dial(authAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Printf("Failed to connect to auth service at %s: %v\n", authAddr, err)
		os.Exit(1)
	}
	defer authConn.Close()
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
	if err := usergw.RegisterUserV1HandlerFromEndpoint(context.Background(), mux, userAddr, dial); err != nil {
		fmt.Printf("Failed to register user service handler: %v\n", err)
		os.Exit(1)
	}
	if err := postgw.RegisterPostServiceHandlerFromEndpoint(context.Background(), mux, postAddr, dial); err != nil {
		fmt.Printf("Failed to register post service handler: %v\n", err)
		os.Exit(1)
	}
	if err := authgw.RegisterAuthV1HandlerFromEndpoint(context.Background(), mux, authAddr, dial); err != nil {
		fmt.Printf("Failed to register auth service handler: %v\n", err)
		os.Exit(1)
	}

	pubs := paths.PublicPaths()

	// Middleware: проверка JWT через gRPC auth
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// публичные маршруты и preflight
		if r.Method == http.MethodOptions || paths.IsPublicPath(r.URL.Path, pubs) {
			mux.ServeHTTP(w, r)
			return
		}

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || !strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
			fmt.Println("unauthorized", authHeader)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		token := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer"))

		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()

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

	port := getenv("PORT", "9999")

	fmt.Printf("Starting HTTP server on :%s...\n", port)
	if err := http.ListenAndServe(":"+port, handler); err != nil {
		fmt.Printf("HTTP server failed: %v\n", err)
		os.Exit(1)
	}
}
