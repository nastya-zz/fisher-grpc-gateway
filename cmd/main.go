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
	feedgw "github.com/nastya-zz/fisher-protocols/gen/feed_v1"
	postgw "github.com/nastya-zz/fisher-protocols/gen/post_v1"
	usergw "github.com/nastya-zz/fisher-protocols/gen/user_v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

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
	authAddr := getenv("AUTH_GRPC_ADDR", "127.0.0.1:50051")
	userAddr := getenv("USER_GRPC_ADDR", "127.0.0.1:50052")
	postAddr := getenv("POST_GRPC_ADDR", "127.0.0.1:50053")
	feedAddr := getenv("FEED_GRPC_ADDR", "127.0.0.1:50054")

	// Коннект к gRPC auth для проверки токена (lazy connection)
	authConn, err := grpc.NewClient(authAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Printf("Failed to create auth client: %v\n", err)
		os.Exit(1)
	}
	defer authConn.Close()
	authClient := authgw.NewAuthV1Client(authConn)
	fmt.Printf("Auth client configured for %s\n", authAddr)

	// Гейтвей: маппинг HTTP→gRPC и прокидка метаданных
	mux := runtime.NewServeMux(
		runtime.WithMetadata(func(ctx context.Context, r *http.Request) metadata.MD {
			token := r.Header.Get("Authorization")
			var pairs []string
			if token != "" {
				pairs = append(pairs, "authorization", token)
			}
			if uid, _ := ctx.Value(ctxUserIDKey{}).(string); uid != "" {
				pairs = append(pairs, "user-id", uid)
			}
			if roles, _ := ctx.Value(ctxUserRolesKey{}).(string); roles != "" {
				pairs = append(pairs, "user-roles", roles)
			}
			md := metadata.Pairs(pairs...)
			fmt.Printf("Forwarding metadata: %v\n", md)
			return md
		}),
		runtime.WithErrorHandler(func(ctx context.Context, mux *runtime.ServeMux, marshaler runtime.Marshaler, w http.ResponseWriter, r *http.Request, err error) {
			// Логируем gRPC ошибку с кириллицей в консоль
			if st, ok := status.FromError(err); ok {
				fmt.Printf("gRPC error: code=%s, message=%s, path=%s\n", st.Code(), st.Message(), r.URL.Path)
			} else {
				fmt.Printf("Error: %v, path=%s\n", err, r.URL.Path)
			}
			// Используем стандартный обработчик, но без передачи кириллицы в заголовки
			runtime.DefaultHTTPErrorHandler(ctx, mux, marshaler, w, r, err)
		}),
	)

	// Используем отдельные клиенты для каждого сервиса с lazy connection
	userConn, err := grpc.NewClient(userAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Printf("Failed to create user client: %v\n", err)
		os.Exit(1)
	}
	defer userConn.Close()

	postConn, err := grpc.NewClient(postAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Printf("Failed to create post client: %v\n", err)
		os.Exit(1)
	}
	defer postConn.Close()

	feedConn, err := grpc.NewClient(feedAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Printf("Failed to create feed client: %v\n", err)
		os.Exit(1)
	}
	defer feedConn.Close()

	// Регистрация handlers через готовые клиенты
	fmt.Printf("Registering user service handler for %s\n", userAddr)
	if err := usergw.RegisterUserV1Handler(context.Background(), mux, userConn); err != nil {
		fmt.Printf("WARNING: Failed to register user service handler: %v\n", err)
	}

	fmt.Printf("Registering post service handler for %s\n", postAddr)
	if err := postgw.RegisterPostServiceHandler(context.Background(), mux, postConn); err != nil {
		fmt.Printf("WARNING: Failed to register post service handler: %v\n", err)
	}

	fmt.Printf("Registering auth service handler for %s\n", authAddr)
	if err := authgw.RegisterAuthV1Handler(context.Background(), mux, authConn); err != nil {
		fmt.Printf("WARNING: Failed to register auth service handler: %v\n", err)
	}

	fmt.Printf("Registering feed service handler for %s\n", feedAddr)
	if err := feedgw.RegisterFeedV1Handler(context.Background(), mux, feedConn); err != nil {
		fmt.Printf("WARNING: Failed to register auth service handler: %v\n", err)
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
			fmt.Printf("Missing or invalid Authorization header: %s\n", authHeader)
			w.Header().Set("Content-Type", "application/json")
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		token := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer"))

		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()

		resp, err := authClient.ValidateToken(ctx, &authgw.ValidateTokenRequest{Token: token})

		if err != nil {
			// Логируем gRPC ошибку в консоль (UTF-8)
			if st, ok := status.FromError(err); ok {
				fmt.Printf("Auth validation failed: code=%s, message=%s\n", st.Code(), st.Message())
			} else {
				fmt.Printf("Auth validation failed: %v\n", err)
			}
			// Возвращаем клиенту только ASCII сообщение
			w.Header().Set("Content-Type", "application/json")
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}

		if resp.GetClaims().GetId() == "" {
			fmt.Println("Auth validation failed: empty user id in claims")
			w.Header().Set("Content-Type", "application/json")
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}

		// Клеймы в контекст → уйдут в gRPC метаданные через WithMetadata выше
		ctx = context.WithValue(r.Context(), ctxUserIDKey{}, resp.GetClaims().GetId())
		fmt.Printf("Authenticated user: id=%s, role=%s\n", resp.GetClaims().GetId(), resp.GetClaims().GetRole())
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
