package app

import (
	"log/slog"
	"time"

	grpcapp "github.com/kviatkovsky/gRPCServ_sso/cmd/app/grpc"
	"github.com/kviatkovsky/gRPCServ_sso/internal/services/auth"
	"github.com/kviatkovsky/gRPCServ_sso/internal/storage/sqlite"
)

type App struct {
	GRPCServ *grpcapp.App
}

func New(
	log *slog.Logger,
	grpcPort int,
	storagePath string,
	tokenTTl time.Duration,
) *App {
	storage, err := sqlite.New(storagePath)
	if err != nil {
		panic(err)
	}

	authService := auth.New(log, storage, storage, storage, tokenTTl)

	grpcApp := grpcapp.New(log, authService, grpcPort)

	return &App{
		GRPCServ: grpcApp,
	}
}
