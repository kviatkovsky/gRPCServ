package app

import (
	"log/slog"
	"time"

	grpcapp "github.com/kviatkovsky/gRPCServ_sso/cmd/app/grpc"
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
	grpcApp := grpcapp.New(log, grpcPort)

	return &App{
		GRPCServ: grpcApp,
	}
}
