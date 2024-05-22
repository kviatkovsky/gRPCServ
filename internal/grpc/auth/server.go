package auth

import (
	"context"

	"github.com/go-playground/validator/v10"
	"github.com/kviatkovsky/gRPCServ_sso/internal/services/auth"
	ssov1 "github.com/kviatkovsky/gRPCService_protos/gen/go/sso"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Auth interface {
	Login(
		ctx context.Context,
		email string,
		password string,
		appId int,
	) (token string, err error)

	RegisterNewUser(
		ctx context.Context,
		email string,
		password string,
	) (userId int64, err error)

	IsAdmin(ctx context.Context, userID int64) (bool, error)
}

type UserLoginPayload struct {
	Email    string `validate:"required,email"`
	Password string `validate:"required"`
	AppId    int32  `validate:"gte=0"`
}

type UserRegistrationPayload struct {
	Email    string `validate:"required,email"`
	Password string `validate:"required"`
}

type IsAdminPayload struct {
	UserId int64 `validate:"required,min=1"`
}

type ServerAPI struct {
	ssov1.UnimplementedAuthServer
	auth Auth
}

var validate *validator.Validate

func Register(gRPC *grpc.Server, auth *auth.Auth) {
	ssov1.RegisterAuthServer(gRPC, &ServerAPI{auth: auth})
}

func (s *ServerAPI) Login(ctx context.Context, req *ssov1.LoginRequest) (*ssov1.LoginResponse, error) {
	payload := UserLoginPayload{
		Email:    req.GetEmail(),
		Password: req.GetPassword(),
		AppId:    req.GetAppId(),
	}

	err := validatePayload(&payload)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	token, err := s.auth.Login(ctx, payload.Email, payload.Password, int(payload.AppId))
	if err != nil {
		return nil, status.Error(codes.Internal, "internal server error")
	}

	return &ssov1.LoginResponse{
		Token: token,
	}, nil
}

func (s *ServerAPI) Register(ctx context.Context, req *ssov1.RegisterRequest) (*ssov1.RegisterResponse, error) {
	payload := UserRegistrationPayload{
		Email:    req.GetEmail(),
		Password: req.GetPassword(),
	}

	err := validatePayload(&payload)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	userId, err := s.auth.RegisterNewUser(ctx, req.GetEmail(), req.GetPassword())
	if err != nil {
		return nil, status.Error(codes.Internal, "internal server error")
	}

	return &ssov1.RegisterResponse{
		UserId: userId,
	}, nil

}

func (s *ServerAPI) IsAdmin(ctx context.Context, req *ssov1.IsAdminRequest) (*ssov1.IsAdminResponse, error) {
	payload := IsAdminPayload{
		UserId: req.GetUserId(),
	}

	err := validatePayload(&payload)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	isAdmin, err := s.auth.IsAdmin(ctx, req.GetUserId())
	if err != nil {
		return nil, status.Error(codes.Internal, "internal server error")
	}

	return &ssov1.IsAdminResponse{
		IsAdmin: isAdmin,
	}, nil
}

func validatePayload(payload any) error {
	validate = validator.New(validator.WithRequiredStructEnabled())

	err := validate.Struct(payload)
	if err != nil {
		return err
	}

	return nil
}
