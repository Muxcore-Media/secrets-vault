package server

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	secretsv1 "github.com/Muxcore-Media/core/proto/gen/muxcore/secrets/v1"
	"github.com/Muxcore-Media/secrets-vault/internal/backend"
)

type Server struct {
	secretsv1.UnimplementedSecretsServiceServer
	backend  backend.Backend
	getCount atomic.Int64
	setCount atomic.Int64
	delCount atomic.Int64
}

func New(b backend.Backend) *Server {
	return &Server{backend: b}
}

func (s *Server) RegisterWithGRPC(srv *grpc.Server) {
	secretsv1.RegisterSecretsServiceServer(srv, s)
}

func (s *Server) Get(ctx context.Context, req *secretsv1.GetRequest) (*secretsv1.GetResponse, error) {
	if req.GetKey() == "" {
		return nil, status.Error(codes.InvalidArgument, "key is required")
	}
	val, err := s.backend.Get(ctx, req.GetKey())
	if err != nil {
		slog.Error("secrets: get failed", "key", req.GetKey(), "error", err)
		return nil, mapError(err)
	}
	s.getCount.Add(1)
	return &secretsv1.GetResponse{Key: req.GetKey(), Value: val}, nil
}

func (s *Server) Set(ctx context.Context, req *secretsv1.SetRequest) (*secretsv1.SetResponse, error) {
	if req.GetKey() == "" {
		return nil, status.Error(codes.InvalidArgument, "key is required")
	}
	if err := s.backend.Set(ctx, req.GetKey(), req.GetValue()); err != nil {
		slog.Error("secrets: set failed", "key", req.GetKey(), "error", err)
		return nil, mapError(err)
	}
	s.setCount.Add(1)
	return &secretsv1.SetResponse{Status: "ok"}, nil
}

func (s *Server) Delete(ctx context.Context, req *secretsv1.DeleteRequest) (*secretsv1.DeleteResponse, error) {
	if req.GetKey() == "" {
		return nil, status.Error(codes.InvalidArgument, "key is required")
	}
	if err := s.backend.Delete(ctx, req.GetKey()); err != nil {
		slog.Error("secrets: delete failed", "key", req.GetKey(), "error", err)
		return nil, mapError(err)
	}
	s.delCount.Add(1)
	return &secretsv1.DeleteResponse{Status: "ok"}, nil
}

func (s *Server) List(ctx context.Context, req *secretsv1.ListRequest) (*secretsv1.ListResponse, error) {
	keys, err := s.backend.List(ctx)
	if err != nil {
		slog.Error("secrets: list failed", "error", err)
		return nil, mapError(err)
	}
	return &secretsv1.ListResponse{Keys: keys, Count: int32(len(keys))}, nil
}

func mapError(err error) error {
	switch {
	case errors.Is(err, backend.ErrEmptyKey):
		return status.Error(codes.InvalidArgument, "key is required")
	case errors.Is(err, backend.ErrNotFound):
		return status.Error(codes.NotFound, "secret not found")
	case errors.Is(err, backend.ErrPermissionDenied):
		return status.Error(codes.PermissionDenied, "permission denied")
	case errors.Is(err, backend.ErrUnsupported):
		return status.Error(codes.FailedPrecondition, "operation not supported")
	default:
		return status.Error(codes.Internal, "operation failed")
	}
}
