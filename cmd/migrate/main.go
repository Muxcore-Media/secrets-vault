package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"time"

	secretsv1 "github.com/Muxcore-Media/core/proto/gen/muxcore/secrets/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	source := flag.String("source", "127.0.0.1:9550", "secrets-file gRPC address")
	dest := flag.String("dest", "127.0.0.1:9551", "secrets-vault gRPC address")
	insecureTLS := flag.Bool("insecure", true, "dial without TLS")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	srcConn, err := dial(ctx, *source, *insecureTLS)
	if err != nil {
		log.Fatalf("dial source: %v", err)
	}
	defer func() { _ = srcConn.Close() }()

	dstConn, err := dial(ctx, *dest, *insecureTLS)
	if err != nil {
		log.Fatalf("dial dest: %v", err)
	}
	defer func() { _ = dstConn.Close() }()

	src := secretsv1.NewSecretsServiceClient(srcConn)
	dst := secretsv1.NewSecretsServiceClient(dstConn)

	list, err := src.List(ctx, &secretsv1.ListRequest{})
	if err != nil {
		log.Fatalf("list source: %v", err)
	}

	var migrated int
	for _, key := range list.GetKeys() {
		got, err := src.Get(ctx, &secretsv1.GetRequest{Key: key})
		if err != nil {
			log.Fatalf("get %q: %v", key, err)
		}
		if _, err := dst.Set(ctx, &secretsv1.SetRequest{Key: key, Value: got.GetValue()}); err != nil {
			log.Fatalf("set %q: %v", key, err)
		}
		migrated++
		fmt.Printf("migrated %q\n", key)
	}
	fmt.Printf("done: %d secrets copied\n", migrated)
}

func dial(_ context.Context, addr string, insecureTLS bool) (*grpc.ClientConn, error) {
	var opts []grpc.DialOption
	if insecureTLS {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}
	return grpc.NewClient(addr, opts...)
}
