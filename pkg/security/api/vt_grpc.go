package api

import (
	"github.com/planetscale/vtprotobuf/codec/grpc"
	"google.golang.org/grpc/encoding"
)

func init() {
	encoding.RegisterCodec(grpc.Codec{})
}
