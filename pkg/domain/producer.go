package domain

import (
	"context"
)

// Producer sends events to a stream somewhere. All events must be valid for
// json.Marshal().
type Producer interface {
	Produce(ctx context.Context, event interface{}) (interface{}, error)
}
