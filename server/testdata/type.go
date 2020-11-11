package testdata

import (
	"context"
	"fmt"

	"github.com/golang/mock/gomock"
)

// DeadlineMatcher implements gomock.Matcher, such that an error is raised if
// there is no context.Context deadline set
type DeadlineMatcher struct{}

// NewDeadlineMatcher returns a new DeadlineMatcher
func NewDeadlineMatcher() gomock.Matcher {
	return &DeadlineMatcher{}
}

// Matches returns true if the passed interface is a context with a deadline
func (dm *DeadlineMatcher) Matches(i interface{}) bool {
	ctx, ok := i.(context.Context)
	if !ok {
		return false
	}
	_, ok = ctx.Deadline()
	return ok
}

// String is needed to implement gomock.Matcher
func (dm *DeadlineMatcher) String() string {
	return fmt.Sprintf("deadlineMatcher{}")
}
