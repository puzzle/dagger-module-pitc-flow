package main

import (
	"dagger/pitc-flow/internal/dagger"
)

type Face interface {
	DaggerObject
	Lint(
		dir *dagger.Directory,
		// +optional
		// +default=false
		pass bool,
	) *dagger.Directory
	DoLint(ctx context.Context) (bool, error)
	SecurityScan(dir *dagger.Directory) *dagger.Directory
	DoSecurityScan(ctx context.Context) (bool, error)
	Test(dir *dagger.Directory) *dagger.Directory
	DoTest(ctx context.Context) (bool, error)
	IntegrationTest(dir *dagger.Directory) *dagger.Directory
	DoIntegrationTest(ctx context.Context) (bool, error)
}

// Lints the sources and returns a directory with the results (default implementation)
func (m *PitcFlow) Lint(
	dir *dagger.Directory,
	pass bool,
	face Face,
) *dagger.Directory {
	return face.Lint(dir, pass)
}

func (m *PitcFlow) DoLint(
	ctx context.Context,
	face Face,
) (bool, error) {
	return face.DoLint(ctx)
}

// Runs security scan and returns a directory with the results (default implementation)
func (m *PitcFlow) SecurityScan(
	dir *dagger.Directory,
	face Face,
) *dagger.Directory {
	return face.SecurityScan(dir)
}

func (m *PitcFlow) DoSecurityScan(
	ctx context.Context,
	face Face,
) (bool, error) {
	return face.DoSecurityScan(ctx)
}

// Runs unit tests and returns a directory with the results (default implementation)
func (m *PitcFlow) Test(
	dir *dagger.Directory,
	face Face,
) *dagger.Directory {
	return face.Test(dir)
}

func (m *PitcFlow) DoTest(
	ctx context.Context,
	face Face,
) (bool, error) {
	return face.DoTest(ctx)
}

// Runs integration tests and returns a directory with the results (default implementation)
func (m *PitcFlow) IntegrationTest(
	dir *dagger.Directory,
	face Face,
) *dagger.Directory {
	return face.IntegrationTest(dir)
}

func (m *PitcFlow) DoIntegrationTest(
	ctx context.Context,
	face Face,
) (bool, error) {
	return face.DoIntegrationTest(ctx)
}
