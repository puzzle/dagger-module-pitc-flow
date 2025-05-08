package main

import (
	"dagger/pitc-flow/internal/dagger"
)

type Face interface {
	DaggerObject
	Lint(dir *dagger.Directory, pass bool) *dagger.Directory
	SecurityScan(dir *dagger.Directory) *dagger.Directory
	Test(dir *dagger.Directory) *dagger.Directory
	IntegrationTest(dir *dagger.Directory) *dagger.Directory
}

// Lints the sources and returns a directory with the results (default implementation)
func (m *PitcFlow) Lint(
	dir *dagger.Directory,
	pass bool,
	face Face,
) *dagger.Directory {
	return face.Lint(dir, pass)
}

// Runs security scan and returns a directory with the results (default implementation)
func (m *PitcFlow) SecurityScan(
	dir *dagger.Directory,
	face Face,
) *dagger.Directory {
	return face.SecurityScan(dir)
}

// Runs unit tests and returns a directory with the results (default implementation)
func (m *PitcFlow) Test(
	dir *dagger.Directory,
	face Face,
) *dagger.Directory {
	return face.Test(dir)
}

// Runs integration tests and returns a directory with the results (default implementation)
func (m *PitcFlow) IntegrationTest(
	dir *dagger.Directory,
	face Face,
) *dagger.Directory {
	return face.IntegrationTest(dir)
}
