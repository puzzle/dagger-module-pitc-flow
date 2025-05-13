package main

import (
	"dagger/pitc-flow/internal/dagger"
)

type Linter interface {
	DaggerObject
	Lint(dir *dagger.Directory,
		// +optional
		// +default=false
		pass bool,
	) *dagger.Directory
}

type SecurityScanner interface {
	DaggerObject
	SecurityScan(dir *dagger.Directory) *dagger.Directory
}

type Tester interface {
	DaggerObject
	Test(dir *dagger.Directory) *dagger.Directory
}

type IntegrationTester interface {
	DaggerObject
	IntegrationTest(dir *dagger.Directory) *dagger.Directory
}

// Lints the sources in the provided directory and returns a directory with the results (default implementation)
func (m *PitcFlow) Lint(
	dir *dagger.Directory,
	// must not be optional here!
	pass bool,
	face Linter,
) *dagger.Directory {
	return face.Lint(dir, pass)
}

// Runs a security scan in the provided directory and returns a directory with the results (default implementation)
func (m *PitcFlow) SecurityScan(
	dir *dagger.Directory,
	face SecurityScanner,
) *dagger.Directory {
	return face.SecurityScan(dir)
}

// Runs unit tests in the provided directory and returns a directory with the results (default implementation)
func (m *PitcFlow) Test(
	dir *dagger.Directory,
	face Tester,
) *dagger.Directory {
	return face.Test(dir)
}

// Runs integration tests in the provided directory and returns a directory with the results (default implementation)
func (m *PitcFlow) IntegrationTest(
	dir *dagger.Directory,
	face IntegrationTester,
) *dagger.Directory {
	return face.IntegrationTest(dir)
}
