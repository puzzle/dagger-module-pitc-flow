package main

import (
	"dagger/pitc-flow/internal/dagger"
)

type Linting interface {
	DaggerObject
	Lint(dir *dagger.Directory,
    // +optional
    // +default=false
    pass bool,
	) *dagger.Directory
}

type SecurityScanning interface {
	DaggerObject
	SecurityScan(dir *dagger.Directory) *dagger.Directory
}

type Testing interface {
	DaggerObject
	Test(dir *dagger.Directory) *dagger.Directory
}

type IntegrationTesting interface {
	DaggerObject
	IntegrationTest(dir *dagger.Directory) *dagger.Directory
}

// Lints the sources in the provided Directory and returns a directory with the results (default implementation)
func (m *PitcFlow) Lint(
	dir *dagger.Directory,
    // must not be optional here!
    pass bool,
	face Linting,
) *dagger.Directory {
	return face.Lint(dir, pass)
}

// Returns a file containing the results of the security scan
func (m *PitcFlow) SecurityScan(
	dir *dagger.Directory,
	face SecurityScanning,
) *dagger.Directory {
	return face.SecurityScan(dir)
}

// Runs unit tests in the provided Directory and returns a directory with the results (default implementation)
func (m *PitcFlow) Test(
	dir *dagger.Directory,
	face Testing,
) *dagger.Directory {
	return face.Test(dir)
}

// Runs integration tests in the provided Directory and returns a directory with the results (default implementation)
func (m *PitcFlow) IntegrationTest(
	dir *dagger.Directory,
	face IntegrationTesting,
) *dagger.Directory {
	return face.IntegrationTest(dir)
}
