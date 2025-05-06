package main

import (
	"dagger/pitc-flow/internal/dagger"
)

type Face interface {
	DaggerObject
//	Vulnscan(sbom *dagger.File) *dagger.File
	Lint(dir *dagger.Directory) *dagger.Directory
//	Sast(dir *dagger.Directory) *dagger.Directory
	Test(dir *dagger.Directory) *dagger.Directory
//	IntegrationTest(dir *dagger.Directory) *dagger.Directory
}

// Scans the SBOM for vulnerabilities and returns the report file (default implementation)
/* func (m *PitcFlow) Vulnscan(
	sbom *dagger.File,
	face Face,
) *dagger.File {
	return face.Vulnscan(sbom)
} */

// Lints the sources in the provided Directory and returns a directory with the results (default implementation)
func (m *PitcFlow) Lint(
	dir *dagger.Directory,
	face Face,
) *dagger.Directory {
	return face.Lint(dir)
}

// Returns a file containing the results of the security scan
/* func (m *PitcFlow) Sast(
	dir *dagger.Directory,
	face Face,
) *dagger.Directory {
	return face.Sast(dir)
} */

// Runs unit tests in the provided Directory and returns a directory with the results (default implementation)
func (m *PitcFlow) Test(
	dir *dagger.Directory,
	face Face,
) *dagger.Directory {
	return face.Test(dir)
}

// Runs integration tests in the provided Directory and returns a directory with the results (default implementation)
/* func (m *PitcFlow) IntegrationTest(
	dir *dagger.Directory,
	face Face,
) *dagger.Directory {
	return face.IntegrationTest(dir)
} */
