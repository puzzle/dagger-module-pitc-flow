package main

import (
	"context"
	"dagger/tests/internal/dagger"
	"fmt"
	"strings"
	"time"

	"github.com/sourcegraph/conc/pool"
)

type Tests struct{}

// All executes all tests.
func (m *Tests) All(ctx context.Context) error {
	p := pool.New().WithErrors().WithContext(ctx)

	p.Go(m.Full)
	p.Go(m.Ci)
	p.Go(m.Flex)

	return p.Wait()
}


// Full test.
func (m *Tests) Full(_ context.Context) error {
	lintContainer := m.uniqContainer("alpine:latest", fmt.Sprintf("%d", time.Now().UnixNano())).
		WithExec([]string{"sh", "-c", "mkdir -p /tmp/lint"}).
		WithExec([]string{"sh", "-c", "echo 'lint' > /tmp/lint/lint.txt"})
	sastContainer := m.uniqContainer("alpine:latest", fmt.Sprintf("%d", time.Now().UnixNano())).
		WithExec([]string{"sh", "-c", "mkdir -p /tmp/sast"}).
		WithExec([]string{"sh", "-c", "echo 'sast' > /tmp/sast/sast.txt"})
	testContainer := m.uniqContainer("alpine:latest", fmt.Sprintf("%d", time.Now().UnixNano())).
		WithExec([]string{"sh", "-c", "mkdir -p /tmp/uTests"})
	integrationTestContainer := m.uniqContainer("alpine:latest", fmt.Sprintf("%d", time.Now().UnixNano())).
		WithExec([]string{"sh", "-c", "mkdir -p /tmp/iTests"})

	dir := dag.CurrentModule().Source().Directory("./testdata")
	lintReportDir := "/tmp/lint"
	sastReportDir := "/tmp/sast"
	testReportDir := "/tmp/uTests"
	integrationTestReportDir := "/tmp/iTests"
	registryUsername := "joe"
	secret := dag.SetSecret("password", "verySecret")
	registryAddress := "ttl.sh/test/alpine:latest"
	dtAddress := "ttl.sh"
	dtProjectUUID := "12345678-1234-1234-1234-123456789012"

	directory := dag.PitcFlow().Full(
		dir,
		lintContainer,
		lintReportDir,
		sastContainer,
		sastReportDir,
		testContainer,
		testReportDir,
		integrationTestContainer,
		integrationTestReportDir,
		registryUsername,
		secret,
		registryAddress,
		dtAddress,
		dtProjectUUID,
		secret,
	)

	if directory == nil {
		return fmt.Errorf("should run the pipeline and return a directory")
	}

	files, err := directory.Entries(context.Background())
	if err != nil {
		return fmt.Errorf("failed to list files in directory: %w", err)
	}

	for _, file := range files {
		if strings.Contains(file, "status.txt") {
			return nil
		}
	}

	return fmt.Errorf("status.txt was missing from all files: %v", files)
}

// Ci test.
func (m *Tests) Ci(_ context.Context) error {
	lintContainer := m.uniqContainer("alpine:latest", fmt.Sprintf("%d", time.Now().UnixNano())).
		WithExec([]string{"sh", "-c", "mkdir -p /tmp/lint"}).
		WithExec([]string{"sh", "-c", "echo 'lint' > /tmp/lint/lint.txt"})
	sastContainer := m.uniqContainer("alpine:latest", fmt.Sprintf("%d", time.Now().UnixNano())).
		WithExec([]string{"sh", "-c", "mkdir -p /tmp/sast"}).
		WithExec([]string{"sh", "-c", "echo 'sast' > /tmp/sast/sast.txt"})
	testContainer := m.uniqContainer("alpine:latest", fmt.Sprintf("%d", time.Now().UnixNano())).
		WithExec([]string{"sh", "-c", "mkdir -p /tmp/uTests"})
	integrationTestContainer := m.uniqContainer("alpine:latest", fmt.Sprintf("%d", time.Now().UnixNano())).
		WithExec([]string{"sh", "-c", "mkdir -p /tmp/iTests"})

	dir := dag.CurrentModule().Source().Directory("./testdata")
	lintReportDir := "/tmp/lint"
	sastReportDir := "/tmp/sast"
	testReportDir := "/tmp/uTests"
	integrationTestReportDir := "/tmp/iTests"

	directory := dag.PitcFlow().Ci(
		dir,
		lintContainer,
		lintReportDir,
		sastContainer,
		sastReportDir,
		testContainer,
		testReportDir,
		integrationTestContainer,
		integrationTestReportDir,
	)

	if directory == nil {
		return fmt.Errorf("should run the pipeline and return a directory")
	}

	files, err := directory.Entries(context.Background())
	if err != nil {
		return fmt.Errorf("failed to list files in directory: %w", err)
	}

	for _, file := range files {
		if strings.Contains(file, "status.txt") {
			return nil
		}
	}

	return fmt.Errorf("status.txt was missing from all files: %v", files)
}

// Flex test.
func (m *Tests) Flex(_ context.Context) error {
	lintContainer := m.uniqContainer("alpine:latest", fmt.Sprintf("%d", time.Now().UnixNano())).
		WithExec([]string{"sh", "-c", "mkdir -p /tmp/lint"}).
		WithExec([]string{"sh", "-c", "echo 'lint' > /tmp/lint/lint.txt"})

	dir := dag.CurrentModule().Source().Directory("./testdata")
	lintReportDir := "/tmp/lint"
	registryUsername := "joe"
	secret := dag.SetSecret("password", "verySecret")
	registryAddress := "ttl.sh/test/alpine:latest"
	dtAddress := "ttl.sh"
	dtProjectUUID := "12345678-1234-1234-1234-123456789012"

	directory := dag.PitcFlow().Flex(
		dir,
		dagger.PitcFlowFlexOpts{LintContainer: lintContainer, LintReportDir: lintReportDir, RegistryUsername: registryUsername, RegistryPassword: secret, RegistryAddress: registryAddress, DtAddress: dtAddress, DtProjectUUID: dtProjectUUID, DtAPIKey: secret},
	)

	if directory == nil {
		return fmt.Errorf("should run the pipeline and return a directory")
	}

	files, err := directory.Entries(context.Background())
	if err != nil {
		return fmt.Errorf("failed to list files in directory: %w", err)
	}

	for _, file := range files {
		if strings.Contains(file, "status.txt") {
			return nil
		}
	}

	return fmt.Errorf("status.txt was missing from all files: %v", files)
}

func (m *Tests) uniqContainer(image string, randomString string) *dagger.Container {
	return dag.Container().From(image).
		WithNewFile(
			fmt.Sprintf("/usr/share/%s", randomString),
			randomString,
		)
}
