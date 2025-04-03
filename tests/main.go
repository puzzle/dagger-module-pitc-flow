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

	p.Go(m.Sbom)
	p.Go(m.SbomBuild)
	p.Go(m.Vulnscan)
	p.Go(m.Publish)
	p.Go(m.PublishWithCredentials)
	p.Go(m.Full)
	p.Go(m.Flex)

	return p.Wait()
}

// Sbom test.
func (m *Tests) Sbom(_ context.Context) error {
	container := m.uniqContainer("alpine:latest", fmt.Sprintf("%d", time.Now().UnixNano()))
	if nil == dag.PitcFlow().Sbom(container) {
		return fmt.Errorf("should return sbom")
	}
	return nil
}

// SbomBuild test.
func (m *Tests) SbomBuild(_ context.Context) error {
	directory := dag.CurrentModule().Source().Directory("./testdata")
	if nil == dag.PitcFlow().SbomBuild(directory) {
		return fmt.Errorf("should build from dockerfile and return sbom")
	}
	return nil
}

// Vulnscan test.
func (m *Tests) Vulnscan(_ context.Context) error {
	container := m.uniqContainer("alpine:latest", fmt.Sprintf("%d", time.Now().UnixNano()))
	sbom := dag.PitcFlow().Sbom(container)
	if nil == dag.PitcFlow().Vulnscan(sbom) {
		return fmt.Errorf("should return vulnerabilty scan report")
	}
	return nil
}

// Publish test.
func (m *Tests) Publish(ctx context.Context) error {
	container := m.uniqContainer("alpine:latest", fmt.Sprintf("%d", time.Now().UnixNano()))
	_, err := dag.PitcFlow().Publish(ctx, container, "ttl.sh/test/alpine:latest")
	if err != nil {
		return fmt.Errorf("should publish container to registry")
	}
	return nil
}

// PublishWithCredentials test.
func (m *Tests) PublishWithCredentials(ctx context.Context) error {
	container := m.uniqContainer("alpine:latest", fmt.Sprintf("%d", time.Now().UnixNano()))
	secret := dag.SetSecret("password", "verySecret")
	_, err := dag.PitcFlow().Publish(
		ctx,
		container,
		"ttl.sh/test/alpine:latest",
		dagger.PitcFlowPublishOpts{RegistryUsername: "joe", RegistryPassword: secret},
	)
	if err != nil {
		return fmt.Errorf("should publish container to registry")
	}
	return nil
}

// Full test.
func (m *Tests) Full(_ context.Context) error {
	lintContainer := m.uniqContainer("alpine:latest", fmt.Sprintf("%d", time.Now().UnixNano())).
		WithExec([]string{"sh", "-c", "echo 'lint' > /tmp/lint.txt"})
	sastContainer := m.uniqContainer("alpine:latest", fmt.Sprintf("%d", time.Now().UnixNano())).
		WithExec([]string{"sh", "-c", "echo 'sast' > /tmp/sast.txt"})
	testContainer := m.uniqContainer("alpine:latest", fmt.Sprintf("%d", time.Now().UnixNano())).
		WithExec([]string{"sh", "-c", "mkdir -p /tmp/uTests"})
	integrationTestContainer := m.uniqContainer("alpine:latest", fmt.Sprintf("%d", time.Now().UnixNano())).
		WithExec([]string{"sh", "-c", "mkdir -p /tmp/iTests"})

	dir := dag.CurrentModule().Source().Directory("./testdata")
	lintReport := "/tmp/lint.txt"
	sastReport := "/tmp/sast.txt"
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
		lintReport,
		sastContainer,
		sastReport,
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

// Flex test.
func (m *Tests) Flex(_ context.Context) error {
	lintContainer := m.uniqContainer("alpine:latest", fmt.Sprintf("%d", time.Now().UnixNano())).
		WithExec([]string{"sh", "-c", "echo 'lint' > /tmp/lint.txt"})

	dir := dag.CurrentModule().Source().Directory("./testdata")
	lintReport := "/tmp/lint.txt"
	registryUsername := "joe"
	secret := dag.SetSecret("password", "verySecret")
	registryAddress := "ttl.sh/test/alpine:latest"
	dtAddress := "ttl.sh"
	dtProjectUUID := "12345678-1234-1234-1234-123456789012"

	directory := dag.PitcFlow().Flex(
		dir,
        dagger.PitcFlowFlexOpts{LintContainer: lintContainer, LintReport: lintReport, RegistryUsername: registryUsername, RegistryPassword: secret, RegistryAddress: registryAddress, DtAddress: dtAddress, DtProjectUUID: dtProjectUUID, DtAPIKey: secret},
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
