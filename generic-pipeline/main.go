// A module containing GenericPipeline functions
//
// This module contains functions that can be used in multiple pipelines

package main

import (
	"context"
	"dagger/generic-pipeline/internal/dagger"
	"fmt"
)

type GenericPipeline struct{}

// Returns a Container built from the Dockerfile in the provided Directory
func (m *GenericPipeline) Build(_ context.Context, dir *dagger.Directory) *dagger.Container {
	return dag.Container().
		WithDirectory("/src", dir).
		WithWorkdir("/src").
		Directory("/src").
		DockerBuild()
}

// Builds the container and creates an SBOM for it
func (m *GenericPipeline) SbomBuild(ctx context.Context, dir *dagger.Directory) *dagger.File {
	container := m.Build(ctx, dir)
	return m.Sbom(container)
}

// Creates an SBOM for the container
func (m *GenericPipeline) Sbom(container *dagger.Container) *dagger.File {
	trivy_container := dag.Container().
		From("aquasec/trivy").
		WithEnvVariable("TRIVY_JAVA_DB_REPOSITORY", "public.ecr.aws/aquasecurity/trivy-java-db")

	trivy := dag.Trivy(dagger.TrivyOpts{
		Container:          trivy_container,
		DatabaseRepository: "public.ecr.aws/aquasecurity/trivy-db",
	})

	sbom := trivy.Container(container).
		Report("cyclonedx").
		WithName("cyclonedx.json")

	return sbom
}

// Scans the SBOM for vulnerabilities
func (m *GenericPipeline) Vulnscan(sbom *dagger.File) *dagger.File {
	trivy_container := dag.Container().
		From("aquasec/trivy").
		WithEnvVariable("TRIVY_JAVA_DB_REPOSITORY", "public.ecr.aws/aquasecurity/trivy-java-db")

	trivy := dag.Trivy(dagger.TrivyOpts{
		Container:          trivy_container,
		DatabaseRepository: "public.ecr.aws/aquasecurity/trivy-db",
	})

	return trivy.Sbom(sbom).Report("json")
}

// Publish cyclonedx SBOM to Deptrack
func (m *GenericPipeline) PublishToDeptrack(
	ctx context.Context,
	// SBOM file
	sbom *dagger.File,
	// deptrack address for publishing the SBOM https://deptrack.example.com/api/v1/bom
	address string,
	// deptrack API key
	apiKey *dagger.Secret,
	// deptrack project UUID
	projectUUID string,
) (string, error) {
	return dag.Container().
		From("curlimages/curl").
		WithFile("sbom.json", sbom).
		WithExec([]string{"curl", "-X", "POST", "-H", "'Content-Type: multipart/form-data'", "-H", fmt.Sprintf("'X-API-Key: %s'", apiKey), "-F", fmt.Sprintf("'project=%s'", projectUUID), "-F", "bom=@sbom.json", address}).
		Stdout(ctx)
}

// Publish the provided Container to the provided registry
func (m *GenericPipeline) Publish(ctx context.Context, container *dagger.Container, registryAddress string) (string, error) {
	return container.Publish(ctx, registryAddress)
}

// Sign the published image using cosign
func (m *GenericPipeline) Sign(
	ctx context.Context,
	registryUsername string,
	registryPassword *dagger.Secret,
	// Container image digest to sign
	digest string,
) (string, error) {
	return dag.Cosign().SignKeyless(ctx, digest, dagger.CosignSignKeylessOpts{RegistryUsername: registryUsername, RegistryPassword: registryPassword})
}

// Attests the SBOM using cosign
func (m *GenericPipeline) Attest(
	ctx context.Context,
	registryUsername string,
	registryPassword *dagger.Secret,
	// Container image digest to attest
	digest string,
	// SBOM file
	predicate *dagger.File,
	// SBOM type
	sbomType string,
) (string, error) {
	return dag.Cosign().AttestKeyless(ctx, digest, predicate, dagger.CosignAttestKeylessOpts{RegistryUsername: registryUsername, RegistryPassword: registryPassword, SbomType: sbomType})
}
