package main

import (
	"context"
	"dagger/pitc-flow/internal/dagger"
	"fmt"
	"sync"
)

// Returns a file containing the results of the lint command
func (m *PitcFlow) lint(
	// Container to run the lint command
	container *dagger.Container,
	// Path to directory containing lint results
	results string,
) *dagger.Directory {
	return container.Directory(results)
}

// Returns a directory containing the results of the test command
func (m *PitcFlow) test(
	// Container to run the test command
	container *dagger.Container,
	// Path to directory containing test results
	results string,
) *dagger.Directory {
	return container.Directory(results)
}

// Returns a directory containing the results of the integration test command
func (m *PitcFlow) intTest(
	// Container to run the integration test command
	container *dagger.Container,
	// Path to directory containing integration test results
	results string,
) *dagger.Directory {
	return container.Directory(results)
}

// Returns a file containing the results of the security scan
func (m *PitcFlow) sast(
	// Container to run the security scan
	container *dagger.Container,
	// Path to directory containing the results of the security scan
	results string,
) *dagger.Directory {
	return container.Directory(results)
}

// Returns a Container built from the Dockerfile in the provided Directory
func (m *PitcFlow) build(_ context.Context, dir *dagger.Directory) *dagger.Container {
	return dag.Container().
		WithDirectory("/src", dir).
		WithWorkdir("/src").
		Directory("/src").
		DockerBuild()
}

// Builds the container and creates a SBOM for it
func (m *PitcFlow) sbomBuild(ctx context.Context, dir *dagger.Directory) *dagger.File {
	container := m.build(ctx, dir)
	return m.sbom(container)
}

// Creates a SBOM for the container
func (m *PitcFlow) sbom(container *dagger.Container) *dagger.File {
	trivy_container := dag.Container().
		From("aquasec/trivy").
		WithEnvVariable("TRIVY_JAVA_DB_REPOSITORY", "public.ecr.aws/aquasecurity/trivy-java-db")

	trivy := dag.Trivy(dagger.TrivyOpts{
		Container:          trivy_container,
		DatabaseRepository: "public.ecr.aws/aquasecurity/trivy-db",
	})

	return trivy.Container(container).
		Report("cyclonedx").
		WithName("cyclonedx.json")
}

// Scans the SBOM for vulnerabilities
func (m *PitcFlow) vulnscan(sbom *dagger.File) *dagger.File {
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
func (m *PitcFlow) publishToDeptrack(
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
		WithExec([]string{"curl", "-f", "-X", "POST", "-H", "'Content-Type: multipart/form-data'", "-H", fmt.Sprintf("'X-API-Key: %s'", apiKey), "-F", fmt.Sprintf("'project=%s'", projectUUID), "-F", "bom=@sbom.json", address}).
		Stdout(ctx)
}

// Publish the provided Container to the provided registry
func (m *PitcFlow) publish(
	ctx context.Context,
	// Container to publish
	container *dagger.Container,
	// Registry address to publish to - formatted as [host]/[user]/[repo]:[tag]
	registryAddress string,
	// Username of the registry's account
	//+optional
	//+default=""
	registryUsername string,
	// API key, password or token to authenticate to the registry
	//+optional
	registryPassword *dagger.Secret,
) (string, error) {
	if registryUsername != "" && registryPassword != nil {
		container = container.WithRegistryAuth(registryAddress, registryUsername, registryPassword)
	}
	return container.Publish(ctx, registryAddress)
}

// Sign the published image using cosign (keyless)
func (m *PitcFlow) sign(
	ctx context.Context,
	// Username of the registry's account
	registryUsername string,
	// API key, password or token to authenticate to the registry
	registryPassword *dagger.Secret,
	// Container image digest to sign
	digest string,
) (string, error) {
	return dag.Cosign().SignKeyless(ctx, digest, dagger.CosignSignKeylessOpts{RegistryUsername: registryUsername, RegistryPassword: registryPassword})
}

// Attests the SBOM using cosign (keyless)
func (m *PitcFlow) attest(
	ctx context.Context,
	// Username of the registry's account
	registryUsername string,
	// API key, password or token to authenticate to the registry
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

// Executes the common steps, does the error handling and returns a directory containing the results
func (m *PitcFlow) common(
	ctx context.Context,
	doLint bool,
	doSast bool,
	doTest bool,
	doIntTest bool,
	//+optional
	lintReports *dagger.Directory,
	//+optional
	securityReports *dagger.Directory,
	//+optional
	testReports *dagger.Directory,
	//+optional
	integrationTestReports *dagger.Directory,
	vulnerabilityScan *dagger.File,
	// registry username for publishing the container image
	//+optional
	registryUsername string,
	// registry password for publishing the container image
	//+optional
	registryPassword *dagger.Secret,
	// registry address registry/repository/image:tag
	//+optional
	registryAddress string,
	// deptrack address for publishing the SBOM https://deptrack.example.com/api/v1/bom
	//+optional
	dtAddress string,
	// deptrack project UUID
	//+optional
	dtProjectUUID string,
	// deptrack API key
	//+optional
	dtApiKey *dagger.Secret,
	// app container
	image *dagger.Container,
) (*dagger.Directory, error) {
	var err error
	// Get the names of the directories to fail on errors of the functions
	if doLint {
		_, err = lintReports.Name(ctx)
		if err != nil {
			return nil, err
		}
	}
	if doTest {
		_, err = testReports.Name(ctx)
		if err != nil {
			return nil, err
		}
	}
	if doIntTest {
		_, err = integrationTestReports.Name(ctx)
		if err != nil {
			return nil, err
		}
	}
	if doSast {
		_, err = securityReports.Name(ctx)
		if err != nil {
			return nil, err
		}
	}
	vulnerabilityScanName, err := vulnerabilityScan.Name(ctx)
	if err != nil {
		return nil, err
	}

	var sbom *dagger.File
	digest := ""
	var wg sync.WaitGroup
	// After linting, scanning and testing is done, we are ready to create the sbom and publish the image
	if registryAddress != "" && registryUsername != "" && registryPassword != nil {
		wg.Add(2)
		sbom = func() *dagger.File {
			defer wg.Done()
			return m.sbom(image)
		}()
		digest, err = func() (string, error) {
			defer wg.Done()
			return m.publish(ctx, image, registryAddress, registryUsername, registryPassword)
		}()
		// This Blocks the execution until its counter become 0
		wg.Wait()
	}

	// After publishing the image, we are ready to sign and attest and publish to deptrack
	if err == nil && (digest != "" || sbom != nil) {
		var dtErr error
		var signErr error
		var attErr error
		if sbom != nil && dtAddress != "" && dtProjectUUID != "" && dtApiKey != nil {
			wg.Add(1)
			_, dtErr = func() (string, error) {
				defer wg.Done()
				return m.publishToDeptrack(ctx, sbom, dtAddress, dtApiKey, dtProjectUUID)
			}()
		}
		if digest != "" && registryUsername != "" && registryPassword != nil {
			wg.Add(1)
			_, signErr = func() (string, error) {
				defer wg.Done()
				return m.sign(ctx, registryUsername, registryPassword, digest)
			}()
			if sbom != nil {
				wg.Add(1)
				_, attErr = func() (string, error) {
					defer wg.Done()
					return m.attest(ctx, registryUsername, registryPassword, digest, sbom, "cyclonedx")
				}()
			}
		}
		// This Blocks the execution until its counter become 0
		wg.Wait()

		if dtErr != nil || signErr != nil || attErr != nil {
			err = fmt.Errorf("one or more errors occurred: dtErr=%w, signErr=%w, attErr=%w", dtErr, signErr, attErr)
		}
	}

	sbomName := ""
	if sbom != nil {
		sbomName, err = sbom.Name(ctx)
	}

	errorString := ""
	if err != nil {
		errorString = err.Error()
	}

	result_container := dag.Container().WithWorkdir("/tmp/out")
	if doLint {
		result_container = result_container.WithDirectory("/tmp/out/lint/", lintReports)
	}
	if doSast {
		result_container = result_container.WithDirectory("/tmp/out/scan/", securityReports)
	}
	if doTest {
		result_container = result_container.WithDirectory("/tmp/out/unit-tests/", testReports)
	}
	if doIntTest {
		result_container = result_container.WithDirectory("/tmp/out/integration-tests/", integrationTestReports)
	}
	if sbom != nil {
		result_container = result_container.WithFile(fmt.Sprintf("/tmp/out/sbom/%s", sbomName), sbom)
	}

	return result_container.
		WithFile(fmt.Sprintf("/tmp/out/vuln/%s", vulnerabilityScanName), vulnerabilityScan).
		WithNewFile("/tmp/out/status.txt", errorString).
		Directory("."), err
}
