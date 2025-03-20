// PITCFlow - Pipeline Integrity, Trust & Compliance
//
// Secure and compliant software delivery with trust and integrity. 🚀
//
// This module contains ready to use pipelines.
// They build and deliver your software / project with security and compliance out of the box.

package main

import (
	"context"
	"dagger/pitc-flow/internal/dagger"
	"fmt"
	"sync"
)

type PitcFlow struct{}

// Returns a file containing the results of the lint command
func (m *PitcFlow) Lint(
	// Container to run the lint command
	container *dagger.Container,
	// Path to file containing lint results
	results string,
) *dagger.File {
	return container.File(results)
}

// Returns a directory containing the results of the test command
func (m *PitcFlow) Test(
	// Container to run the test command
	container *dagger.Container,
	// Path to directory containing test results
	results string,
) *dagger.Directory {
	return container.Directory(results)
}

// Returns a directory containing the results of the integration test command
func (m *PitcFlow) IntTest(
	// Container to run the integration test command
	container *dagger.Container,
	// Path to directory containing integration test results
	results string,
) *dagger.Directory {
	return container.Directory(results)
}

// Returns a file containing the results of the security scan
func (m *PitcFlow) Sast(
	// Container to run the security scan
	container *dagger.Container,
	// Path to file containing the results of the security scan
	results string,
) *dagger.File {
	return container.File(results)
}

// Returns a Container built from the Dockerfile in the provided Directory
func (m *PitcFlow) Build(_ context.Context, dir *dagger.Directory) *dagger.Container {
	return dag.Container().
		WithDirectory("/src", dir).
		WithWorkdir("/src").
		Directory("/src").
		DockerBuild()
}

// Builds the container and creates a SBOM for it
func (m *PitcFlow) SbomBuild(ctx context.Context, dir *dagger.Directory) *dagger.File {
	container := m.Build(ctx, dir)
	return m.Sbom(container)
}

// Creates a SBOM for the container
func (m *PitcFlow) Sbom(container *dagger.Container) *dagger.File {
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
func (m *PitcFlow) Vulnscan(sbom *dagger.File) *dagger.File {
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
func (m *PitcFlow) PublishToDeptrack(
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
func (m *PitcFlow) Publish(
	ctx context.Context,
	// Container to publish
	container *dagger.Container,
	// Registry address to publish to - formatted as [host]/[user]/[repo]:[tag]
	registryAddress string,
	// Username of the registry's account
	// +optional
	// +default=""
	registryUsername string,
	// API key, password or token to authenticate to the registry
	// +optional
	registryPassword *dagger.Secret,
) (string, error) {
	if registryUsername != "" && registryPassword != nil {
		container = container.WithRegistryAuth(registryAddress, registryUsername, registryPassword)
	}
	return container.Publish(ctx, registryAddress)
}

// Sign the published image using cosign (keyless)
func (m *PitcFlow) Sign(
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
func (m *PitcFlow) Attest(
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

// Executes only the desired steps and returns a directory with the results
func (m *PitcFlow) Flex(
	ctx context.Context,
	// source directory
	dir *dagger.Directory,
	// lint container
	// +optional
	lintContainer *dagger.Container,
	// lint report file name e.g. "lint.json"
	// +optional
	lintReport string,
	// sast container
	// +optional
	sastContainer *dagger.Container,
	// security scan report file name e.g. "/app/brakeman-output.tabs"
	// +optional
	sastReport string,
	// test container
	// +optional
	testContainer *dagger.Container,
	// test report folder name e.g. "/mnt/test/reports"
	// +optional
	testReportDir string,
	// integration test container
	// +optional
	integrationTestContainer *dagger.Container,
	// integration test report folder name e.g. "/mnt/int-test/reports"
	// +optional
	integrationTestReportDir string,
	// registry username for publishing the container image
	// +optional
	registryUsername string,
	// registry password for publishing the container image
	// +optional
	registryPassword *dagger.Secret,
	// registry address registry/repository/image:tag
	// +optional
	registryAddress string,
	// deptrack address for publishing the SBOM https://deptrack.example.com/api/v1/bom
	// +optional
	dtAddress string,
	// deptrack project UUID
	// +optional
	dtProjectUUID string,
	// deptrack API key
	// +optional
	dtApiKey *dagger.Secret,
) (*dagger.Directory, error) {

	prep := 2
	doLint := shouldRunStep(lintContainer, lintReport)
	doSast := shouldRunStep(sastContainer, sastReport)
	doTest := shouldRunStep(testContainer, testReportDir)
	doIntTest := shouldRunStep(integrationTestContainer, integrationTestReportDir)
	prep += countTrue(doLint, doSast, doTest, doIntTest)

	var wg sync.WaitGroup
	wg.Add(prep)

	var lintOutput *dagger.File
	var securityScan *dagger.File
	var testReports *dagger.Directory
	var integrationTestReports *dagger.Directory
	if doLint {
		lintOutput = func() *dagger.File {
			defer wg.Done()
			return m.Lint(lintContainer, lintReport)
		}()
	}
	if doSast {
		securityScan = func() *dagger.File {
			defer wg.Done()
			return m.Sast(sastContainer, sastReport)
		}()
	}
	if doTest {
		testReports = func() *dagger.Directory {
			defer wg.Done()
			return m.Test(testContainer, testReportDir)
		}()
	}
    if doIntTest {
        integrationTestReports = func() *dagger.Directory {
            defer wg.Done()
            return m.IntTest(integrationTestContainer, integrationTestReportDir)
        }()
    }

	var vulnerabilityScan = func() *dagger.File {
		defer wg.Done()
		return m.Vulnscan(m.SbomBuild(ctx, dir))
	}()
	var image = func() *dagger.Container {
		defer wg.Done()
		return m.Build(ctx, dir)
	}()
	// This Blocks the execution until its counter become 0
	wg.Wait()

	var err error
	lintOutputName := ""
	securityScanName := ""
	// Get the names of the files to fail on errors of the functions
	if doLint {
		lintOutputName, err = lintOutput.Name(ctx)
		if err != nil {
			return nil, err
		}
	}
	if doSast {
		securityScanName, err = securityScan.Name(ctx)
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
	// After linting, scanning and testing is done, we are ready to create the sbom and publish the image
	if registryAddress != "" && registryUsername != "" && registryPassword != nil {
		wg.Add(2)
		sbom = func() *dagger.File {
			defer wg.Done()
			return m.Sbom(image)
		}()
		digest, err = func() (string, error) {
			defer wg.Done()
			return m.Publish(ctx, image, registryAddress, registryUsername, registryPassword)
		}()
		// This Blocks the execution until its counter become 0
		wg.Wait()
	}

	var doPublishToDeptrack bool
	var doSign bool
	var doAttest bool
	// After publishing the image, we are ready to sign and attest and publish to deptrack
	if err == nil && (digest != "" || sbom != nil) {
		post := 0
		if sbom != nil && dtAddress != "" && dtProjectUUID != "" && dtApiKey != nil {
			doPublishToDeptrack = true
			post++
		}
		if digest != "" && registryUsername != "" && registryPassword != nil {
			doSign = true
			post++
			if sbom != nil {
				doAttest = true
				post++
			}
		}

		var dtErr error
		var signErr error
		var attErr error
		wg.Add(post)
		if doPublishToDeptrack {
			_, dtErr = func() (string, error) {
				defer wg.Done()
				return m.PublishToDeptrack(ctx, sbom, dtAddress, dtApiKey, dtProjectUUID)
			}()
		}
		if doSign {
			_, signErr = func() (string, error) {
				defer wg.Done()
				return m.Sign(ctx, registryUsername, registryPassword, digest)
			}()
		}
		if doAttest {
			_, attErr = func() (string, error) {
				defer wg.Done()
				return m.Attest(ctx, registryUsername, registryPassword, digest, sbom, "cyclonedx")
			}()
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
		result_container = result_container.WithFile(fmt.Sprintf("/tmp/out/lint/%s", lintOutputName), lintOutput)
	}
    if doSast {
        result_container = result_container.WithFile(fmt.Sprintf("/tmp/out/scan/%s", securityScanName), securityScan)
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

// Executes all the steps and returns a directory with the results
func (m *PitcFlow) Full(
	ctx context.Context,
	// source directory
	dir *dagger.Directory,
	// lint container
	lintContainer *dagger.Container,
	// lint report file name e.g. "lint.json"
	lintReport string,
	// sast container
	sastContainer *dagger.Container,
	// security scan report file name e.g. "/app/brakeman-output.tabs"
	sastReport string,
	// test container
	testContainer *dagger.Container,
	// test report folder name e.g. "/mnt/test/reports"
	testReportDir string,
	// integration test container
	integrationTestContainer *dagger.Container,
	// integration test report folder name e.g. "/mnt/int-test/reports"
	integrationTestReportDir string,
	// registry username for publishing the container image
	registryUsername string,
	// registry password for publishing the container image
	registryPassword *dagger.Secret,
	// registry address registry/repository/image:tag
	registryAddress string,
	// deptrack address for publishing the SBOM https://deptrack.example.com/api/v1/bom
	dtAddress string,
	// deptrack project UUID
	dtProjectUUID string,
	// deptrack API key
	dtApiKey *dagger.Secret,
) (*dagger.Directory, error) {
	return m.Flex(
		ctx,
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
		registryPassword,
		registryAddress,
		dtAddress,
		dtProjectUUID,
		dtApiKey,
	)
}

func shouldRunStep(container *dagger.Container, report string) bool {
	return container != nil && report != ""
}

func countTrue(bools ...bool) int {
	count := 0
	for _, b := range bools {
		if b {
			count++
		}
	}
	return count
}
