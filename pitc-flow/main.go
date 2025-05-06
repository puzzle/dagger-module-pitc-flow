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

// Executes only the desired steps and returns a directory with the results
func (m *PitcFlow) Flex(
	ctx context.Context,
	// source directory
	dir *dagger.Directory,
	// lint container
	//+optional
	lintContainer *dagger.Container,
	// lint report folder name e.g. "lint.json"
	//+optional
	lintReportDir string,
	// sast container
	//+optional
	sastContainer *dagger.Container,
	// security scan report folder name e.g. "/app/brakeman-output.tabs"
	//+optional
	sastReportDir string,
	// test container
	//+optional
	testContainer *dagger.Container,
	// test report folder name e.g. "/mnt/test/reports"
	//+optional
	testReportDir string,
	// integration test container
	//+optional
	integrationTestContainer *dagger.Container,
	// integration test report folder name e.g. "/mnt/int-test/reports"
	//+optional
	integrationTestReportDir string,
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
	// pre built app container
	//+optional
	appContainer *dagger.Container,
) (*dagger.Directory, error) {

	doLint := shouldRunStep(lintContainer, lintReportDir)
	doSast := shouldRunStep(sastContainer, sastReportDir)
	doTest := shouldRunStep(testContainer, testReportDir)
	doIntTest := shouldRunStep(integrationTestContainer, integrationTestReportDir)
	doBuild := appContainer == nil

	var wg sync.WaitGroup
	wg.Add(2)
	var lintReports *dagger.Directory
	var securityReports *dagger.Directory
	var testReports *dagger.Directory
	var integrationTestReports *dagger.Directory
	if doLint {
		wg.Add(1)
		lintReports = func() *dagger.Directory {
			defer wg.Done()
			return m.lint(lintContainer, lintReportDir)
		}()
	}
	if doSast {
		wg.Add(1)
		securityReports = func() *dagger.Directory {
			defer wg.Done()
			return m.sast(sastContainer, sastReportDir)
		}()
	}
	if doTest {
		wg.Add(1)
		testReports = func() *dagger.Directory {
			defer wg.Done()
			return m.test(testContainer, testReportDir)
		}()
	}
	if doIntTest {
		wg.Add(1)
		integrationTestReports = func() *dagger.Directory {
			defer wg.Done()
			return m.intTest(integrationTestContainer, integrationTestReportDir)
		}()
	}

	var vulnerabilityScan = func() *dagger.File {
		defer wg.Done()
		if doBuild {
			return m.vulnscan(m.sbomBuild(ctx, dir))
		}
		return m.vulnscan(m.sbom(appContainer))
	}()
	var image = func() *dagger.Container {
		defer wg.Done()
		if doBuild {
			return m.build(ctx, dir)
		}
		return appContainer
	}()
	// This Blocks the execution until its counter become 0
	wg.Wait()

	var err error
	// Get the names of the files to fail on errors of the functions
	if doLint {
		_, err = lintReports.Name(ctx)
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

// Executes all the steps and returns a directory with the results
func (m *PitcFlow) Full(
	ctx context.Context,
	// source directory
	dir *dagger.Directory,
	// lint container
	lintContainer *dagger.Container,
	// lint report folder name e.g. "lint.json"
	lintReportDir string,
	// sast container
	sastContainer *dagger.Container,
	// security scan report folder name e.g. "/app/brakeman-output.tabs"
	sastReportDir string,
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
	// pre built app container
	//+optional
	appContainer *dagger.Container,
) (*dagger.Directory, error) {
	return m.Flex(
		ctx,
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
		registryPassword,
		registryAddress,
		dtAddress,
		dtProjectUUID,
		dtApiKey,
		appContainer,
	)
}

// Executes all the CI steps (no publishing) and returns a directory with the results
func (m *PitcFlow) Ci(
	ctx context.Context,
	// source directory
	dir *dagger.Directory,
	// lint container
	lintContainer *dagger.Container,
	// lint report folder name e.g. "lint.json"
	lintReportDir string,
	// sast container
	sastContainer *dagger.Container,
	// security scan report folder name e.g. "/app/brakeman-output.tabs"
	sastReportDir string,
	// test container
	testContainer *dagger.Container,
	// test report folder name e.g. "/mnt/test/reports"
	testReportDir string,
	// integration test container
	integrationTestContainer *dagger.Container,
	// integration test report folder name e.g. "/mnt/int-test/reports"
	integrationTestReportDir string,
	// pre built app container
	//+optional
	appContainer *dagger.Container,
) (*dagger.Directory, error) {
	return m.Flex(
		ctx,
		dir,
		lintContainer,
		lintReportDir,
		sastContainer,
		sastReportDir,
		testContainer,
		testReportDir,
		integrationTestContainer,
		integrationTestReportDir,
		"",
		nil,
		"",
		"",
		"",
		nil,
		appContainer,
	)
}

func (m *PitcFlow) Cii(
	ctx context.Context,
	// source directory
	dir *dagger.Directory,
	// interface implementation
	face Face,
) (*dagger.Directory, error) {
	var wg sync.WaitGroup
	var lintReports *dagger.Directory
	var securityReports *dagger.Directory
	var testReports *dagger.Directory
	var integrationTestReports *dagger.Directory

	wg.Add(1)
	lintReports = func() *dagger.Directory {
		defer wg.Done()
		return face.Lint(dir, true)
	}()

	wg.Add(1)
	securityReports = func() *dagger.Directory {
		defer wg.Done()
		return face.Sast(dir)
	}()

	wg.Add(1)
	testReports = func() *dagger.Directory {
		defer wg.Done()
		return face.Test(dir)
	}()

	wg.Add(1)
	integrationTestReports = func() *dagger.Directory {
		defer wg.Done()
		return face.IntegrationTest(dir)
	}()

	wg.Add(1)
	var vulnerabilityScan = func() *dagger.File {
		defer wg.Done()
		return face.Vulnscan(m.sbomBuild(ctx, dir))
	}()
	// This Blocks the execution until its counter become 0
	wg.Wait()

	vulnerabilityScanName, err := vulnerabilityScan.Name(ctx)
	if err != nil {
		return nil, err
	}

	result_container := dag.Container().WithWorkdir("/tmp/out")

	result_container = result_container.WithDirectory("/tmp/out/lint/", lintReports)

	result_container = result_container.WithDirectory("/tmp/out/scan/", securityReports)

	result_container = result_container.WithDirectory("/tmp/out/unit-tests/", testReports)

	result_container = result_container.WithDirectory("/tmp/out/integration-tests/", integrationTestReports)

	errorString := ""
	if err != nil {
		errorString = err.Error()
	}

	return result_container.
		WithFile(fmt.Sprintf("/tmp/out/vuln/%s", vulnerabilityScanName), vulnerabilityScan).
		WithNewFile("/tmp/out/status.txt", errorString).
		Directory("."), err
}

// Verifies if the run was succesful and returns the error messages
func (m *PitcFlow) Verify(
	ctx context.Context,
	// status.txt file to be verified
	status *dagger.File,
) (string, error) {
	content, err := status.Contents(ctx)
	if err != nil {
		return "", err
	}
	if content != "" {
		return content, fmt.Errorf("%w", content)
	}
	return "", nil
}

func shouldRunStep(container *dagger.Container, report string) bool {
	return container != nil && report != ""
}
