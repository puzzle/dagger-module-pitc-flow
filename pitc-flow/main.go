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

	return m.common(
		ctx,
		doLint,
		doSast,
		doTest,
		doIntTest,
		lintReports,
		securityReports,
		testReports,
		integrationTestReports,
		vulnerabilityScan,
		registryUsername,
		registryPassword,
		registryAddress,
		dtAddress,
		dtProjectUUID,
		dtApiKey,
		image,
	)
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

// Executes only the desired steps and returns a directory with the results (interface variant)
func (m *PitcFlow) IFlex(
	ctx context.Context,
	// source directory
	dir *dagger.Directory,
	// directory containing the lint results
	//+optional
	lintReports *dagger.Directory,
	// directory containing the security scan results
	//+optional
	securityReports *dagger.Directory,
	// diredctory containing the test results
	//+optional
	testReports *dagger.Directory,
	// directory containing the integration test results
	//+optional
	integrationTestReports *dagger.Directory,
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
	doLint := lintReports != nil
	doSast := securityReports != nil
	doTest := testReports != nil
	doIntTest := integrationTestReports != nil
	doBuild := appContainer == nil

	var wg sync.WaitGroup
	wg.Add(2)
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

	return m.common(
		ctx,
		doLint,
		doSast,
		doTest,
		doIntTest,
		lintReports,
		securityReports,
		testReports,
		integrationTestReports,
		vulnerabilityScan,
		registryUsername,
		registryPassword,
		registryAddress,
		dtAddress,
		dtProjectUUID,
		dtApiKey,
		image,
	)
}

// Executes all the steps and returns a directory with the results (interface variant)
func (m *PitcFlow) IFull(
	ctx context.Context,
	// source directory
	dir *dagger.Directory,
	// lint container
	lintReports *dagger.Directory,
	// directory containing the security scan results
	securityReports *dagger.Directory,
	// diredctory containing the test results
	testReports *dagger.Directory,
	// directory containing the integration test results
	integrationTestReports *dagger.Directory,
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
	return m.IFlex(
		ctx,
		dir,
		lintReports,
		securityReports,
		testReports,
		integrationTestReports,
		registryUsername,
		registryPassword,
		registryAddress,
		dtAddress,
		dtProjectUUID,
		dtApiKey,
		appContainer,
	)
}

// Executes all the CI steps (no publishing) and returns a directory with the results (interface variant)
func (m *PitcFlow) ICi(
	ctx context.Context,
	// source directory
	dir *dagger.Directory,
	// directory containing the lint results
	lintReports *dagger.Directory,
	// directory containing the security scan results
	securityReports *dagger.Directory,
	// diredctory containing the test results
	testReports *dagger.Directory,
	// directory containing the integration test results
	integrationTestReports *dagger.Directory,
	// pre built app container
	//+optional
	appContainer *dagger.Container,
) (*dagger.Directory, error) {
	return m.IFlex(
		ctx,
		dir,
		lintReports,
		securityReports,
		testReports,
		integrationTestReports,
		"",
		nil,
		"",
		"",
		"",
		nil,
		appContainer,
	)
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
