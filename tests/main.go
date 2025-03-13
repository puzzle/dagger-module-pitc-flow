// A generated module for Tests functions
//
// This module has been generated via dagger init and serves as a reference to
// basic module structure as you get started with Dagger.
//
// Two functions have been pre-created. You can modify, delete, or add to them,
// as needed. They demonstrate usage of arguments and return types using simple
// echo and grep commands. The functions can be called from the dagger CLI or
// from one of the SDKs.
//
// The first line in this comment block is a short description line and the
// rest is a long description with more detail on the module's purpose or usage,
// if appropriate. All modules should have a short description.

package main

import (
    "fmt"
)

type Tests struct{}

func (m *Tests) Sbom() error {
    container := dag.Container().From("alpine:latest")
	if nil == dag.GenericPipeline().Sbom(container) {
		return fmt.Errorf("should return sbom")
	}
    return nil
}

func (m *Tests) SbomBuild() error {
    directory := dag.CurrentModule().Source().Directory("./testdata")
    if nil == dag.GenericPipeline().SbomBuild(directory) {
        return fmt.Errorf("should build from dockerfile and return sbom")
    }
    return nil
}

func (m *Tests) Vulnscan() error {
    container := dag.Container().From("alpine:latest")
    sbom := dag.GenericPipeline().Sbom(container)
    if nil == dag.GenericPipeline().Vulnscan(sbom) {
        return fmt.Errorf("should return vulnerabilty scan report")
    }
    return nil
}