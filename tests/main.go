package main

import (
    "context"
    "dagger/tests/internal/dagger"
    "fmt"
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

    return p.Wait()
}

func (m *Tests) Sbom(_ context.Context) error {
    container := m.uniqContainer("alpine:latest", fmt.Sprintf("%d", time.Now().UnixNano())[0:10])
    if nil == dag.PitcFlow().Sbom(container) {
        return fmt.Errorf("should return sbom")
    }
    return nil
}

func (m *Tests) SbomBuild(_ context.Context) error {
    directory := dag.CurrentModule().Source().Directory("./testdata")
    if nil == dag.PitcFlow().SbomBuild(directory) {
        return fmt.Errorf("should build from dockerfile and return sbom")
    }
    return nil
}

func (m *Tests) Vulnscan(_ context.Context) error {
    container := m.uniqContainer("alpine:latest", fmt.Sprintf("%d", time.Now().UnixNano())[0:10])
    sbom := dag.PitcFlow().Sbom(container)
    if nil == dag.PitcFlow().Vulnscan(sbom) {
        return fmt.Errorf("should return vulnerabilty scan report")
    }
    return nil
}

func (m *Tests) Publish(ctx context.Context) error {
    container := m.uniqContainer("alpine:latest", fmt.Sprintf("%d", time.Now().UnixNano())[0:10])
    _, err := dag.PitcFlow().Publish(ctx, container, "ttl.sh/test/alpine:latest")
    if err != nil {
        return fmt.Errorf("should publish container to registry")
    }
    return nil
}

func (m *Tests) PublishWithCredentials(ctx context.Context) error {
    container := m.uniqContainer("alpine:latest", fmt.Sprintf("%d", time.Now().UnixNano())[0:10])
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

func (m *Tests) uniqContainer(image string, randomString string) *dagger.Container {
    return dag.Container().From(image).
        WithNewFile(
            fmt.Sprintf("/usr/share/%s",randomString),
            randomString,
        )
}