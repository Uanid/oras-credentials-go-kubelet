package oras_credentials_go_kubelet

import (
	"context"
	"errors"
	"net/url"
	"sort"
	"strings"

	"github.com/pubg/oras-credentials-go-kubelet/credentialprovider"
	"github.com/pubg/oras-credentials-go-kubelet/credentialprovider/plugin"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"
	"oras.land/oras-go/v2/registry/remote/auth"
)

type credentialsProviderStore struct {
	binDir     string
	configFile string

	providers []credentialprovider.DockerConfigProvider
}

func newKubeletCredentialsProviderStore(configFile string, binDir string) (*credentialsProviderStore, error) {
	providers, err := plugin.NewCredentialProviderPlugins(configFile, binDir)
	if err != nil {
		return nil, err
	}

	return &credentialsProviderStore{binDir: binDir, configFile: configFile, providers: providers}, nil
}

func (ks *credentialsProviderStore) Get(ctx context.Context, serverAddress string) (auth.Credential, error) {
	for _, provider := range ks.providers {
		if !provider.Enabled() {
			continue
		}

		dockerConfig := provider.Provide(serverAddress)
		if dockerConfig == nil {
			continue
		}

		dockerEntry, err := ks.selectTopPriorityDockerEntry(dockerConfig)
		if err != nil {
			return auth.EmptyCredential, err
		}

		return auth.Credential{
			Username: dockerEntry.Username,
			Password: dockerEntry.Password,
		}, nil
	}
	return auth.EmptyCredential, nil
}

func (ks *credentialsProviderStore) selectTopPriorityDockerEntry(dockerConfig credentialprovider.DockerConfig) (credentialprovider.DockerConfigEntry, error) {
	var orderedIndex []string
	normalizedMap := map[string]credentialprovider.DockerConfigEntry{}

	for matchImage, authConfig := range dockerConfig {
		value := matchImage
		if !strings.HasPrefix(value, "https://") && !strings.HasPrefix(value, "http://") {
			value = "https://" + value
		}
		parsed, err := url.Parse(value)
		if err != nil {
			klog.Errorf("Entry %q in dockercfg invalid (%v), ignoring", matchImage, err)
			continue
		}

		// The docker client allows exact matches:
		//    foo.bar.com/namespace
		// Or hostname matches:
		//    foo.bar.com
		// It also considers /v2/  and /v1/ equivalent to the hostname
		// See ResolveAuthConfig in docker/registry/auth.go.
		effectivePath := parsed.Path
		if strings.HasPrefix(effectivePath, "/v2/") || strings.HasPrefix(effectivePath, "/v1/") {
			effectivePath = effectivePath[3:]
		}
		var key string
		if (len(effectivePath) > 0) && (effectivePath != "/") {
			key = parsed.Host + effectivePath
		} else {
			key = parsed.Host
		}
		orderedIndex = append(orderedIndex, key)
		normalizedMap[key] = authConfig
	}

	eliminateDupes := sets.NewString(orderedIndex...)
	orderedIndex = eliminateDupes.List()

	// Update the index used to identify which credentials to use for a given
	// image. The index is reverse-sorted so more specific paths are matched
	// first. For example, if for the given image "gcr.io/etcd-development/etcd",
	// credentials for "quay.io/coreos" should match before "quay.io".
	sort.Sort(sort.Reverse(sort.StringSlice(orderedIndex)))

	if len(orderedIndex) == 0 {
		return credentialprovider.DockerConfigEntry{}, errors.New("no docker config entry found")
	}

	return normalizedMap[orderedIndex[0]], nil
}

func (ks *credentialsProviderStore) Put(ctx context.Context, serverAddress string, cred auth.Credential) error {
	return errors.New("putting credentials is disabled on Kubelet CredentialsProviderStore")
}

func (ks *credentialsProviderStore) Delete(ctx context.Context, serverAddress string) error {
	return errors.New("deleting credentials is disabled on Kubelet CredentialsProviderStore")
}
