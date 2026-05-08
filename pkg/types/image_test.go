/*
Copyright © 2026 SUSE LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package types

import (
	"net/http"
	"testing"
)

func TestRegistryTransportTLSVerify(t *testing.T) {
	if got := registryTransport(true); got != http.DefaultTransport {
		t.Fatalf("expected verified transport to reuse http.DefaultTransport")
	}

	got, ok := registryTransport(false).(*http.Transport)
	if !ok {
		t.Fatalf("expected unverified transport to be *http.Transport")
	}
	if got == http.DefaultTransport {
		t.Fatalf("expected unverified transport to clone http.DefaultTransport")
	}
	if got.TLSClientConfig == nil {
		t.Fatalf("expected unverified transport to configure TLS")
	}
	if !got.TLSClientConfig.InsecureSkipVerify {
		t.Fatalf("expected unverified transport to skip TLS verification")
	}

	defaultTransport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return
	}
	if defaultTransport.TLSClientConfig != nil && defaultTransport.TLSClientConfig.InsecureSkipVerify {
		t.Fatalf("expected http.DefaultTransport to remain unchanged")
	}
}
