// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf
// +build linux_bpf

package classifier

import (
	"testing"

	"github.com/DataDog/datadog-agent/pkg/network/config"
	"github.com/DataDog/datadog-agent/pkg/util/kernel"
	"github.com/stretchr/testify/require"
)

func TestClassifierCompile(t *testing.T) {
	if !rtcClassifierSupported(t) {
		t.Skip("Classifier Runtime compilation not supported on this kernel version")
	}
	cfg := config.New()
	cfg.BPFDebug = true
	_, err := getRuntimeCompiledClassifier(cfg)
	require.NoError(t, err)
}

func rtcClassifierSupported(t *testing.T) bool {
	currKernelVersion, err := kernel.HostVersion()
	require.NoError(t, err)
	return currKernelVersion >= kernel.VersionCode(4, 5, 0)
}
