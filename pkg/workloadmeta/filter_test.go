// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package workloadmeta

import "testing"

const (
	fooSource = "foo"
	barSource = "bar"
)

func TestFilterMatch(t *testing.T) {
	ev := CollectorEvent{
		Source: fooSource,
		Entity: EntityID{
			Kind: KindContainer,
		},
	}

	tests := []struct {
		name     string
		filter   *Filter
		event    CollectorEvent
		expected bool
	}{
		{
			name:     "nil filter",
			filter:   nil,
			event:    ev,
			expected: true,
		},

		{
			name: "matching single kind",
			filter: NewFilter(
				[]Kind{KindContainer},
				SourceAll,
			),
			event:    ev,
			expected: true,
		},
		{
			name: "matching one of kinds",
			filter: NewFilter(
				[]Kind{KindContainer, KindKubernetesPod},
				SourceAll,
			),
			event:    ev,
			expected: true,
		},
		{
			name: "matching no kind",
			filter: NewFilter(
				[]Kind{KindKubernetesPod},
				SourceAll,
			),
			event:    ev,
			expected: false,
		},

		{
			name: "matching source",
			filter: NewFilter(
				nil,
				fooSource,
			),
			event:    ev,
			expected: true,
		},
		{
			name: "matching no source",
			filter: NewFilter(
				nil,
				barSource,
			),
			event:    ev,
			expected: false,
		},

		{
			name: "matching source but not kind",
			filter: NewFilter(
				[]Kind{KindKubernetesPod},
				fooSource,
			),
			event:    ev,
			expected: false,
		},
		{
			name: "matching kind but not source",
			filter: NewFilter(
				[]Kind{KindContainer},
				barSource,
			),
			event:    ev,
			expected: false,
		},
		{
			name: "matching both kind and source",
			filter: NewFilter(
				[]Kind{KindContainer},
				fooSource,
			),
			event:    ev,
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := tt.filter.Match(tt.event)
			if actual != tt.expected {
				t.Errorf("expected filter.Match() to be %t, got %t instead", tt.expected, actual)
			}
		})
	}
}