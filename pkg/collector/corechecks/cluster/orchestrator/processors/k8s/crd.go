// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build orchestrator
// +build orchestrator

package k8s

import (
	model "github.com/DataDog/agent-payload/v5/process"
	"github.com/DataDog/datadog-agent/pkg/collector/corechecks/cluster/orchestrator/processors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
)

// CRDHandlers implements the Handlers interface for Kubernetes ClusterRoles.
type CRDHandlers struct{}

// AfterMarshalling is a handler called after resource marshalling.
func (h *CRDHandlers) AfterMarshalling(ctx *processors.ProcessorContext, resource, resourceModel interface{}, yaml []byte) (skip bool) {
	return
}

// BeforeCacheCheck is a handler called before cache lookup.
func (h *CRDHandlers) BeforeCacheCheck(ctx *processors.ProcessorContext, resource, resourceModel interface{}) (skip bool) {
	return
}

// BeforeMarshalling is a handler called before resource marshalling.
func (h *CRDHandlers) BeforeMarshalling(ctx *processors.ProcessorContext, resource, resourceModel interface{}) (skip bool) {
	return
}

// BuildMessageBody is a handler called to build a message body out of a list of
// extracted resources.
func (h *CRDHandlers) BuildMessageBody(ctx *processors.ProcessorContext, resourceModels []interface{}, groupSize int) model.MessageBody {
	return nil
}

// ExtractResource is a handler called to extract the resource model out of a raw resource.
func (h *CRDHandlers) ExtractResource(ctx *processors.ProcessorContext, resource interface{}) (resourceModel interface{}) {
	r := resource.(*unstructured.Unstructured)
	return r
	//return k8sTransformers.ExtractCRD(r)
}

// ResourceList is a handler called to convert a list passed as a generic
// interface to a list of generic interfaces.
func (h *CRDHandlers) ResourceList(ctx *processors.ProcessorContext, list interface{}) (resources []interface{}) {
	resourceList := list.([]*unstructured.Unstructured)
	resources = make([]interface{}, 0, len(resourceList))

	for _, resource := range resourceList {
		resources = append(resources, resource)
	}

	return resources
}

// ResourceUID is a handler called to retrieve the resource UID.
func (h *CRDHandlers) ResourceUID(ctx *processors.ProcessorContext, resource, resourceModel interface{}) types.UID {
	return resource.(*unstructured.Unstructured).GetUID()
}

// ResourceVersion is a handler called to retrieve the resource version.
func (h *CRDHandlers) ResourceVersion(ctx *processors.ProcessorContext, resource, resourceModel interface{}) string {
	return resource.(*unstructured.Unstructured).GetResourceVersion()
}

// ScrubBeforeExtraction is a handler called to redact the raw resource before
// it is extracted as an internal resource model.
func (h *CRDHandlers) ScrubBeforeExtraction(ctx *processors.ProcessorContext, resource interface{}) {
}

// ScrubBeforeMarshalling is a handler called to redact the raw resource before
// it is marshalled to generate a manifest.
func (h *CRDHandlers) ScrubBeforeMarshalling(ctx *processors.ProcessorContext, resource interface{}) {
}