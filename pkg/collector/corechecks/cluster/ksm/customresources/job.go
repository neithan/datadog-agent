// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package customresources

import (
	"context"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/kube-state-metrics/v2/pkg/customresource"
	"k8s.io/kube-state-metrics/v2/pkg/metric"
	generator "k8s.io/kube-state-metrics/v2/pkg/metric_generator"
)

var descJobLabelsDefaultLabels = []string{"namespace", "job_name"}

// NewJobFactory returns a new Job metric family generator factory.
func NewJobFactory() customresource.RegistryFactory {
	return &jobFactory{}
}

type jobFactory struct{}

func (f *jobFactory) Name() string {
	return "jobs_extended"
}

// CreateClient is not implemented
func (f *jobFactory) CreateClient(cfg *rest.Config) (interface{}, error) {
	panic("not implemented")
}

func (f *jobFactory) MetricFamilyGenerators(allowAnnotationsList, allowLabelsList []string) []generator.FamilyGenerator {
	return []generator.FamilyGenerator{
		*generator.NewFamilyGenerator(
			"kube_job_duration",
			"Duration represents the time elapsed between the StartTime and CompletionTime of a Job",
			metric.Gauge,
			"",
			wrapJobFunc(func(j *batchv1.Job) *metric.Family {
				ms := []*metric.Metric{}

				if j.Status.StartTime != nil {
					start := j.Status.StartTime.Unix()
					end := time.Now().Unix()

					if j.Status.CompletionTime != nil {
						end = j.Status.CompletionTime.Unix()
					}

					ms = append(ms, &metric.Metric{
						Value: float64(end - start),
					})
				}

				return &metric.Family{
					Metrics: ms,
				}
			}),
		),
	}
}

func wrapJobFunc(f func(*batchv1.Job) *metric.Family) func(interface{}) *metric.Family {
	return func(obj interface{}) *metric.Family {
		cronJob := obj.(*batchv1.Job)

		metricFamily := f(cronJob)

		for _, m := range metricFamily.Metrics {
			m.LabelKeys, m.LabelValues = mergeKeyValues(descJobLabelsDefaultLabels, []string{cronJob.Namespace, cronJob.Name}, m.LabelKeys, m.LabelValues)
		}

		return metricFamily
	}
}

func (f *jobFactory) ExpectedType() interface{} {
	return &batchv1.Job{}
}

func (f *jobFactory) ListWatch(customResourceClient interface{}, ns string, fieldSelector string) cache.ListerWatcher {
	client := customResourceClient.(kubernetes.Interface)
	return &cache.ListWatch{
		ListFunc: func(opts metav1.ListOptions) (runtime.Object, error) {
			opts.FieldSelector = fieldSelector
			return client.BatchV1().Jobs(ns).List(context.TODO(), opts)
		},
		WatchFunc: func(opts metav1.ListOptions) (watch.Interface, error) {
			opts.FieldSelector = fieldSelector
			return client.BatchV1().Jobs(ns).Watch(context.TODO(), opts)
		},
	}
}
