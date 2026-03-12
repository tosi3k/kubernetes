/*
Copyright 2025 The Kubernetes Authors.

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

package workload

import (
	"context"

	"k8s.io/apimachinery/pkg/api/operation"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/registry/rest"
	"k8s.io/apiserver/pkg/storage/names"
	"k8s.io/apiserver/pkg/util/feature"
	"k8s.io/kubernetes/pkg/api/legacyscheme"
	"k8s.io/kubernetes/pkg/apis/scheduling"
	"k8s.io/kubernetes/pkg/apis/scheduling/validation"
	"k8s.io/kubernetes/pkg/features"
)

// workloadStrategy implements behavior for Workload objects.
type workloadStrategy struct {
	runtime.ObjectTyper
	names.NameGenerator
}

// Strategy is the default logic that applies when creating and updating Workload objects.
var Strategy = workloadStrategy{legacyscheme.Scheme, names.SimpleNameGenerator}

func (workloadStrategy) NamespaceScoped() bool {
	return true
}

func (workloadStrategy) PrepareForCreate(ctx context.Context, obj runtime.Object) {
	workload := obj.(*scheduling.Workload)
	dropDisabledWorkloadFields(workload, nil)
}

func (workloadStrategy) Validate(ctx context.Context, obj runtime.Object) field.ErrorList {
	workloadScheduling := obj.(*scheduling.Workload)
	allErrs := validation.ValidateWorkload(workloadScheduling)
	var opts []string
	if feature.DefaultFeatureGate.Enabled(features.WorkloadAwarePreemption) {
		opts = append(opts, string(features.WorkloadAwarePreemption))
	}
	return rest.ValidateDeclarativelyWithMigrationChecks(ctx, legacyscheme.Scheme, obj, nil, allErrs, operation.Create, rest.WithDeclarativeEnforcement(), rest.WithOptions(opts))
}

func (workloadStrategy) WarningsOnCreate(ctx context.Context, obj runtime.Object) []string {
	return nil
}

func (workloadStrategy) Canonicalize(obj runtime.Object) {}

func (workloadStrategy) AllowCreateOnUpdate() bool {
	return false
}

func (workloadStrategy) PrepareForUpdate(ctx context.Context, obj, old runtime.Object) {
	newWorkload := obj.(*scheduling.Workload)
	oldWorkload := old.(*scheduling.Workload)
	dropDisabledWorkloadFields(newWorkload, oldWorkload)
}

func (workloadStrategy) ValidateUpdate(ctx context.Context, obj, old runtime.Object) field.ErrorList {
	allErrs := validation.ValidateWorkloadUpdate(obj.(*scheduling.Workload), old.(*scheduling.Workload))
	var opts []string
	if feature.DefaultFeatureGate.Enabled(features.WorkloadAwarePreemption) {
		opts = append(opts, string(features.WorkloadAwarePreemption))
	}
	return rest.ValidateDeclarativelyWithMigrationChecks(ctx, legacyscheme.Scheme, obj, old, allErrs, operation.Update, rest.WithDeclarativeEnforcement(), rest.WithOptions(opts))
}

func (workloadStrategy) WarningsOnUpdate(ctx context.Context, obj, old runtime.Object) []string {
	return nil
}

func (workloadStrategy) AllowUnconditionalUpdate() bool {
	return true
}

// dropDisabledWorkloadFields removes fields which are covered by a feature gate.
func dropDisabledWorkloadFields(workload, oldWorkload *scheduling.Workload) {
	var workloadSpec, oldWorkloadSpec *scheduling.WorkloadSpec
	if workload != nil {
		workloadSpec = &workload.Spec
	}
	if oldWorkload != nil {
		oldWorkloadSpec = &oldWorkload.Spec
	}
	dropDisabledWorkloadSpecFields(workloadSpec, oldWorkloadSpec)
}

func dropDisabledWorkloadSpecFields(workloadSpec, oldWorkloadSpec *scheduling.WorkloadSpec) {
	dropDisabledDisruptionModeFields(workloadSpec, oldWorkloadSpec)
	dropDisabledPriorityClassNameFields(workloadSpec, oldWorkloadSpec)
	dropDisabledPriorityFields(workloadSpec, oldWorkloadSpec)
}

// dropDisabledDisruptionModeField removes the DisruptionMode fields unless it is
// already used in the old Workload spec.
func dropDisabledDisruptionModeFields(workloadSpec, oldWorkloadSpec *scheduling.WorkloadSpec) {
	if feature.DefaultFeatureGate.Enabled(features.WorkloadAwarePreemption) || disruptionModeInUse(oldWorkloadSpec) {
		// No need to drop anything.
		return
	}
	for i := range workloadSpec.PodGroupTemplates {
		template := &workloadSpec.PodGroupTemplates[i]
		template.DisruptionMode = nil
	}
}

// dropDisabledPriorityClassNameField removes the PriorityClassName fields unless
// it is already used in the old Workload spec.
func dropDisabledPriorityClassNameFields(workloadSpec, oldWorkloadSpec *scheduling.WorkloadSpec) {
	if feature.DefaultFeatureGate.Enabled(features.WorkloadAwarePreemption) || priorityClassNameInUse(oldWorkloadSpec) {
		// No need to drop anything.
		return
	}
	for i := range workloadSpec.PodGroupTemplates {
		template := &workloadSpec.PodGroupTemplates[i]
		template.PriorityClassName = ""
	}
}

// dropDisabledPriorityField removes the Priority fields unless it is already used
// in the old Workload spec.
func dropDisabledPriorityFields(workloadSpec, oldWorkloadSpec *scheduling.WorkloadSpec) {
	if feature.DefaultFeatureGate.Enabled(features.WorkloadAwarePreemption) || priorityInUse(oldWorkloadSpec) {
		// No need to drop anything.
		return
	}
	for i := range workloadSpec.PodGroupTemplates {
		template := &workloadSpec.PodGroupTemplates[i]
		template.Priority = nil
	}
}

func disruptionModeInUse(workloadSpec *scheduling.WorkloadSpec) bool {
	if workloadSpec == nil {
		return false
	}
	for _, template := range workloadSpec.PodGroupTemplates {
		if template.DisruptionMode != nil {
			return true
		}
	}
	return false
}

func priorityClassNameInUse(workloadSpec *scheduling.WorkloadSpec) bool {
	if workloadSpec == nil {
		return false
	}
	for _, template := range workloadSpec.PodGroupTemplates {
		if template.PriorityClassName != "" {
			return true
		}
	}
	return false
}

func priorityInUse(workloadSpec *scheduling.WorkloadSpec) bool {
	if workloadSpec == nil {
		return false
	}
	for _, template := range workloadSpec.PodGroupTemplates {
		if template.Priority != nil {
			return true
		}
	}
	return false
}
