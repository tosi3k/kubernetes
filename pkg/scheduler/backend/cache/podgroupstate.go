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

package cache

import (
	"maps"
	"sync"
	"sync/atomic"

	v1 "k8s.io/api/core/v1"
	schedulingv1alpha3 "k8s.io/api/scheduling/v1alpha3"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"
)

var generation atomic.Int64

// nextPodGroupGeneration increments generation numbers monotonically for a pod group state (instead of per-instance increment)
// to prevent generation reset or collision when a pod group is deleted and recreated with the same name.
func nextPodGroupGeneration() int64 {
	return generation.Add(1)
}

// podGroupKey uniquely identifies a specific instance of a PodGroup.
type podGroupKey struct {
	name      string
	namespace string
}

func (pgk podGroupKey) GetName() string {
	return pgk.name
}

func (pgk podGroupKey) GetNamespace() string {
	return pgk.namespace
}

func (pgk podGroupKey) String() string {
	return pgk.namespace + "/" + pgk.name
}

var _ klog.KMetadata = &podGroupKey{}

func newPodGroupKey(namespace string, name string) podGroupKey {
	return podGroupKey{
		namespace: namespace,
		name:      name,
	}
}

func unpackPodGroupKey(key podGroupKey) (namespace, name string) {
	return key.namespace, key.name
}

// podGroupStateData holds data and functionality shared between podGroupState and podGroupStateSnapshot.
// Note that the podGroup field is populated from the observed PodGroup API object,
// while other fields are populated from observed Pod objects. This means podGroupStateData
// can exist without a corresponding PodGroup API object as long as at least one
// Pod references it.
type podGroupStateData struct {
	// generation gets bumped whenever the data is changed.
	// It's used to detect changes and avoid unnecessary cloning when taking a snapshot.
	generation int64
	// allPods tracks all pods belonging to the group that are known to the scheduler.
	allPods map[types.UID]*v1.Pod
	// unscheduledPods tracks all pods that are unscheduled for this group,
	// i.e., are neither assumed nor assigned.
	unscheduledPods sets.Set[types.UID]
	// assumedPods tracks pods that have reached the Reserve stage and are waiting
	// for the rest of the gang to arrive before being allowed to bind.
	assumedPods map[types.UID]*v1.Pod
	// assignedPods tracks all pods belonging to the group that are assigned (bound).
	assignedPods sets.Set[types.UID]
	// podGroup is the cached API object of the PodGroup.
	podGroup *schedulingv1alpha3.PodGroup
	// parent references the parent composite pod group.
	parent *podGroupKey
}

func newPodGroupStateData() podGroupStateData {
	return podGroupStateData{
		allPods:         make(map[types.UID]*v1.Pod),
		unscheduledPods: sets.New[types.UID](),
		assumedPods:     make(map[types.UID]*v1.Pod),
		assignedPods:    sets.New[types.UID](),
	}
}

// addPod adds the pod to this group.
func (d *podGroupStateData) addPod(pod *v1.Pod) {
	d.generation = nextPodGroupGeneration()
	d.allPods[pod.UID] = pod
	if pod.Spec.NodeName != "" {
		d.assignedPods.Insert(pod.UID)
		d.unscheduledPods.Delete(pod.UID)
		delete(d.assumedPods, pod.UID)
	} else {
		d.unscheduledPods.Insert(pod.UID)
	}
}

// updatePod updates the pod in this group.
func (d *podGroupStateData) updatePod(oldPod, newPod *v1.Pod) {
	d.generation = nextPodGroupGeneration()
	d.allPods[newPod.UID] = newPod
	if oldPod.Spec.NodeName == "" && newPod.Spec.NodeName != "" {
		d.assignedPods.Insert(newPod.UID)
		d.unscheduledPods.Delete(newPod.UID)
		delete(d.assumedPods, newPod.UID)
	}
}

// deletePod removes the pod from this pod group state.
func (d *podGroupStateData) deletePod(podUID types.UID) {
	d.generation = nextPodGroupGeneration()
	delete(d.allPods, podUID)
	d.unscheduledPods.Delete(podUID)
	delete(d.assumedPods, podUID)
	d.assignedPods.Delete(podUID)
}

// assumePod marks a pod as assumed within the pod group state.
func (d *podGroupStateData) assumePod(pod *v1.Pod) {
	storedPod, ok := d.allPods[pod.UID]
	if !ok {
		return
	}
	d.generation = nextPodGroupGeneration()
	if storedPod.Spec.NodeName != "" {
		d.assignedPods.Insert(pod.UID)
	} else {
		d.assumedPods[pod.UID] = pod
	}
	d.unscheduledPods.Delete(pod.UID)
}

// forgetPod moves a pod back from the assumed state to unscheduled within the pod group state.
func (d *podGroupStateData) forgetPod(podUID types.UID) {
	pod := d.allPods[podUID]
	if pod == nil {
		return
	}
	d.generation = nextPodGroupGeneration()
	delete(d.assumedPods, podUID)
	if pod.Spec.NodeName != "" {
		d.assignedPods.Insert(podUID)
	} else {
		d.unscheduledPods.Insert(podUID)
	}
}

// scheduledPods returns the pods that are either assumed or assigned for this pod group.
func (d *podGroupStateData) scheduledPods() []*v1.Pod {
	scheduledPods := make([]*v1.Pod, 0, len(d.assignedPods)+len(d.assumedPods))
	for uid := range d.assignedPods {
		scheduledPods = append(scheduledPods, d.allPods[uid])
	}
	for _, pod := range d.assumedPods {
		scheduledPods = append(scheduledPods, pod)
	}
	return scheduledPods
}

// empty returns true when the pod group state contains no pods.
func (d *podGroupStateData) empty() bool {
	return len(d.allPods) == 0 && d.podGroup == nil
}

// allPodsCount returns the number of all pods known to the scheduler for this group.
func (d *podGroupStateData) allPodsCount() int {
	return len(d.allPods)
}

// scheduledPodsCount returns the number of pods for this group that are either assumed or assigned.
func (d *podGroupStateData) scheduledPodsCount() int {
	return len(d.assumedPods) + len(d.assignedPods)
}

// clone returns a clone of the pod group state data.
func (d *podGroupStateData) clone() podGroupStateData {
	var parentCopy *podGroupKey
	if d.parent != nil {
		p := *d.parent
		parentCopy = &p
	}
	return podGroupStateData{
		generation:      d.generation,
		allPods:         maps.Clone(d.allPods),
		unscheduledPods: d.unscheduledPods.Clone(),
		assumedPods:     maps.Clone(d.assumedPods),
		assignedPods:    d.assignedPods.Clone(),
		podGroup:        d.podGroup,
		parent:          parentCopy,
	}
}

// setPodGroup sets the PodGroup object.
func (d *podGroupStateData) setPodGroup(podGroup *schedulingv1alpha3.PodGroup) {
	d.generation = nextPodGroupGeneration()
	d.podGroup = podGroup
}

// removePodGroup removes the PodGroup object.
func (d *podGroupStateData) removePodGroup() {
	d.generation = nextPodGroupGeneration()
	d.podGroup = nil
}

// unscheduledPodsMap returns all unscheduled pods for this pod group.
func (d *podGroupStateData) unscheduledPodsMap() map[string]*v1.Pod {
	result := make(map[string]*v1.Pod, len(d.unscheduledPods))
	for podUID := range d.unscheduledPods {
		pod := d.allPods[podUID]
		result[pod.Name] = pod
	}
	return result
}

// getParent returns the parent composite pod group name, if any.
// This always refers to a composite pod group.
func (d *podGroupStateData) getParent() (string, bool) {
	if d.parent == nil {
		return "", false
	}
	return d.parent.name, true
}

// setParent sets the parent composite pod group.
// This always refers to a composite pod group.
func (d *podGroupStateData) setParent(parent *podGroupKey) {
	d.generation = nextPodGroupGeneration()
	d.parent = parent
}

// removeParent removes the parent composite pod group.
// This always refers to a composite pod group.
func (d *podGroupStateData) removeParent() {
	d.generation = nextPodGroupGeneration()
	d.parent = nil
}

type compositePodGroupStateData struct {
	generation        int64
	compositePodGroup *schedulingv1alpha3.CompositePodGroup
	parent            *podGroupKey
	childrenCPGs      sets.Set[podGroupKey]
	childrenPGs       sets.Set[podGroupKey]
}

func newCompositePodGroupStateData() compositePodGroupStateData {
	return compositePodGroupStateData{
		childrenCPGs: make(sets.Set[podGroupKey]),
		childrenPGs:  make(sets.Set[podGroupKey]),
	}
}

func (d *compositePodGroupStateData) clone() compositePodGroupStateData {
	var parentCopy *podGroupKey
	if d.parent != nil {
		p := *d.parent
		parentCopy = &p
	}
	var childrenCPGsCopy sets.Set[podGroupKey]
	if d.childrenCPGs != nil {
		childrenCPGsCopy = d.childrenCPGs.Clone()
	}
	var childrenPGsCopy sets.Set[podGroupKey]
	if d.childrenPGs != nil {
		childrenPGsCopy = d.childrenPGs.Clone()
	}
	return compositePodGroupStateData{
		generation:        d.generation,
		compositePodGroup: d.compositePodGroup,
		parent:            parentCopy,
		childrenCPGs:      childrenCPGsCopy,
		childrenPGs:       childrenPGsCopy,
	}
}

// empty returns true when the composite pod group state contains no composite pod group.
func (d *compositePodGroupStateData) empty() bool {
	return d.compositePodGroup == nil && len(d.childrenCPGs) == 0 && len(d.childrenPGs) == 0
}

func (d *compositePodGroupStateData) setCompositePodGroup(compositePodGroup *schedulingv1alpha3.CompositePodGroup) {
	d.generation = nextPodGroupGeneration()
	d.compositePodGroup = compositePodGroup
}

func (d *compositePodGroupStateData) removeCompositePodGroup() {
	d.generation = nextPodGroupGeneration()
	d.compositePodGroup = nil
}

// getParent returns the parent composite pod group name, if any.
// This always refers to a composite pod group.
func (d *compositePodGroupStateData) getParent() (string, bool) {
	if d.parent == nil {
		return "", false
	}
	return d.parent.name, true
}

// setParent sets the parent composite pod group.
// This always refers to a composite pod group.
func (d *compositePodGroupStateData) setParent(parent *podGroupKey) {
	d.generation = nextPodGroupGeneration()
	d.parent = parent
}

// removeParent removes the parent composite pod group.
// This always refers to a composite pod group.
func (d *compositePodGroupStateData) removeParent() {
	d.generation = nextPodGroupGeneration()
	d.parent = nil
}

func (d *compositePodGroupStateData) addChildCPG(child *podGroupKey) {
	d.generation = nextPodGroupGeneration()
	d.childrenCPGs.Insert(*child)
}

func (d *compositePodGroupStateData) removeChildCPG(child *podGroupKey) {
	d.generation = nextPodGroupGeneration()
	d.childrenCPGs.Delete(*child)
}

func (d *compositePodGroupStateData) getChildrenCPGs() []string {
	var children []string
	for child := range d.childrenCPGs {
		children = append(children, child.String())
	}
	return children
}

func (d *compositePodGroupStateData) addChildPG(child *podGroupKey) {
	d.generation = nextPodGroupGeneration()
	d.childrenPGs.Insert(*child)
}

func (d *compositePodGroupStateData) removeChildPG(child *podGroupKey) {
	d.generation = nextPodGroupGeneration()
	d.childrenPGs.Delete(*child)
}

func (d *compositePodGroupStateData) getChildrenPGs() []string {
	var children []string
	for child := range d.childrenPGs {
		children = append(children, child.String())
	}
	return children
}

// podGroupState holds the runtime state of a pod group.
type podGroupState struct {
	lock sync.RWMutex
	podGroupStateData
}

func newPodGroupState() *podGroupState {
	return &podGroupState{podGroupStateData: newPodGroupStateData()}
}

func (pgs *podGroupState) snapshot() *podGroupStateSnapshot {
	return &podGroupStateSnapshot{podGroupStateData: pgs.podGroupStateData.clone()}
}

func (pgs *podGroupState) empty() bool {
	pgs.lock.RLock()
	defer pgs.lock.RUnlock()
	return pgs.podGroupStateData.empty()
}

func (pgs *podGroupState) addPod(pod *v1.Pod) {
	pgs.lock.Lock()
	defer pgs.lock.Unlock()
	pgs.podGroupStateData.addPod(pod)
}

func (pgs *podGroupState) updatePod(oldPod, newPod *v1.Pod) {
	pgs.lock.Lock()
	defer pgs.lock.Unlock()
	pgs.podGroupStateData.updatePod(oldPod, newPod)
}

func (pgs *podGroupState) deletePod(podUID types.UID) {
	pgs.lock.Lock()
	defer pgs.lock.Unlock()
	pgs.podGroupStateData.deletePod(podUID)
}

func (pgs *podGroupState) assumePod(pod *v1.Pod) {
	pgs.lock.Lock()
	defer pgs.lock.Unlock()
	pgs.podGroupStateData.assumePod(pod)
}

func (pgs *podGroupState) forgetPod(podUID types.UID) {
	pgs.lock.Lock()
	defer pgs.lock.Unlock()
	pgs.podGroupStateData.forgetPod(podUID)
}

func (pgs *podGroupState) setPodGroup(podGroup *schedulingv1alpha3.PodGroup) {
	pgs.lock.Lock()
	defer pgs.lock.Unlock()
	pgs.podGroupStateData.setPodGroup(podGroup)
	pgs.podGroupStateData.generation = nextPodGroupGeneration()
}

func (pgs *podGroupState) removePodGroup() {
	pgs.lock.Lock()
	defer pgs.lock.Unlock()
	pgs.podGroupStateData.removePodGroup()
	pgs.podGroupStateData.generation = nextPodGroupGeneration()
}

func (pgs *podGroupState) AllPods() sets.Set[types.UID] {
	pgs.lock.RLock()
	defer pgs.lock.RUnlock()
	return sets.KeySet(pgs.podGroupStateData.allPods)
}

func (pgs *podGroupState) AllPodsCount() int {
	pgs.lock.RLock()
	defer pgs.lock.RUnlock()
	return pgs.podGroupStateData.allPodsCount()
}

func (pgs *podGroupState) UnscheduledPods() map[string]*v1.Pod {
	pgs.lock.RLock()
	defer pgs.lock.RUnlock()
	return pgs.podGroupStateData.unscheduledPodsMap()
}

func (pgs *podGroupState) AssumedPods() sets.Set[types.UID] {
	pgs.lock.RLock()
	defer pgs.lock.RUnlock()
	return sets.KeySet(pgs.podGroupStateData.assumedPods)
}

func (pgs *podGroupState) AssignedPods() sets.Set[types.UID] {
	pgs.lock.RLock()
	defer pgs.lock.RUnlock()
	return pgs.podGroupStateData.assignedPods.Clone()
}

func (pgs *podGroupState) ScheduledPods() []*v1.Pod {
	pgs.lock.RLock()
	defer pgs.lock.RUnlock()
	return pgs.podGroupStateData.scheduledPods()
}

func (pgs *podGroupState) ScheduledPodsCount() int {
	pgs.lock.RLock()
	defer pgs.lock.RUnlock()
	return pgs.podGroupStateData.scheduledPodsCount()
}

func (pgs *podGroupState) PodGroup() *schedulingv1alpha3.PodGroup {
	pgs.lock.RLock()
	defer pgs.lock.RUnlock()
	return pgs.podGroupStateData.podGroup
}

func (pgs *podGroupState) GetParent() (string, bool) {
	pgs.lock.RLock()
	defer pgs.lock.RUnlock()
	return pgs.podGroupStateData.getParent()
}

// compositePodGroupState holds the runtime state of a composite pod group.
type compositePodGroupState struct {
	lock sync.RWMutex
	compositePodGroupStateData
}

func newCompositePodGroupState() *compositePodGroupState {
	return &compositePodGroupState{compositePodGroupStateData: newCompositePodGroupStateData()}
}

func (cpgs *compositePodGroupState) snapshot() *compositePodGroupStateSnapshot {
	return &compositePodGroupStateSnapshot{compositePodGroupStateData: cpgs.compositePodGroupStateData.clone()}
}

func (cpgs *compositePodGroupState) empty() bool {
	cpgs.lock.RLock()
	defer cpgs.lock.RUnlock()
	return cpgs.compositePodGroupStateData.empty()
}

func (cpgs *compositePodGroupState) setCompositePodGroup(compositePodGroup *schedulingv1alpha3.CompositePodGroup) {
	cpgs.lock.Lock()
	defer cpgs.lock.Unlock()
	cpgs.compositePodGroupStateData.setCompositePodGroup(compositePodGroup)
}

func (cpgs *compositePodGroupState) removeCompositePodGroup() {
	cpgs.lock.Lock()
	defer cpgs.lock.Unlock()
	cpgs.compositePodGroupStateData.removeCompositePodGroup()
}

func (cpgs *compositePodGroupState) CompositePodGroup() *schedulingv1alpha3.CompositePodGroup {
	cpgs.lock.RLock()
	defer cpgs.lock.RUnlock()
	return cpgs.compositePodGroupStateData.compositePodGroup
}

func (cpgs *compositePodGroupState) GetParent() (string, bool) {
	cpgs.lock.RLock()
	defer cpgs.lock.RUnlock()
	return cpgs.compositePodGroupStateData.getParent()
}

func (cpgs *compositePodGroupState) GetChildrenCPGs() []string {
	cpgs.lock.RLock()
	defer cpgs.lock.RUnlock()
	return cpgs.compositePodGroupStateData.getChildrenCPGs()
}

func (cpgs *compositePodGroupState) GetChildrenPGs() []string {
	cpgs.lock.RLock()
	defer cpgs.lock.RUnlock()
	return cpgs.compositePodGroupStateData.getChildrenPGs()
}

type podGroupStateSnapshot struct {
	podGroupStateData
}

func (s *podGroupStateSnapshot) assumePod(pod *v1.Pod) {
	s.podGroupStateData.assumePod(pod)
}

func (s *podGroupStateSnapshot) forgetPod(podUID types.UID) {
	s.podGroupStateData.forgetPod(podUID)
}

func (s *podGroupStateSnapshot) AllPods() sets.Set[types.UID] {
	return sets.KeySet(s.podGroupStateData.allPods)
}

func (s *podGroupStateSnapshot) UnscheduledPods() map[string]*v1.Pod {
	return s.podGroupStateData.unscheduledPodsMap()
}

func (s *podGroupStateSnapshot) AssumedPods() sets.Set[types.UID] {
	return sets.KeySet(s.podGroupStateData.assumedPods)
}

func (s *podGroupStateSnapshot) AssignedPods() sets.Set[types.UID] {
	return s.podGroupStateData.assignedPods
}

func (s *podGroupStateSnapshot) ScheduledPods() []*v1.Pod {
	return s.podGroupStateData.scheduledPods()
}

func (s *podGroupStateSnapshot) AllPodsCount() int {
	return s.podGroupStateData.allPodsCount()
}

func (s *podGroupStateSnapshot) ScheduledPodsCount() int {
	return s.podGroupStateData.scheduledPodsCount()
}

func (s *podGroupStateSnapshot) GetParent() (string, bool) {
	return s.podGroupStateData.getParent()
}

type compositePodGroupStateSnapshot struct {
	compositePodGroupStateData
}

func (s *compositePodGroupStateSnapshot) GetParent() (string, bool) {
	return s.compositePodGroupStateData.getParent()
}

func (s *compositePodGroupStateSnapshot) GetChildrenCPGs() []string {
	return s.compositePodGroupStateData.getChildrenCPGs()
}

func (s *compositePodGroupStateSnapshot) GetChildrenPGs() []string {
	return s.compositePodGroupStateData.getChildrenPGs()
}
