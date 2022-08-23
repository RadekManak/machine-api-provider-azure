/*
Copyright The Kubernetes Authors.
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

package machineset

import (
	"context"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/go-logr/logr"
	machinev1 "github.com/openshift/api/machine/v1beta1"
	mapierrors "github.com/openshift/machine-api-operator/pkg/controller/machine"
	"github.com/openshift/machine-api-provider-azure/pkg/cloud/azure"
	"github.com/openshift/machine-api-provider-azure/pkg/cloud/azure/actuators"
	"github.com/openshift/machine-api-provider-azure/pkg/cloud/azure/services/resourceskus"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
)

const (
	// This exposes compute information based on the providerSpec input.
	// This is needed by the autoscaler to foresee upcoming capacity when scaling from zero.
	// https://github.com/openshift/enhancements/pull/186
	cpuKey    = "machine.openshift.io/vCPU"
	memoryKey = "machine.openshift.io/memoryMb"
	gpuKey    = "machine.openshift.io/GPU"
)

// Reconciler reconciles machineSets.
type Reconciler struct {
	Client client.Client
	Log    logr.Logger

	recorder     record.EventRecorder
	scheme       *runtime.Scheme
	resourceSkus azure.Service
}

// SetupWithManager creates a new controller for a manager.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager, options controller.Options) error {
	_, err := ctrl.NewControllerManagedBy(mgr).
		For(&machinev1.MachineSet{}).
		WithOptions(options).
		Build(r)

	if err != nil {
		return fmt.Errorf("failed setting up with a controller manager: %w", err)
	}

	r.recorder = mgr.GetEventRecorderFor("machineset-controller")
	r.scheme = mgr.GetScheme()
	return nil
}

// Reconcile implements controller runtime Reconciler interface.
func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := r.Log.WithValues("machineset", req.Name, "namespace", req.Namespace)
	logger.V(3).Info("Reconciling")

	machineSet := &machinev1.MachineSet{}
	if err := r.Client.Get(ctx, req.NamespacedName, machineSet); err != nil {
		if apierrors.IsNotFound(err) {
			// Object not found, return. Created objects are automatically garbage collected.
			// For additional cleanup logic use finalizers.
			return ctrl.Result{}, nil
		}
		// Error reading the object - requeue the request.
		return ctrl.Result{}, err
	}

	// Ignore deleted MachineSets, this can happen when foregroundDeletion
	// is enabled
	if !machineSet.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}
	originalMachineSetToPatch := client.MergeFrom(machineSet.DeepCopy())

	result, err := r.reconcile(machineSet)
	if err != nil {
		logger.Error(err, "Failed to reconcile MachineSet")
		r.recorder.Eventf(machineSet, corev1.EventTypeWarning, "ReconcileError", "%v", err)
		// we don't return here so we want to attempt to patch the machine regardless of an error.
	}

	if err := r.Client.Patch(ctx, machineSet, originalMachineSetToPatch); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to patch machineSet: %v", err)
	}

	if isInvalidConfigurationError(err) {
		// For situations where requeuing won't help we don't return error.
		// https://github.com/kubernetes-sigs/controller-runtime/issues/617
		return result, nil
	}

	return result, err
}

func isInvalidConfigurationError(err error) bool {
	switch t := err.(type) {
	case *mapierrors.MachineError:
		if t.Reason == machinev1.InvalidConfigurationMachineError {
			return true
		}
	}
	return false
}

func (r *Reconciler) reconcile(machineSet *machinev1.MachineSet) (ctrl.Result, error) {
	klog.Infof("%v: Reconciling MachineSet", machineSet.Name)
	sku, err := getSKU(r, machineSet)
	if err != nil {
		if strings.Contains(err.Error(), "not found in location") {
			// Print different error message when there is no failure, but SKU is not available.
			klog.Errorf("Unable to set scale from zero annotations: instance type unknown or unavailabe for this account or location: %v", err)
		} else {
			klog.Errorf("Unable to set scale from zero annotations: Azure list SKU request failed: %v", err)
		}

		// Returning no error to prevent further reconciliation, as user intervention is now required but emit an informational event
		r.recorder.Eventf(machineSet, corev1.EventTypeWarning, "FailedUpdate", "Failed to set autoscaling from zero annotations, instance type unknown or unavailable")

		return ctrl.Result{}, nil
	}

	updateMachineSetAnnotations(machineSet, sku)

	return ctrl.Result{}, nil
}

func getSKU(r *Reconciler, machineSet *machinev1.MachineSet) (resourceskus.SKU, error) {
	providerConfig, err := getproviderConfig(machineSet)
	if err != nil {
		return resourceskus.SKU{}, mapierrors.InvalidMachineConfiguration("failed to get providerConfig: %v", err)
	}

	params := actuators.MachineScopeParams{
		Machine: &machinev1.Machine{
			Spec: machineSet.Spec.Template.Spec,
		},
		CoreClient: r.Client,
	}

	machineScope, err := actuators.NewMachineScope(params)
	if err != nil {
		return resourceskus.SKU{}, err
	}

	if r.resourceSkus == nil {
		r.resourceSkus = resourceskus.NewService(machineScope)
	}

	skuSpec := resourceskus.Spec{
		Name:         providerConfig.VMSize,
		ResourceType: resourceskus.VirtualMachines,
	}
	skuI, err := r.resourceSkus.Get(context.Background(), skuSpec)

	if err != nil {
		return resourceskus.SKU{}, fmt.Errorf("could not find sku: %s", providerConfig.VMSize)
	}

	sku := skuI.(resourceskus.SKU)

	return sku, nil
}

func updateMachineSetAnnotations(machineSet *machinev1.MachineSet, sku resourceskus.SKU) error {
	if machineSet.Annotations == nil {
		machineSet.Annotations = make(map[string]string)
	}

	// TODO: get annotations keys from machine API
	// CPU
	cpuCap, ok := sku.GetCapability(resourceskus.VCPUs)
	if !ok {
		fmt.Printf("failed to get vCPUs from capabilities: %v", sku.Capabilities)
	}
	machineSet.Annotations[cpuKey] = cpuCap

	// Memory
	memoryCap, ok := sku.GetCapability(resourceskus.MemoryGB)
	if !ok {
		fmt.Printf("failed to get memoryGB from capabilities: %v", sku.Capabilities)
	}
	memoryCapFloatGB, err := strconv.ParseFloat(memoryCap, 64)
	if err != nil {
		fmt.Printf("failed to parse memoryGB: %v", err)
	}
	memoryCapFloatMB := memoryCapFloatGB * 1024
	memoryCapIntMb := int64(math.Round(memoryCapFloatMB))
	machineSet.Annotations[memoryKey] = strconv.FormatInt(memoryCapIntMb, 10)

	// GPU
	gpuCap, ok := sku.GetCapability(resourceskus.GPUs)
	if !ok {
		machineSet.Annotations[gpuKey] = "0"
	} else {
		machineSet.Annotations[gpuKey] = gpuCap
	}

	return nil
}

func getproviderConfig(machineSet *machinev1.MachineSet) (*machinev1.AzureMachineProviderSpec, error) {
	return actuators.MachineConfigFromProviderSpec(machineSet.Spec.Template.Spec.ProviderSpec)
}
