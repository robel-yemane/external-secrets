/*
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

package externalsecret

import (
	"context"
	"errors"
	"fmt"

	v1 "k8s.io/api/core/v1"
	apiextensions "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/restmapper"

	esv1beta1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1beta1"
	genv1alpha1 "github.com/external-secrets/external-secrets/apis/generators/v1alpha1"
	"github.com/external-secrets/external-secrets/pkg/controllers/secretstore"
	// Loading registered generators.
	_ "github.com/external-secrets/external-secrets/pkg/generator/register"
	// Loading registered providers.
	_ "github.com/external-secrets/external-secrets/pkg/provider/register"
	"github.com/external-secrets/external-secrets/pkg/utils"
)

// getProviderSecretData returns the provider's secret data with the provided ExternalSecret.
func (r *Reconciler) getProviderSecretData(ctx context.Context, externalSecret *esv1beta1.ExternalSecret) (map[string][]byte, error) {
	providerData := make(map[string][]byte)
	for i, remoteRef := range externalSecret.Spec.DataFrom {
		var secretMap map[string][]byte
		var err error

		if remoteRef.Find != nil {
			secretMap, err = r.handleFindAllSecrets(ctx, externalSecret, remoteRef, i)
		} else if remoteRef.Extract != nil {
			secretMap, err = r.handleExtractSecrets(ctx, externalSecret, remoteRef, i)
		} else if remoteRef.SourceRef != nil && (remoteRef.SourceRef.Generator != nil || remoteRef.SourceRef.GeneratorRef != nil) {
			secretMap, err = r.handleGenerateSecrets(ctx, externalSecret.Namespace, remoteRef, i)
		}
		if errors.Is(err, esv1beta1.NoSecretErr) && externalSecret.Spec.Target.DeletionPolicy != esv1beta1.DeletionPolicyRetain {
			r.recorder.Event(
				externalSecret,
				v1.EventTypeNormal,
				esv1beta1.ReasonDeleted,
				fmt.Sprintf("secret does not exist at provider using .dataFrom[%d]", i),
			)
			continue
		}
		if err != nil {
			return nil, err
		}
		providerData = utils.MergeByteMap(providerData, secretMap)
	}

	for i, secretRef := range externalSecret.Spec.Data {
		err := r.handleSecretData(ctx, i, *externalSecret, secretRef, providerData)
		if errors.Is(err, esv1beta1.NoSecretErr) && externalSecret.Spec.Target.DeletionPolicy != esv1beta1.DeletionPolicyRetain {
			r.recorder.Event(externalSecret, v1.EventTypeNormal, esv1beta1.ReasonDeleted, fmt.Sprintf("secret does not exist at provider using .data[%d] key=%s", i, secretRef.RemoteRef.Key))
			continue
		}
		if err != nil {
			return nil, err
		}
	}

	return providerData, nil
}

func (r *Reconciler) handleSecretData(ctx context.Context, i int, externalSecret esv1beta1.ExternalSecret, secretRef esv1beta1.ExternalSecretData, providerData map[string][]byte) error {
	client, err := r.getClientOrDefault(ctx, externalSecret.Spec.SecretStoreRef, externalSecret.Namespace, secretRef.SourceRef)
	if err != nil {
		return err
	}
	defer client.Close(ctx)
	secretData, err := client.GetSecret(ctx, secretRef.RemoteRef)
	if err != nil {
		return err
	}
	secretData, err = utils.Decode(secretRef.RemoteRef.DecodingStrategy, secretData)
	if err != nil {
		return fmt.Errorf(errDecode, "spec.data", i, err)
	}
	providerData[secretRef.SecretKey] = secretData
	return nil
}

func (r *Reconciler) handleGenerateSecrets(ctx context.Context, namespace string, remoteRef esv1beta1.ExternalSecretDataFromRemoteRef, i int) (map[string][]byte, error) {
	genDef, err := r.getGeneratorDefinition(ctx, namespace, remoteRef.SourceRef)
	if err != nil {
		return nil, err
	}
	gen, err := genv1alpha1.GetGenerator(genDef)
	if err != nil {
		return nil, err
	}
	secretMap, err := gen.Generate(ctx, genDef, r.Client, namespace)
	if err != nil {
		return nil, fmt.Errorf(errGenerate, i, err)
	}
	secretMap, err = utils.RewriteMap(remoteRef.Rewrite, secretMap)
	if err != nil {
		return nil, fmt.Errorf(errRewrite, i, err)
	}
	if !utils.ValidateKeys(secretMap) {
		return nil, fmt.Errorf(errInvalidKeys, "generator", i)
	}
	return secretMap, err
}

// getGeneratorDefinition returns the generator JSON for a given sourceRef
// when a generator is defined inline it returns sourceRef.Generator straight away
// when it uses a generatorRef it fetches the resource and returns the JSON.
func (r *Reconciler) getGeneratorDefinition(ctx context.Context, namespace string, sourceRef *esv1beta1.SourceRef) (*apiextensions.JSON, error) {
	if sourceRef.Generator != nil {
		return sourceRef.Generator, nil
	}
	// client-go dynamic client needs a GVR to fetch the resource
	// But we only have the GVK in our generatorRef.
	//
	// TODO: there is no need to discover the GroupVersionResource
	//       this should be cached.
	c := discovery.NewDiscoveryClientForConfigOrDie(r.RestConfig)
	groupResources, err := restmapper.GetAPIGroupResources(c)
	if err != nil {
		return nil, err
	}

	gv, err := schema.ParseGroupVersion(sourceRef.GeneratorRef.APIVersion)
	if err != nil {
		return nil, err
	}
	mapper := restmapper.NewDiscoveryRESTMapper(groupResources)
	mapping, err := mapper.RESTMapping(schema.GroupKind{
		Group: gv.Group,
		Kind:  sourceRef.GeneratorRef.Kind,
	})
	if err != nil {
		return nil, err
	}
	d, err := dynamic.NewForConfig(r.RestConfig)
	if err != nil {
		return nil, err
	}
	res, err := d.Resource(mapping.Resource).
		Namespace(namespace).
		Get(ctx, sourceRef.GeneratorRef.Name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	jsonRes, err := res.MarshalJSON()
	if err != nil {
		return nil, err
	}
	return &apiextensions.JSON{Raw: jsonRes}, nil
}

func (r *Reconciler) handleExtractSecrets(ctx context.Context, externalSecret *esv1beta1.ExternalSecret, remoteRef esv1beta1.ExternalSecretDataFromRemoteRef, i int) (map[string][]byte, error) {
	client, err := r.getClientOrDefault(ctx, externalSecret.Spec.SecretStoreRef, externalSecret.Namespace, remoteRef.SourceRef)
	if err != nil {
		return nil, err
	}
	defer client.Close(ctx)
	secretMap, err := client.GetSecretMap(ctx, *remoteRef.Extract)
	if err != nil {
		return nil, err
	}
	secretMap, err = utils.RewriteMap(remoteRef.Rewrite, secretMap)
	if err != nil {
		return nil, fmt.Errorf(errRewrite, i, err)
	}
	if len(remoteRef.Rewrite) == 0 {
		secretMap, err = utils.ConvertKeys(remoteRef.Extract.ConversionStrategy, secretMap)
		if err != nil {
			return nil, fmt.Errorf(errConvert, err)
		}
	}
	if !utils.ValidateKeys(secretMap) {
		return nil, fmt.Errorf(errInvalidKeys, "extract", i)
	}
	secretMap, err = utils.DecodeMap(remoteRef.Extract.DecodingStrategy, secretMap)
	if err != nil {
		return nil, fmt.Errorf(errDecode, "spec.dataFrom", i, err)
	}
	return secretMap, err
}

func (r *Reconciler) handleFindAllSecrets(ctx context.Context, externalSecret *esv1beta1.ExternalSecret, remoteRef esv1beta1.ExternalSecretDataFromRemoteRef, i int) (map[string][]byte, error) {
	client, err := r.getClientOrDefault(ctx, externalSecret.Spec.SecretStoreRef, externalSecret.Namespace, remoteRef.SourceRef)
	if err != nil {
		return nil, err
	}
	defer client.Close(ctx)
	secretMap, err := client.GetAllSecrets(ctx, *remoteRef.Find)
	if err != nil {
		return nil, err
	}
	secretMap, err = utils.RewriteMap(remoteRef.Rewrite, secretMap)
	if err != nil {
		return nil, fmt.Errorf(errRewrite, i, err)
	}
	if len(remoteRef.Rewrite) == 0 {
		// ConversionStrategy is deprecated. Use RewriteMap instead.
		r.recorder.Event(externalSecret, v1.EventTypeWarning, esv1beta1.ReasonDeprecated, fmt.Sprintf("dataFrom[%d].find.conversionStrategy=%v is deprecated and will be removed in further releases. Use dataFrom.rewrite instead", i, remoteRef.Find.ConversionStrategy))
		secretMap, err = utils.ConvertKeys(remoteRef.Find.ConversionStrategy, secretMap)
		if err != nil {
			return nil, fmt.Errorf(errConvert, err)
		}
	}
	if !utils.ValidateKeys(secretMap) {
		return nil, fmt.Errorf(errInvalidKeys, "find", i)
	}
	secretMap, err = utils.DecodeMap(remoteRef.Find.DecodingStrategy, secretMap)
	if err != nil {
		return nil, fmt.Errorf(errDecode, "spec.dataFrom", i, err)
	}
	return secretMap, err
}

// getClientOrDefault returns a provider client from the given storeRef or sourceRef.secretStoreRef
// while sourceRef.SecretStoreRef takes precedence over storeRef.
// it returns nil if both storeRef and sourceRef.secretStoreRef is empty.
func (r *Reconciler) getClientOrDefault(ctx context.Context, storeRef esv1beta1.SecretStoreRef, namespace string, sourceRef *esv1beta1.SourceRef) (esv1beta1.SecretsClient, error) {
	if sourceRef != nil && sourceRef.SecretStoreRef != nil {
		storeRef = *sourceRef.SecretStoreRef
	}

	store, err := r.getStore(ctx, &storeRef, namespace)
	if err != nil {
		return nil, err
	}

	// check if store should be handled by this controller instance
	if !secretstore.ShouldProcessStore(store, r.ControllerClass) {
		return nil, fmt.Errorf("can not reference unmanaged store")
	}

	if r.EnableFloodGate {
		err := assertStoreIsUsable(store)
		if err != nil {
			return nil, err
		}
	}

	storeProvider, err := esv1beta1.GetProvider(store)
	if err != nil {
		return nil, err
	}

	// secret client is created only if we are going to refresh
	// this skip an unnecessary check/request in the case we are not going to do anything
	providerClient, err := storeProvider.NewClient(ctx, store, r.Client, namespace)
	if err != nil {
		return nil, err
	}
	return providerClient, nil
}

// assertStoreIsUsable assert that the store is ready to use.
func assertStoreIsUsable(store esv1beta1.GenericStore) error {
	if store == nil {
		return nil
	}
	condition := secretstore.GetSecretStoreCondition(store.GetStatus(), esv1beta1.SecretStoreReady)
	if condition == nil || condition.Status != v1.ConditionTrue {
		return fmt.Errorf(errSecretStoreNotReady, store.GetName())
	}
	return nil
}

func (r *Reconciler) getStore(ctx context.Context, storeRef *esv1beta1.SecretStoreRef, namespace string) (esv1beta1.GenericStore, error) {
	ref := types.NamespacedName{
		Name: storeRef.Name,
	}

	if storeRef.Kind == esv1beta1.ClusterSecretStoreKind {
		var store esv1beta1.ClusterSecretStore
		err := r.Get(ctx, ref, &store)
		if err != nil {
			return nil, fmt.Errorf(errGetClusterSecretStore, ref.Name, err)
		}
		return &store, nil
	}

	ref.Namespace = namespace
	var store esv1beta1.SecretStore
	err := r.Get(ctx, ref, &store)
	if err != nil {
		return nil, fmt.Errorf(errGetSecretStore, ref.Name, err)
	}
	return &store, nil
}
