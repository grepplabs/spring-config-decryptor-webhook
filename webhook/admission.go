package webhook

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/grepplabs/spring-config-decryptor/pkg/decryptor"
	"github.com/pkg/errors"
	v1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"
	"strings"
)

type patchOperation struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	Value string `json:"value"`
}

type patchOperations []patchOperation

func (ps *patchOperations) Replace(key string, value string) {
	*ps = append(*ps, patchOperation{
		Op:    "replace",
		Path:  fmt.Sprintf("/data/%s", key),
		Value: value,
	})
}

type AdmissionReviewMutator struct {
	configDecryptor decryptor.Decryptor
}

func NewAdmissionReviewMutator(configDecryptor decryptor.Decryptor) *AdmissionReviewMutator {
	return &AdmissionReviewMutator{
		configDecryptor: configDecryptor,
	}
}

func (m AdmissionReviewMutator) admitConfigMaps(ar v1.AdmissionReview) *v1.AdmissionResponse {
	klog.V(2).Infof("admitting configmap %s/%s", ar.Request.Namespace, ar.Request.Name)

	configMapResource := metav1.GroupVersionResource{Group: "", Version: "v1", Resource: "configmaps"}
	if ar.Request.Resource != configMapResource {
		msg := fmt.Sprintf("expect resource to be %v, but is %v", configMapResource, ar.Request.Resource)
		klog.Error(msg)
		return toV1AdmissionResponse(errors.New(msg))
	}

	var raw []byte
	if ar.Request.Operation == v1.Delete {
		raw = ar.Request.OldObject.Raw
	} else {
		raw = ar.Request.Object.Raw
	}

	if ar.Request.Operation != v1.Create && ar.Request.Operation != v1.Update {
		reviewResponse := v1.AdmissionResponse{}
		reviewResponse.Allowed = true
		return &reviewResponse
	}

	configmap := corev1.ConfigMap{}
	deserializer := codecs.UniversalDeserializer()
	if _, _, err := deserializer.Decode(raw, nil, &configmap); err != nil {
		klog.Error(err)
		return toV1AdmissionResponse(err)
	}
	reviewResponse := v1.AdmissionResponse{}
	reviewResponse.Allowed = true

	patches := patchOperations{}
	for k, v := range configmap.Data {
		var buf bytes.Buffer
		err := m.configDecryptor.Decrypt(&buf, strings.NewReader(v))
		if err != nil {
			klog.Error(err)
			return toV1AdmissionResponse(err)
		}
		vnew := buf.String()
		if v != vnew {
			patches.Replace(k, vnew)
		}
	}
	if len(patches) != 0 {
		b, err := json.Marshal(patches)
		if err != nil {
			klog.Error(err)
			return toV1AdmissionResponse(err)
		}
		klog.Infof("patch configmap %s/%s", configmap.ObjectMeta.Namespace, configmap.ObjectMeta.Name)
		klog.V(4).Infof("AdmissionResponse patch %s", string(b))
		reviewResponse.Patch = b
		pt := v1.PatchTypeJSONPatch
		reviewResponse.PatchType = &pt
	}
	return &reviewResponse
}

func (m AdmissionReviewMutator) admitSecrets(ar v1.AdmissionReview) *v1.AdmissionResponse {
	klog.V(2).Infof("admitting secret %s/%s", ar.Request.Namespace, ar.Request.Name)

	secretResource := metav1.GroupVersionResource{Group: "", Version: "v1", Resource: "secrets"}
	if ar.Request.Resource != secretResource {
		msg := fmt.Sprintf("expect resource to be %v, but is %v", secretResource, ar.Request.Resource)
		klog.Error(msg)
		return toV1AdmissionResponse(errors.New(msg))
	}

	var raw []byte
	if ar.Request.Operation == v1.Delete {
		raw = ar.Request.OldObject.Raw
	} else {
		raw = ar.Request.Object.Raw
	}

	if ar.Request.Operation != v1.Create && ar.Request.Operation != v1.Update {
		reviewResponse := v1.AdmissionResponse{}
		reviewResponse.Allowed = true
		return &reviewResponse
	}

	secret := corev1.Secret{}
	deserializer := codecs.UniversalDeserializer()
	if _, _, err := deserializer.Decode(raw, nil, &secret); err != nil {
		klog.Error(err)
		return toV1AdmissionResponse(err)
	}
	reviewResponse := v1.AdmissionResponse{}
	reviewResponse.Allowed = true

	patches := patchOperations{}
	for k, v := range secret.Data {
		var buf bytes.Buffer
		err := m.configDecryptor.Decrypt(&buf, bytes.NewReader(v))
		if err != nil {
			klog.Error(err)
			return toV1AdmissionResponse(err)
		}
		vnew := base64.StdEncoding.EncodeToString(buf.Bytes())
		vold := base64.StdEncoding.EncodeToString(v)
		if vold != vnew {
			patches.Replace(k, vnew)
		}
	}
	if len(patches) != 0 {
		b, err := json.Marshal(patches)
		if err != nil {
			klog.Error(err)
			return toV1AdmissionResponse(err)
		}
		klog.Infof("patch secret %s/%s", secret.ObjectMeta.Namespace, secret.ObjectMeta.Name)
		klog.V(4).Infof("AdmissionResponse patch %s", string(b))
		reviewResponse.Patch = b
		pt := v1.PatchTypeJSONPatch
		reviewResponse.PatchType = &pt
	}
	return &reviewResponse
}
