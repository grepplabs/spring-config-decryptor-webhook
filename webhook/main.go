package webhook

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"

	"github.com/spf13/cobra"

	v1 "k8s.io/api/admission/v1"
	"k8s.io/api/admission/v1beta1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/klog/v2"

	"github.com/grepplabs/spring-config-decryptor/pkg/decryptor"
	"github.com/oklog/run"
)

const (
	defaultEnvEncryptKey = "ENCRYPT_KEY"
)

var (
	tlsCertFile    string
	tlsKeyFile     string
	listenPort     int
	healthzPort    int
	encryptKeyFile string
)

// CmdWebhook is used by agnhost Cobra.
var CmdWebhook = &cobra.Command{
	Use:   "webhook",
	Short: "Kubernetes mutating webhook decrypting configmaps and secrets encrypted with Spring Cloud Config asymmetric key",
	Args:  cobra.MaximumNArgs(0),
	Run:   main,
}

func init() {
	CmdWebhook.Flags().StringVar(&tlsCertFile, "tls-cert-file", "", "File containing the default x509 Certificate for HTTPS. (CA cert, if any, concatenated after server cert).")
	CmdWebhook.Flags().StringVar(&tlsKeyFile, "tls-private-key-file", "", "File containing the default x509 private key matching --tls-cert-file.")
	CmdWebhook.Flags().IntVar(&listenPort, "secure-port", 6443, "port number to listen on for secure TLS connections")
	CmdWebhook.Flags().IntVar(&healthzPort, "healthz-port", 6081, "port number to listen on for insecure healthz connections")
	CmdWebhook.Flags().StringVar(&encryptKeyFile, "encrypt-key-file", "", fmt.Sprintf("The file with RSA private key. If empty the key is read from environment variable %s ", defaultEnvEncryptKey))
}

// admitv1beta1Func handles a v1beta1 admission
type admitv1beta1Func func(v1beta1.AdmissionReview) *v1beta1.AdmissionResponse

// admitv1beta1Func handles a v1 admission
type admitv1Func func(v1.AdmissionReview) *v1.AdmissionResponse

// admitHandler is a handler, for both validators and mutators, that supports multiple admission review versions
type admitHandler struct {
	v1beta1 admitv1beta1Func
	v1      admitv1Func
}

func newDelegateToV1AdmitHandler(f admitv1Func) admitHandler {
	return admitHandler{
		v1beta1: delegateV1beta1AdmitToV1(f),
		v1:      f,
	}
}

func delegateV1beta1AdmitToV1(f admitv1Func) admitv1beta1Func {
	return func(review v1beta1.AdmissionReview) *v1beta1.AdmissionResponse {
		in := v1.AdmissionReview{Request: convertAdmissionRequestToV1(review.Request)}
		out := f(in)
		return convertAdmissionResponseToV1beta1(out)
	}
}

// serve handles the http portion of a request prior to handing to an admit function
func serve(w http.ResponseWriter, r *http.Request, admit admitHandler) {
	var body []byte
	if r.Body != nil {
		if data, err := ioutil.ReadAll(r.Body); err == nil {
			body = data
		}
	}
	// verify the content type is accurate
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" {
		klog.Errorf("contentType=%s, expect application/json", contentType)
		return
	}

	klog.V(5).Info(fmt.Sprintf("handling request: %s", body))

	deserializer := codecs.UniversalDeserializer()
	obj, gvk, err := deserializer.Decode(body, nil, nil)
	if err != nil {
		msg := fmt.Sprintf("Request could not be decoded: %v", err)
		klog.Error(msg)
		http.Error(w, msg, http.StatusBadRequest)
		return
	}

	var responseObj runtime.Object
	switch *gvk {
	case v1beta1.SchemeGroupVersion.WithKind("AdmissionReview"):
		requestedAdmissionReview, ok := obj.(*v1beta1.AdmissionReview)
		if !ok {
			klog.Errorf("Expected v1beta1.AdmissionReview but got: %T", obj)
			return
		}
		responseAdmissionReview := &v1beta1.AdmissionReview{}
		responseAdmissionReview.SetGroupVersionKind(*gvk)
		responseAdmissionReview.Response = admit.v1beta1(*requestedAdmissionReview)
		responseAdmissionReview.Response.UID = requestedAdmissionReview.Request.UID
		responseObj = responseAdmissionReview
	case v1.SchemeGroupVersion.WithKind("AdmissionReview"):
		requestedAdmissionReview, ok := obj.(*v1.AdmissionReview)
		if !ok {
			klog.Errorf("Expected v1.AdmissionReview but got: %T", obj)
			return
		}
		responseAdmissionReview := &v1.AdmissionReview{}
		responseAdmissionReview.SetGroupVersionKind(*gvk)
		responseAdmissionReview.Response = admit.v1(*requestedAdmissionReview)
		responseAdmissionReview.Response.UID = requestedAdmissionReview.Request.UID
		responseObj = responseAdmissionReview
	default:
		msg := fmt.Sprintf("Unsupported group version kind: %v", gvk)
		klog.Error(msg)
		http.Error(w, msg, http.StatusBadRequest)
		return
	}

	respBytes, err := json.Marshal(responseObj)
	if err != nil {
		klog.Error(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	klog.V(5).Info(fmt.Sprintf("sending response: %s", respBytes))

	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(respBytes); err != nil {
		klog.Error(err)
	}
}

func main(_ *cobra.Command, _ []string) {
	var g run.Group
	{
		healthzAddr := fmt.Sprintf(":%d", healthzPort)
		l, err := net.Listen("tcp", healthzAddr)
		if err != nil {
			klog.Error(err)
			os.Exit(1)
		}
		g.Add(func() error {
			mux := http.NewServeMux()
			mux.HandleFunc("/healthz", func(w http.ResponseWriter, req *http.Request) { _, _ = w.Write([]byte("ok")) })
			mux.HandleFunc("/livez", func(w http.ResponseWriter, req *http.Request) { _, _ = w.Write([]byte("ok")) })
			klog.Info("listening for insecure healthz connections", "address", healthzAddr)
			srv := &http.Server{
				Handler: mux,
			}
			return srv.Serve(l)
		}, func(error) {
			_ = l.Close()
		})
	}
	{
		listenAddr := fmt.Sprintf(":%d", listenPort)
		l, err := net.Listen("tcp", listenAddr)
		if err != nil {
			klog.Error(err)
			os.Exit(1)
		}
		g.Add(func() error {
			encryptKey, err := getEncryptKey()
			if err != nil {
				return err
			}
			configDecryptor, err := decryptor.NewDecryptor(encryptKey)
			if err != nil {
				return err
			}
			admissionReviewMutator := NewAdmissionReviewMutator(configDecryptor)
			mux := http.NewServeMux()
			mux.HandleFunc("/configmaps", func(w http.ResponseWriter, r *http.Request) {
				serve(w, r, newDelegateToV1AdmitHandler(admissionReviewMutator.admitConfigMaps))
			})
			mux.HandleFunc("/secrets", func(w http.ResponseWriter, r *http.Request) {
				serve(w, r, newDelegateToV1AdmitHandler(admissionReviewMutator.admitSecrets))
			})
			klog.Info("listening for secure connections", "address", listenAddr)
			sCert, err := tls.LoadX509KeyPair(tlsCertFile, tlsKeyFile)
			if err != nil {
				return err
			}
			l = tls.NewListener(l, &tls.Config{
				Certificates: []tls.Certificate{sCert},
			})
			srv := &http.Server{
				Handler: mux,
			}
			return srv.Serve(l)
		}, func(error) {
			_ = l.Close()
		})
	}
	err := g.Run()
	if err != nil {
		klog.Error(err)
		os.Exit(1)
	}
}

func getEncryptKey() ([]byte, error) {
	if len(encryptKeyFile) != 0 {
		return ioutil.ReadFile(encryptKeyFile)
	} else {
		value := os.Getenv(defaultEnvEncryptKey)
		if value == "" {
			return nil, fmt.Errorf("missing private key error, provide key in the env variable %s or use --encrypt-key-file flag", defaultEnvEncryptKey)
		}
		return []byte(value), nil
	}
}
