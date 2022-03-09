package main

import (
	"flag"
	"time"

	"github.com/StatCan/cert-manager-istio-controller/pkg/controller"
	"github.com/StatCan/cert-manager-istio-controller/pkg/signals"

	istio "istio.io/client-go/pkg/clientset/versioned"
	istioinformers "istio.io/client-go/pkg/informers/externalversions"
	kubeinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog"
)

var (
	masterURL      string
	kubeconfig     string
	clusterDomain  string
	defaultGateway string
)

func main() {
	klog.InitFlags(nil)
	flag.Parse()

	stopCh := signals.SetupSignalHandler()

	cfg, err := clientcmd.BuildConfigFromFlags(masterURL, kubeconfig)
	if err != nil {
		klog.Fatalf("error building kubeconfig: %v", err)
	}

	kubeclient, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		klog.Fatalf("error building kubernetes clientset: %v", err)
	}

	istioclient, err := istio.NewForConfig(cfg)
	if err != nil {
		klog.Fatalf("error building istio client: %v", err)
	}

	kubeInformerFactory := kubeinformers.NewSharedInformerFactory(kubeclient, time.Second*30)
	istioInformerFactory := istioinformers.NewSharedInformerFactory(istioclient, time.Second*30)

	ctlr := controller.NewController(
		kubeclient,
		istioclient,
		clusterDomain,
		defaultGateway,
		kubeInformerFactory.Networking().V1().Ingresses(),
		istioInformerFactory.Networking().V1beta1().VirtualServices(),
		istioInformerFactory.Networking().V1beta1().DestinationRules())

	kubeInformerFactory.Start(stopCh)
	istioInformerFactory.Start(stopCh)

	if err = ctlr.Run(2, stopCh); err != nil {
		klog.Fatalf("error running controller: %v", err)
	}
}

func init() {
	flag.StringVar(&kubeconfig, "kubeconfig", "", "Path to a kubeconfig. Only required if out-of-cluster.")
	flag.StringVar(&masterURL, "master", "", "The address of the Kubernetes API server. Overrides any value in kubeconfig. Only required if out-of-cluster.")
	flag.StringVar(&clusterDomain, "cluster-domain", "cluster.local", "The cluster domain.")
	flag.StringVar(&defaultGateway, "default-gateway", "istio-system/istio-autogenerated-k8s-ingress", "The default Istio gateway used when no existing VirtualService is located matching the host.")
}
