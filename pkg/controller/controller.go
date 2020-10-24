package controller

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"istio.io/api/networking/v1beta1"
	istionetworkingv1beta1 "istio.io/client-go/pkg/apis/networking/v1beta1"
	istio "istio.io/client-go/pkg/clientset/versioned"
	istionetworkinginformers "istio.io/client-go/pkg/informers/externalversions/networking/v1beta1"
	istionetworkinglisters "istio.io/client-go/pkg/listers/networking/v1beta1"
	corev1 "k8s.io/api/core/v1"
	networkingv1beta1 "k8s.io/api/networking/v1beta1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	networkinginformers "k8s.io/client-go/informers/networking/v1beta1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	networkinglisters "k8s.io/client-go/listers/networking/v1beta1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"
)

const controllerAgentName = "cert-manager-istio-controller"

// Controller responds to new resources and applies the necessary configuration
type Controller struct {
	kubeclientset  kubernetes.Interface
	istioclientset istio.Interface

	clusterDomain  string
	defaultGateway string

	ingressesLister  networkinglisters.IngressLister
	ingressesSynched cache.InformerSynced

	virtualServicesListers istionetworkinglisters.VirtualServiceLister
	virtualServicesSynched cache.InformerSynced

	destinationRuleLister   istionetworkinglisters.DestinationRuleLister
	destinationRulesSynched cache.InformerSynced

	workqueue workqueue.RateLimitingInterface
	recorder  record.EventRecorder
}

func NewController(
	kubeclientset kubernetes.Interface,
	istioclientset istio.Interface,
	clusterDomain string,
	defaultGateway string,
	ingressesInformer networkinginformers.IngressInformer,
	virtualServicesInformer istionetworkinginformers.VirtualServiceInformer,
	destinationRulesInformer istionetworkinginformers.DestinationRuleInformer) *Controller {

	// Create event broadcaster
	klog.V(4).Info("creating event broadcaster")

	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartRecordingToSink(&typedcorev1.EventSinkImpl{Interface: kubeclientset.CoreV1().Events("")})
	recorder := eventBroadcaster.NewRecorder(scheme.Scheme, corev1.EventSource{Component: controllerAgentName})

	controller := &Controller{
		kubeclientset:           kubeclientset,
		istioclientset:          istioclientset,
		clusterDomain:           clusterDomain,
		defaultGateway:          defaultGateway,
		ingressesLister:         ingressesInformer.Lister(),
		ingressesSynched:        ingressesInformer.Informer().HasSynced,
		virtualServicesListers:  virtualServicesInformer.Lister(),
		virtualServicesSynched:  virtualServicesInformer.Informer().HasSynced,
		destinationRuleLister:   destinationRulesInformer.Lister(),
		destinationRulesSynched: destinationRulesInformer.Informer().HasSynced,
		workqueue:               workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "CertManagerIstio"),
		recorder:                recorder,
	}

	klog.Info("setting up event handlers")
	ingressesInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: controller.enqueueIngress,
		UpdateFunc: func(old, new interface{}) {
			controller.enqueueIngress(new)
		},
	})

	return controller
}

// Run runs the controller.
func (c *Controller) Run(threadiness int, stopCh <-chan struct{}) error {
	defer utilruntime.HandleCrash()
	defer c.workqueue.ShutDown()

	klog.Info("starting controller")

	klog.Info("waiting for informer caches to sync")
	if ok := cache.WaitForCacheSync(stopCh, c.ingressesSynched, c.virtualServicesSynched, c.destinationRulesSynched); !ok {
		return fmt.Errorf("failed to wait for caches to sync")
	}

	klog.Info("starting workers")
	for i := 0; i < threadiness; i++ {
		go wait.Until(c.runWorker, time.Second, stopCh)
	}

	klog.Info("started workers")
	<-stopCh
	klog.Info("shutting down workers")

	return nil
}

func (c *Controller) runWorker() {
	for c.processNextWorkItem() {
	}
}

func (c *Controller) processNextWorkItem() bool {
	obj, shutdown := c.workqueue.Get()

	if shutdown {
		return false
	}

	err := func(obj interface{}) error {
		defer c.workqueue.Done(obj)
		var key string
		var ok bool

		if key, ok = obj.(string); !ok {
			c.workqueue.Forget(obj)
			utilruntime.HandleError(fmt.Errorf("expected string in workqueue but got %#v", obj))
			return nil
		}

		if err := c.syncHandler(key); err != nil {
			c.workqueue.AddRateLimited(key)
			return fmt.Errorf("error synching %q: %v, requeing", key, err)
		}

		c.workqueue.Forget(obj)
		klog.Infof("successfully synched %q", key)
		return nil
	}(obj)

	if err != nil {
		utilruntime.HandleError(err)
		return true
	}

	return true
}

func (c *Controller) syncHandler(key string) error {
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("invalid resource key: %s", key))
		return nil
	}

	// Get the ingress object
	ingress, err := c.ingressesLister.Ingresses(namespace).Get(name)
	if err != nil {
		if errors.IsNotFound(err) {
			utilruntime.HandleError(fmt.Errorf("ingress %q in work queue no longer exists", key))
			return nil
		}

		return err
	}

	// Only process if it is created by a cert-manager order
	isCertManagerIngress := false
	for _, owner := range ingress.ObjectMeta.OwnerReferences {
		if owner.Kind == "Challenge" && strings.HasPrefix(owner.APIVersion, "acme.cert-manager.io") {
			isCertManagerIngress = true
			break
		}
	}

	if !isCertManagerIngress {
		klog.Infof("ignorning non cert-manager ingress: %s/%s", ingress.Namespace, ingress.Name)
		return nil
	}

	// Handle the VirtualService
	err = c.handleVirtualService(ingress)
	if err != nil {
		klog.Errorf("failed to handle virtual service: %v", err)
		return err
	}

	// Handle the DestinationRule
	err = c.handleDestinationRule(ingress)
	if err != nil {
		klog.Errorf("failed to handle destination rule: %v", err)
		return err
	}

	return nil
}

func (c *Controller) enqueueIngress(obj interface{}) {
	var key string
	var err error
	if key, err = cache.MetaNamespaceKeyFunc(obj); err != nil {
		utilruntime.HandleError(err)
		return
	}

	c.workqueue.Add(key)
}

func (c *Controller) handleVirtualService(ingress *networkingv1beta1.Ingress) error {
	// Find a virtual service with the same labels
	selector := labels.Set(ingress.ObjectMeta.Labels).AsSelector()
	virtualServices, err := c.virtualServicesListers.VirtualServices(ingress.Namespace).List(selector)
	if err != nil {
		return err
	}

	host := ingress.Spec.Rules[0].Host
	path := ingress.Spec.Rules[0].HTTP.Paths[0].Path
	serviceName := ingress.Spec.Rules[0].HTTP.Paths[0].Backend.ServiceName
	servicePort := ingress.Spec.Rules[0].HTTP.Paths[0].Backend.ServicePort

	// We should at most 1 virtuual services which matches
	if len(virtualServices) > 1 {
		return fmt.Errorf("too many virtual services match %s/%s", ingress.Namespace, ingress.Name)
	}

	// Identify which gateway is used by any matching virtual services
	// Default to the default gateway
	gateways := []string{}

	// If the virtual service already exists,
	// just copy its gateways
	if len(virtualServices) == 1 {
		virtualService := virtualServices[0]
		gateways = virtualService.Spec.Gateways
	} else {
		allVirtualServices, err := c.virtualServicesListers.VirtualServices("").List(labels.Everything())
		if err != nil {
			return err
		}

		for _, virtualService := range allVirtualServices {
			if stringInArray(host, virtualService.Spec.Hosts) {
				for _, gateway := range virtualService.Spec.Gateways {
					if ingress.Namespace != virtualService.Namespace && !strings.Contains(gateway, "/") {
						gateway = fmt.Sprintf("%s/%s", virtualService.Namespace, gateway)
					}
					if !stringInArray(gateway, gateways) {
						gateways = append(gateways, gateway)
					}
				}
			}
		}
	}

	if len(gateways) == 0 {
		gateways = append(gateways, c.defaultGateway)
	}

	sort.Strings(gateways)

	// Generate a new VirtualService
	newVirtualService := &istionetworkingv1beta1.VirtualService{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName:    ingress.GenerateName,
			Namespace:       ingress.Namespace,
			OwnerReferences: ingress.OwnerReferences,
			Labels:          ingress.Labels,
		},
		Spec: v1beta1.VirtualService{
			Gateways: gateways,
			Hosts:    []string{host},
			Http: []*v1beta1.HTTPRoute{
				{
					Match: []*v1beta1.HTTPMatchRequest{
						{
							Uri: &v1beta1.StringMatch{
								MatchType: &v1beta1.StringMatch_Exact{
									Exact: path,
								},
							},
						},
					},
					Route: []*v1beta1.HTTPRouteDestination{
						{
							Destination: &v1beta1.Destination{
								Host: serviceName,
								Port: &v1beta1.PortSelector{
									Number: uint32(servicePort.IntValue()),
								},
							},
						},
					},
				},
			},
		},
	}

	if len(virtualServices) == 0 {
		klog.Infof("creating VirtualService for ingress %s/%s", ingress.Namespace, ingress.Name)
		newVirtualService, err = c.istioclientset.NetworkingV1beta1().VirtualServices(ingress.Namespace).Create(newVirtualService)
		if err != nil {
			return fmt.Errorf("failed to create VirtualService: %v", err)
		}

		klog.Infof("created VirtualService %s/%s", newVirtualService.Namespace, newVirtualService.Name)
	} else {
		existingVirtualService := virtualServices[0]

		klog.Infof("%t %t %t %t %t",
			!stringArrayEquals(existingVirtualService.Spec.Gateways, gateways),
			existingVirtualService.Spec.Hosts[0] != host,
			existingVirtualService.Spec.Http[0].Match[0].Uri.GetExact() != path,
			existingVirtualService.Spec.Http[0].Route[0].Destination.Host != host,
			existingVirtualService.Spec.Http[0].Route[0].Destination.Port.Number != uint32(servicePort.IntValue()))

		// TODO: Handle nil values
		if !stringArrayEquals(existingVirtualService.Spec.Gateways, gateways) ||
			existingVirtualService.Spec.Hosts[0] != host ||
			existingVirtualService.Spec.Http[0].Match[0].Uri.GetExact() != path ||
			existingVirtualService.Spec.Http[0].Route[0].Destination.Host != serviceName ||
			existingVirtualService.Spec.Http[0].Route[0].Destination.Port.Number != uint32(servicePort.IntValue()) {
			klog.Infof("updating VirtualService %s/%s", existingVirtualService.Namespace, existingVirtualService.Name)

			existingVirtualService.Spec = newVirtualService.Spec

			newVirtualService, err = c.istioclientset.NetworkingV1beta1().VirtualServices(ingress.Namespace).Update(existingVirtualService)
			if err != nil {
				return err
			}

			klog.Infof("Updated VirtualService %s/%s", newVirtualService.Namespace, newVirtualService.Name)
		}
	}

	return nil
}

func stringInArray(str string, arr []string) bool {
	for _, val := range arr {
		if str == val {
			return true
		}
	}

	return false
}

func stringArrayEquals(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}

	for indx := range a {
		if a[indx] != b[indx] {
			return false
		}
	}

	return true
}

func (c *Controller) handleDestinationRule(ingress *networkingv1beta1.Ingress) error {
	// Find a destination rule with the same labels
	selector := labels.Set(ingress.ObjectMeta.Labels).AsSelector()
	destinationRules, err := c.destinationRuleLister.DestinationRules(ingress.Namespace).List(selector)
	if err != nil {
		return err
	}

	// We should have at most 1 destination rule which matches
	if len(destinationRules) > 1 {
		return fmt.Errorf("too many destination rules match %s/%s", ingress.Namespace, ingress.Name)
	}

	newDestinationRule := &istionetworkingv1beta1.DestinationRule{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName:    ingress.GenerateName,
			Namespace:       ingress.Namespace,
			OwnerReferences: ingress.OwnerReferences,
			Labels:          ingress.Labels,
		},
		Spec: v1beta1.DestinationRule{
			Host: fmt.Sprintf("%s.%s.svc.%s", ingress.Spec.Rules[0].HTTP.Paths[0].Backend.ServiceName, ingress.Namespace, c.clusterDomain),
			TrafficPolicy: &v1beta1.TrafficPolicy{
				Tls: &v1beta1.TLSSettings{
					Mode: v1beta1.TLSSettings_DISABLE,
				},
			},
		},
	}

	// If there are no destination rules, then lets create one
	if len(destinationRules) == 0 {
		klog.Infof("creating DestinationRule for ingress %s/%s", ingress.Namespace, ingress.Name)
		newDestinationRule, err = c.istioclientset.NetworkingV1beta1().DestinationRules(ingress.Namespace).Create(newDestinationRule)
		if err != nil {
			return fmt.Errorf("failed to create DestinationRule: %v", err)
		}

		klog.Infof("created DestinationRule %s/%s", newDestinationRule.Namespace, newDestinationRule.Name)
	} else {
		existingDestinationRule := destinationRules[0]

		if existingDestinationRule.Spec.Host != newDestinationRule.Spec.Host {
			klog.Infof("updating DestinationRule %s/%s", existingDestinationRule.Namespace, existingDestinationRule.Name)
			newDestinationRule.Name = existingDestinationRule.Name

			newDestinationRule, err = c.istioclientset.NetworkingV1beta1().DestinationRules(ingress.Namespace).Update(newDestinationRule)
			if err != nil {
				return err
			}

			klog.Infof("updated DestinationRule %s/%s", newDestinationRule.Namespace, newDestinationRule.Name)
		}
	}

	return nil
}
