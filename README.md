# spring-config-decryptor-webhook

| WARNING: DO NOT USE IN PRODUCTION |
| --------------------------------- |

Kubernetes mutating webhook decrypting configmaps  and secrets encrypted with Spring Cloud Config asymmetric key.

**Do not use in production as webhook http endpoint is unprotected and allows decryption of arbitrary secrets** 

## Usage example

Prerequisites:

- [cert-manager](https://github.com/jetstack/cert-manager)
- The `spring` command line client (with [Spring Cloud CLI](https://cloud.spring.io/spring-cloud-cli/reference/html/) extensions installed)
- [helm 3](https://github.com/helm/helm) version v3.3.4
- [kubectl](https://kubernetes.io/docs/tasks/tools/install-kubectl/)

1.Generate RSA key pair

```
$ openssl genrsa -out rsa-private-key.pem 4096
$ openssl rsa -in rsa-private-key.pem -outform PEM -pubout -out rsa-public-key.pem
```

2.Create kubernetes secret with RSA private key

```
$ kubectl create namespace webhook
$ kubectl create secret generic spring-encrypt-key -n  webhook --from-file=rsa-private-key=rsa-private-key.pem
```

3.Deploy mutating webhook to kubernetes

Depending on your kubernetes installation change helm values and invoke make accordingly.

```
$ make HELM_VALUES=values-eks.yaml KUBE_CONTEXT=test-cluster helm-install
```

4.Check the deployment

```
$ kubectl get all -n webhook
NAME                                                   READY   STATUS    RESTARTS   AGE
pod/spring-config-decryptor-webhook-7c8bfc8d54-dw8dc   1/1     Running   0          5m50s

NAME                                      TYPE           CLUSTER-IP      EXTERNAL-IP                                                                           PORT(S)         AGE
service/spring-config-decryptor-webhook   LoadBalancer   172.20.30.252   internal-a785e316153b849e7bbee4001035c7ba-1452171545.eu-central-1.elb.amazonaws.com   443:32458/TCP   5m50s

NAME                                              READY   UP-TO-DATE   AVAILABLE   AGE
deployment.apps/spring-config-decryptor-webhook   1/1     1            1           5m50s

NAME                                                         DESIRED   CURRENT   READY   AGE
replicaset.apps/spring-config-decryptor-webhook-7c8bfc8d54   1         1         1       5m50s

```

```
$ kubectl get secrets -n webhook
NAME                                                    TYPE                                  DATA   AGE
default-token-vw4bg                                     kubernetes.io/service-account-token   3      3d2h
sh.helm.release.v1.spring-config-decryptor-webhook.v1   helm.sh/release.v1                    1      6m42s
spring-config-decryptor-webhook-certificate             kubernetes.io/tls                     3      6m42s
spring-config-decryptor-webhook-token-wlshn             kubernetes.io/service-account-token   3      6m42s
spring-encrypt-key                                      Opaque
```

5.Check `cert-manager` injected `caBundle` into `mutatingwebhookconfigurations`

```
$ kubectl get mutatingwebhookconfigurations.admissionregistration.k8s.io spring-config-decryptor-webhook -o json | jq -r '.webhooks[].clientConfig'
{
  "caBundle": "LS0tLS1CRUdJTiBDRVJUSUZ....",
}
{
  "caBundle": "LS0tLS1CRUdJTiBDRVJUSUZ....",
}
```

6.Create RSA encrypted `test-secret` secret with `spring-config-decrypt=true` label. Prefix the encrypted password value with`{cipher}`

```
ENCRYPTED_PASSWORD=$(spring encrypt --key @./rsa-public-key.pem my-password)
kubectl create secret generic test-secret --from-literal="username=my-app" --from-literal="password={cipher}${ENCRYPTED_PASSWORD}" -o yaml --dry-run | kubectl label -f- --dry-run -o yaml --local spring-config-decrypt="true" | kubectl apply -n webhook -f -
```

Check the mutating webhook decrypted the secret, and it is store in the plain text.

```
$ kubectl get secrets -n webhook test-secret -o json | jq -r '.data.password' | base64 -d
my-password
```


7.Create RSA encrypted `test-cm` configmap. Prefix secret property value with`{cipher}`

```
ENCRYPTED_VALUE=$(spring encrypt --key @./rsa-public-key.pem value2)
kubectl create configmap test-cm -n webhook --from-literal key1=value1 --from-literal "key2={cipher}${ENCRYPTED_VALUE}"
```

Check `key2` is still encrypted

```
$ kubectl get configmaps -n webhook test-cm -o json | jq '.data'
{
  "key1": "value1",
  "key2": "{cipher}AgBBmob53tmsrm8ufAyVeSjLa3WDvRxa6OTLa5gDpG7wp5qoHZ90W78Fn117LOQ6QgrQ+N4TgoIZsS2dbNeYK+UrPr2hXgw+aHqUFxflifnA4KwfVNIHVQ2Z+XafJw2eaMh7ARUhxnWw2LPWM6M9LNCPJe9oExp/tW/6UOZLCfApVLVyEursRNMfGCeUDQB/2QfFKfgIExMbwkdPhUpjSokwgYjZy9fgNFNMY0Ovq4XNPISEwaNmKs5OskhMAdvfmUZnQ89ipDFK3pD+N//EHm0b6Bax2pNcIVMYe3296YQrvJ6Uh/bfdblVii6PLgyjAiEpxzYN4Q+sbq338C2IZoSZiAqLJzSWel5bwrzbUPKGJmiYRbIyhHVtuupw8L/oiRVxzx3iQcfXqvXE2k6gNNQ4JwqlUmrQq0eH5v9/GE/BMuIhLi13oTia1DGjSMxgzO/zdtG0By0c374fmH07O+Yxspg8rf4PDZWhprCrEvgXI7XTHjr8yk1rmZSZ/Cg4+E1Wp+yf89hSKQurjQC8ycIvljTF8ng5HaLl+Xzq3jber/Wzsu1zddunb06uzM3KeZgxvGFo3ZIuk+JZfskDCDa+MqCO81lIMe3oFT6u0ywciA3Vems5O36eitv5UOT569n6mY3pLwGQNVv+0M4QxR0XINM/WnJ8UPr2uzlAa6ckMlkwBxABTMK2C5bj8IAUUuEtPXLI/FLnDxywju7un7sV"
}
```


Label the config map with `spring-config-decrypt=true` and check the decrypted secret

```
$ kubectl label configmap -n webhook test-cm spring-config-decrypt=true
$ kubectl get configmaps -n webhook test-cm -o json | jq '.data'
{
  "key1": "value1",
  "key2": "value2"
}
```
