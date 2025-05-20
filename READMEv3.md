# Guía Completa: Implementación de Encriptación End-to-End en EKS Auto Mode

Esta guía detalla la implementación de una arquitectura de encriptación completa en Amazon EKS Auto Mode, utilizando cert-manager con AWSPCAClusterIssuer para gestión centralizada de certificados y desplegando el juego 2048 como aplicación de demostración.

## Índice
1. [Requisitos previos](#requisitos-previos)
2. [Arquitectura de la solución](#arquitectura-de-la-solución)
3. [Creación del clúster EKS Auto Mode](#creación-del-clúster-eks-auto-mode)
4. [Configuración de AWS Certificate Manager (ACM)](#configuración-de-aws-certificate-manager-acm)
5. [Configuración de AWS Private CA](#configuración-de-aws-private-ca)
6. [Instalación de cert-manager](#instalación-de-cert-manager)
7. [Configuración de AWS PCA Issuer](#configuración-de-aws-pca-issuer)
8. [Despliegue de la aplicación 2048](#despliegue-de-la-aplicación-2048)
9. [Implementación del proxy NGINX](#implementación-del-proxy-nginx)
10. [Configuración del ALB con Ingress](#configuración-del-alb-con-ingress)
11. [Configuración de DNS](#configuración-de-dns)
12. [Verificación y pruebas](#verificación-y-pruebas)
13. [Solución de problemas comunes](#solución-de-problemas-comunes)
14. [Consideraciones de seguridad](#consideraciones-de-seguridad)

## Requisitos previos

Antes de comenzar, asegúrate de tener:

- Una cuenta AWS con permisos para crear y administrar:
  - Amazon EKS
  - AWS Certificate Manager (ACM)
  - AWS Private CA
  - IAM roles y políticas
  - Route 53 (para DNS)
- Herramientas instaladas y configuradas:
  - AWS CLI v2
  - kubectl (compatible con la versión de EKS)
  - eksctl
  - helm v3
- Un nombre de dominio registrado que puedas controlar para la configuración de DNS

```bash
# Verificar que las herramientas estén instaladas correctamente
aws --version
kubectl version --client
eksctl version
helm version
```

## Arquitectura de la solución

La arquitectura implementa capas de encriptación:

1. **Cliente a ALB**: Encriptación HTTPS con certificados públicos (ACM)
2. **ALB a NGINX Proxy**: Encriptación HTTPS con certificados privados (AWS Private CA)
3. **Dentro del clúster**: 
   - Tráfico HTTP entre NGINX Proxy y Pods (dentro del perímetro seguro)
   - Encriptación automática entre nodos gracias a instancias Nitro

## Creación del clúster EKS Auto Mode

Primero, vamos a crear un clúster EKS con Auto Mode habilitado:

```bash
# Configurar variables de entorno
export CLUSTER_NAME="eks-auto-mode-secure-demo"
export AWS_REGION="us-east-1"
export K8S_VERSION="1.32"

# Crear archivo de configuración del clúster
cat <<EOF > cluster-config.yaml
apiVersion: eksctl.io/v1alpha5
kind: ClusterConfig
metadata:
  name: ${CLUSTER_NAME}
  region: ${AWS_REGION}
  version: "${K8S_VERSION}"
autoModeConfig:
  enabled: true
iam:
  withOIDC: true
vpc:
  clusterEndpoints:
    privateAccess: true
    publicAccess: true
EOF

# Crear el clúster (toma aproximadamente 15-20 minutos)
eksctl create cluster -f cluster-config.yaml

# Verificar que el clúster esté funcionando
kubectl get nodes
```

## Configuración de AWS Certificate Manager (ACM)

Necesitamos crear un certificado público para el ALB:

```bash
# Configurar el dominio de la aplicación
export APP_DOMAIN="app.ejemplo.com"  # Reemplazar con tu dominio real

# Solicitar un certificado público en ACM
aws acm request-certificate \
  --domain-name ${APP_DOMAIN} \
  --validation-method DNS \
  --region ${AWS_REGION}

# Guardar el ARN del certificado público
export PUBLIC_CERT_ARN=$(aws acm list-certificates \
  --query "CertificateSummaryList[?DomainName=='${APP_DOMAIN}'].CertificateArn" \
  --output text \
  --region ${AWS_REGION})

echo "Certificado público ARN: ${PUBLIC_CERT_ARN}"

# Obtener información para validación DNS
aws acm describe-certificate \
  --certificate-arn ${PUBLIC_CERT_ARN} \
  --region ${AWS_REGION}
```

Ahora debes crear el registro CNAME de validación en tu DNS para validar la propiedad del dominio.

## Configuración de AWS Private CA

A continuación, crearemos una Autoridad Certificadora Privada para emitir certificados internos:

```bash
# Crear configuración de la CA privada
cat <<EOF > ca-config.json
{
  "KeyAlgorithm": "RSA_2048",
  "SigningAlgorithm": "SHA256WITHRSA",
  "Subject": {
    "Country": "US",
    "Organization": "Mi Empresa",
    "OrganizationalUnit": "Seguridad",
    "State": "Washington",
    "Locality": "Seattle",
    "CommonName": "Mi Empresa Private CA"
  }
}
EOF

# Crear configuración de revocación
cat <<EOF > revoke-config.json
{
  "CrlConfiguration": {
    "Enabled": true,
    "ExpirationInDays": 7,
    "S3BucketName": "${CLUSTER_NAME}-crl-bucket"
  }
}
EOF

# Crear el bucket S3 para la CRL
aws s3 mb s3://${CLUSTER_NAME}-crl-bucket --region ${AWS_REGION}

# Crear la CA privada
aws acm-pca create-certificate-authority \
  --certificate-authority-configuration file://ca-config.json \
  --certificate-authority-type "ROOT" \
  --revocation-configuration file://revoke-config.json \
  --tags Key=Environment,Value=Production

# Obtener el ARN de la CA privada
export CA_ARN=$(aws acm-pca list-certificate-authorities \
  --query "CertificateAuthorities[?Status=='ACTIVE'].Arn" \
  --output text)

echo "CA privada ARN: ${CA_ARN}"

# Emitir un certificado para la CA privada
aws acm-pca issue-certificate \
  --certificate-authority-arn ${CA_ARN} \
  --csr fileb://csr.pem \
  --signing-algorithm "SHA256WITHRSA" \
  --validity Value=365,Type="DAYS" \
  --template-arn arn:aws:acm-pca:::template/RootCACertificate/V1

# Obtener el certificado de la CA
aws acm-pca get-certificate \
  --certificate-authority-arn ${CA_ARN} \
  --certificate-arn ${CERTIFICATE_ARN} \
  --output text > ca-cert.pem
```

## Instalación de cert-manager

Ahora instalaremos cert-manager para automatizar la gestión de certificados:

```bash
# Añadir repositorio Helm de Jetstack
helm repo add jetstack https://charts.jetstack.io
helm repo update

# Instalar cert-manager con CRDs (Custom Resource Definitions)
kubectl create namespace cert-manager
helm install cert-manager jetstack/cert-manager \
  --namespace cert-manager \
  --version v1.13.1 \
  --set installCRDs=true \
  --set global.leaderElection.namespace=cert-manager

# Verificar la instalación
kubectl get pods -n cert-manager
```

## Configuración de AWS PCA Issuer

Vamos a instalar y configurar AWS PCA Issuer para integrar cert-manager con AWS Private CA:

```bash
# Crear política IAM para el AWS PCA Issuer
cat <<EOF > pca-issuer-policy.json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "acm-pca:DescribeCertificateAuthority",
        "acm-pca:GetCertificate",
        "acm-pca:IssueCertificate"
      ],
      "Resource": "${CA_ARN}"
    }
  ]
}
EOF

# Crear la política en IAM
aws iam create-policy \
  --policy-name AWSPCAIssuerPolicy \
  --policy-document file://pca-issuer-policy.json

# Guardar el ARN de la política
export POLICY_ARN=$(aws iam list-policies \
  --query "Policies[?PolicyName=='AWSPCAIssuerPolicy'].Arn" \
  --output text)

# Configurar cuenta de servicio con IRSA (IAM Roles for Service Accounts)
eksctl create iamserviceaccount \
  --cluster=${CLUSTER_NAME} \
  --namespace=cert-manager \
  --name=aws-pca-issuer \
  --attach-policy-arn=${POLICY_ARN} \
  --approve

# Instalar el complemento AWS PCA Issuer
helm repo add awspca https://cert-manager.github.io/aws-privateca-issuer
helm repo update
helm install aws-pca-issuer awspca/aws-privateca-issuer \
  --namespace cert-manager \
  --set serviceAccount.create=false \
  --set serviceAccount.name=aws-pca-issuer

# Crear un AWSPCAClusterIssuer para emitir certificados a nivel de clúster
cat <<EOF > awspca-cluster-issuer.yaml
apiVersion: awspca.cert-manager.io/v1beta1
kind: AWSPCAClusterIssuer
metadata:
  name: pca-cluster-issuer
spec:
  arn: ${CA_ARN}
  region: ${AWS_REGION}
EOF

kubectl apply -f awspca-cluster-issuer.yaml

# Verificar que el ClusterIssuer se ha creado correctamente
kubectl get awspcaclusterissuer
kubectl describe awspcaclusterissuer pca-cluster-issuer
```

## Despliegue de la aplicación 2048

Ahora crearemos un namespace para nuestra aplicación y desplegaremos el juego 2048:

```bash
# Crear namespace para la aplicación
kubectl create namespace app-namespace

# Desplegar el juego 2048
cat <<EOF > game-2048.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: deployment-2048
  namespace: app-namespace
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: app-2048
  replicas: 2
  template:
    metadata:
      labels:
        app.kubernetes.io/name: app-2048
    spec:
      containers:
      - image: alexwhen/docker-2048
        imagePullPolicy: Always
        name: app-2048
        ports:
        - containerPort: 80
---
apiVersion: v1
kind: Service
metadata:
  name: app-backend-service
  namespace: app-namespace
spec:
  ports:
  - port: 80
    targetPort: 80
    protocol: TCP
  selector:
    app.kubernetes.io/name: app-2048
EOF

kubectl apply -f game-2048.yaml

# Verificar que la aplicación se haya desplegado correctamente
kubectl get pods -n app-namespace
kubectl get service -n app-namespace
```

## Implementación del proxy NGINX

Implementaremos un proxy NGINX que terminará TLS antes de enviar el tráfico a la aplicación:

```bash
# Crear certificado para el proxy usando cert-manager
cat <<EOF > proxy-certificate.yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: nginx-proxy-cert
  namespace: app-namespace
spec:
  secretName: nginx-tls
  duration: 2160h0m0s  # 90 días
  renewBefore: 360h0m0s  # 15 días
  subject:
    organizations:
      - "Example Corp"  # Usar el mismo valor que en la CA
  dnsNames:
    - "nginx-proxy-service.app-namespace.svc.cluster.local"
    - "nginx-proxy-service"
    - "nginx-proxy-service.app-namespace"
  issuerRef:
    name: pca-cluster-issuer
    kind: AWSPCAClusterIssuer
    group: awspca.cert-manager.io
EOF

kubectl apply -f proxy-certificate.yaml

# Verificar que el certificado se haya creado correctamente
kubectl get certificate -n app-namespace
kubectl describe certificate nginx-proxy-cert -n app-namespace

# Crear ConfigMap para la configuración de NGINX
cat <<EOF > nginx-config.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: nginx-config
  namespace: app-namespace
data:
  default.conf: |
    server {
        listen 443 ssl;
        server_name _;
        
        ssl_certificate /etc/nginx/certs/tls.crt;
        ssl_certificate_key /etc/nginx/certs/tls.key;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers HIGH:!aNULL:!MD5;
        
        # Health check location
        location /health {
            return 200 'healthy\n';
            add_header Content-Type text/plain;
        }
        
        # Ruta específica para el juego 2048
        location / {
            proxy_pass http://app-backend-service:80;
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto \$scheme;
        }
    }
EOF

kubectl apply -f nginx-config.yaml

# Implementar el proxy NGINX
cat <<EOF > nginx-proxy.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-proxy
  namespace: app-namespace
spec:
  replicas: 2
  selector:
    matchLabels:
      app: nginx-proxy
  template:
    metadata:
      labels:
        app: nginx-proxy
    spec:
      containers:
      - name: nginx
        image: nginx:1.25
        ports:
        - containerPort: 443
        volumeMounts:
        - name: nginx-config
          mountPath: /etc/nginx/conf.d
        - name: nginx-certs
          mountPath: /etc/nginx/certs
        livenessProbe:
          httpGet:
            path: /health
            port: 443
            scheme: HTTPS
          initialDelaySeconds: 10
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 443
            scheme: HTTPS
          initialDelaySeconds: 5
          periodSeconds: 5
      volumes:
      - name: nginx-config
        configMap:
          name: nginx-config
      - name: nginx-certs
        secret:
          secretName: nginx-tls
---
apiVersion: v1
kind: Service
metadata:
  name: nginx-proxy-service
  namespace: app-namespace
spec:
  selector:
    app: nginx-proxy
  ports:
  - port: 443
    targetPort: 443
    protocol: TCP
  type: ClusterIP
EOF

kubectl apply -f nginx-proxy.yaml

# Verificar que el proxy se haya desplegado correctamente
kubectl get pods -n app-namespace -l app=nginx-proxy
kubectl get service -n app-namespace
```

## Configuración del ALB con Ingress

Configuraremos un IngressClass y un Ingress para exponer nuestra aplicación:

```bash
# Crear un IngressClass para el ALB
cat <<EOF > ingress-class.yaml
apiVersion: eks.amazonaws.com/v1
kind: IngressClassParams
metadata:
  name: eks-auto-alb
spec:
  scheme: internet-facing
---
apiVersion: networking.k8s.io/v1
kind: IngressClass
metadata:
  name: eks-auto-alb
  annotations:
    ingressclass.kubernetes.io/is-default-class: "true"
spec:
  controller: eks.amazonaws.com/alb
  parameters:
    apiGroup: eks.amazonaws.com
    kind: IngressClassParams
    name: eks-auto-alb
EOF

kubectl apply -f ingress-class.yaml

# Configurar el Ingress con anotaciones para TLS
cat <<EOF > alb-ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: app-ingress
  namespace: app-namespace
  annotations:
    alb.ingress.kubernetes.io/certificate-arn: arn:aws:acm:us-east-1:678702182018:certificate/5e2e3d12-d955-4ed1-a904-568539cf68be
    alb.ingress.kubernetes.io/listen-ports: '[{"HTTPS":443}]'
    alb.ingress.kubernetes.io/ssl-policy: ELBSecurityPolicy-TLS13-1-2-2021-06
    alb.ingress.kubernetes.io/backend-protocol: HTTPS
    alb.ingress.kubernetes.io/healthcheck-protocol: HTTPS
    alb.ingress.kubernetes.io/healthcheck-port: "443"
    alb.ingress.kubernetes.io/healthcheck-path: /health
    alb.ingress.kubernetes.io/target-type: ip
spec:
  ingressClassName: eks-auto-alb
  rules:
  - host: eksautomode.dbravo.org
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: nginx-proxy-service
            port:
              number: 443
EOF

kubectl apply -f alb-ingress.yaml

# Verificar la creación del Ingress
kubectl get ingress -n app-namespace
```

## Configuración de DNS

Configuraremos Route 53 para dirigir el tráfico a nuestro ALB:

```bash
# Esperar a que el ALB se provisione
echo "Esperando a que el ALB se aprovisione (esto puede tomar varios minutos)..."
kubectl wait --for=jsonpath='{.status.loadBalancer.ingress[0].hostname}' ingress/app-ingress -n app-namespace --timeout=5m

# Obtener la dirección DNS del ALB
export ALB_DNS=$(kubectl get ingress app-ingress -n app-namespace -o jsonpath='{.status.loadBalancer.ingress[0].hostname}')
echo "ALB DNS: ${ALB_DNS}"

# Obtener el ID de la zona hospedada de Route 53
export HOSTED_ZONE_ID=$(aws route53 list-hosted-zones \
  --query "HostedZones[?Name=='$(echo ${APP_DOMAIN} | sed 's/[^.]*\.//')'].Id" \
  --output text | sed 's/\/hostedzone\///')

# Crear un registro CNAME en Route 53
cat <<EOF > route53-record.json
{
  "Changes": [
    {
      "Action": "UPSERT",
      "ResourceRecordSet": {
        "Name": "${APP_DOMAIN}",
        "Type": "CNAME",
        "TTL": 300,
        "ResourceRecords": [
          {
            "Value": "${ALB_DNS}"
          }
        ]
      }
    }
  ]
}
EOF

aws route53 change-resource-record-sets \
  --hosted-zone-id ${HOSTED_ZONE_ID} \
  --change-batch file://route53-record.json
```

## Implementación de Network Policies

Implementaremos Network Policies para restringir el tráfico entre pods:

```bash
cat <<EOF > network-policy.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: restrict-backend-access
  namespace: app-namespace
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: app-2048
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: nginx-proxy
    ports:
    - protocol: TCP
      port: 80
EOF

kubectl apply -f network-policy.yaml
```

## Verificación y pruebas

Para verificar que todo funciona correctamente:

```bash
# Verificar certificado del ALB
echo | openssl s_client -connect ${APP_DOMAIN}:443 -servername ${APP_DOMAIN} 2>/dev/null | openssl x509 -noout -text | grep Issuer

# Crear pod de prueba para verificaciones internas
kubectl run test-curl --image=curlimages/curl --rm -it -- sh

# Desde el pod de prueba, verificar la conexión con el proxy NGINX
curl -v --insecure https://nginx-proxy-service.app-namespace.svc.cluster.local:443/health

# Verificar conexión con el servicio backend
curl -v http://app-backend-service.app-namespace.svc.cluster.local:80
```

Finalmente, abre un navegador y visita `https://${APP_DOMAIN}/` para verificar que el juego 2048 se carga correctamente y que la conexión es segura.

## Solución de problemas comunes

### 1. Problema: El secreto del certificado no se encuentra

Si ves un error como:
```
MountVolume.SetUp failed for volume "nginx-certs" : secret "nginx-tls" not found
```

Solución:
- Verifica el estado del certificado: `kubectl get certificate -n app-namespace`
- Verifica los logs de cert-manager: `kubectl logs -n cert-manager -l app=cert-manager -c cert-manager`
- Verifica el ClusterIssuer: `kubectl describe awspcaclusterissuer pca-cluster-issuer`

### 2. Problema: AWS PCA Issuer no puede emitir certificados

Verifica la configuración de IAM:

```bash
# Obtener el ARN del rol de la cuenta de servicio
ROLE_ARN=$(kubectl get serviceaccount -n cert-manager aws-pca-issuer -o jsonpath='{.metadata.annotations.eks\.amazonaws\.com/role-arn}')

# Extraer el nombre del rol
ROLE_NAME=$(echo $ROLE_ARN | cut -d '/' -f 2)

# Verificar políticas adjuntas
aws iam list-attached-role-policies --role-name $ROLE_NAME

# Verificar la relación de confianza
aws iam get-role --role-name $ROLE_NAME --query 'Role.AssumeRolePolicyDocument' --output text
```

### 3. Problema: El ALB no se crea correctamente

Verifica los logs del controlador de AWS Load Balancer:

```bash
kubectl logs -n kube-system -l app.kubernetes.io/name=aws-load-balancer-controller
```

### 4. Problema: El certificado no se muestra como válido

Verifica si los nombres DNS en el certificado son correctos:

```bash
kubectl get secret nginx-tls -n app-namespace -o jsonpath='{.data.tls\.crt}' | base64 -d | openssl x509 -text -noout
```

## Consideraciones de seguridad

1. **Rotación de certificados**: cert-manager renovará automáticamente los certificados antes de que expiren.

2. **Monitoreo**: Configura alarmas para vigilar la expiración de certificados:

```bash
# Ejemplo de CloudWatch Alarm para certificados próximos a expirar
aws cloudwatch put-metric-alarm \
  --alarm-name CertificateExpiration \
  --alarm-description "Alert when certificates are 30 days from expiry" \
  --metric-name DaysToExpiry \
  --namespace AWS/CertificateManager \
  --statistic Minimum \
  --period 86400 \
  --threshold 30 \
  --comparison-operator LessThanThreshold \
  --dimensions Name=CertificateArn,Value=${PUBLIC_CERT_ARN}
```

3. **Hardening de NGINX**: Utiliza las mejores prácticas de seguridad para configurar NGINX.

4. **Encriptación entre nodos**: EKS Auto Mode con instancias Nitro proporciona encriptación automática del tráfico entre nodos.

5. **Acceso a secretos**: Limita quién puede acceder a los secretos del clúster que contienen los certificados.

---

Este documento proporciona una solución completa para implementar una arquitectura de encriptación end-to-end en entornos Amazon EKS Auto Mode, incluso cuando se trabaja con imágenes de contenedores de terceros que no pueden modificarse.
