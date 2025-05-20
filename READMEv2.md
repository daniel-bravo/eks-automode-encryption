# Arquitectura de Encriptación End-to-End para Amazon EKS Auto Mode
#### *Una solución para encriptar tráfico ALB > Ingress > Pod con contenedores de terceros*

## Resumen Ejecutivo

Este documento presenta una arquitectura de referencia para implementar encriptación end-to-end en entornos Amazon EKS Auto Mode, abordando específicamente el desafío de trabajar con imágenes de contenedores de terceros que no pueden ser modificadas. La solución propuesta mantiene la seguridad en tránsito a lo largo de toda la ruta de comunicación, utilizando servicios nativos de AWS y respetando las limitaciones de EKS Auto Mode.

## Desafío Técnico

Las organizaciones que migran a Kubernetes frecuentemente enfrentan el reto de mantener encriptación end-to-end cuando:

1. Utilizan EKS Auto Mode donde AWS gestiona los componentes de infraestructura
2. Deben trabajar con imágenes de contenedores de terceros que no pueden modificarse
3. Necesitan cumplir con requisitos de seguridad y regulaciones que exigen encriptación en tránsito

Esta arquitectura resuelve estos desafíos proporcionando encriptación completa desde el cliente hasta las puertas del contenedor.

---

## Arquitectura de la Solución

![Diagrama de Arquitectura de Encriptación](https://example.com/eks-encryption-diagram.png)

La arquitectura implementa una estrategia de encriptación en capas:

### Componentes Clave

1. **Application Load Balancer (ALB)**: 
   - Gestionado automáticamente por EKS Auto Mode
   - Termina HTTPS desde el cliente usando certificados públicos de ACM
   - Reencripta el tráfico para la comunicación interna

2. **Proxy NGINX**:
   - Desplegado como un componente dedicado dentro del clúster
   - Recibe tráfico HTTPS desde el ALB
   - Actúa como punto final de terminación TLS antes de los pods
   - Utiliza certificados de AWS Private CA

3. **Pods de Aplicación**:
   - Contenedores de terceros sin modificar
   - Reciben tráfico HTTP desde el proxy NGINX dentro del perímetro seguro del clúster

4. **Servicios de Gestión de Certificados**:
   - AWS Certificate Manager (ACM) para certificados públicos
   - AWS Private Certificate Authority (PCA) para certificados privados internos
   - cert-manager para automatizar la gestión de certificados dentro del clúster

### Flujo de Tráfico y Encriptación

1. **Cliente a ALB**:
   - Protocolo: HTTPS (TLS 1.2/1.3)
   - Certificado: Público (AWS Certificate Manager)
   - Encriptación: TLS con certificados públicos confiables

2. **ALB a Proxy NGINX**:
   - Protocolo: HTTPS (TLS 1.2/1.3)
   - Certificado: Privado (AWS Private CA)
   - Encriptación: TLS con certificados privados internos

3. **Proxy NGINX a Pods**:
   - Protocolo: HTTP
   - Seguridad: Tráfico confinado dentro del perímetro seguro del clúster
   - Network Policies de Kubernetes que restringen el acceso

4. **Entre Pods/Nodos dentro del clúster**:
   - Encriptación automática: Todos los nodos Nitro implementan encriptación en tránsito a nivel de hardware
   - Protocolo: Encriptación transparente por VPC

---

## Ventajas de la Arquitectura

- **Cumplimiento**: Mantiene encriptación en tránsito para cumplir con requisitos regulatorios
- **Compatibilidad**: Funciona con imágenes de contenedores de terceros sin modificaciones
- **Servicios Nativos**: Aprovecha servicios AWS (EKS Auto Mode, ACM, Private CA)
- **Simplicidad Operativa**: Elimina la necesidad de gestionar certificados manualmente
- **Seguridad en Capas**: Implementa seguridad a nivel de red, transporte y aplicación
- **Encriptación Automática entre Nodos**: Aprovecha la encriptación transparente de las instancias Nitro

---

## Tráfico dentro del clúster

### Encriptación automática en instancias Nitro

Una ventaja clave de EKS Auto Mode con instancias Nitro es la encriptación automática del tráfico entre nodos:

> "En los sistemas Nitro, el tráfico de red entre instancias Nitro, cuando están en una VPC, se encripta de forma transparente de manera predeterminada."
> — [AWS Nitro System Documentation](https://docs.aws.amazon.com/systems-manager/latest/userguide/nitro-system-encryption.html)

Beneficios de la encriptación automática para EKS Auto Mode:

1. **Transparencia operativa**: No requiere configuración adicional ni cambios en el código
2. **Sin impacto en el rendimiento**: La encriptación se realiza por hardware dedicado
3. **Activación automática**: Funciona automáticamente en todas las instancias Nitro
4. **Algoritmo robusto**: Utiliza AES-256-GCM para la encriptación de datos

Esta encriptación a nivel de infraestructura proporciona una capa adicional de seguridad para el tráfico entre pods que se ejecutan en diferentes nodos del clúster, complementando nuestra arquitectura de encriptación de extremo a extremo.

---

## Implementación de Referencia

### Prerrequisitos 

- Cuenta AWS con permisos para EKS, ACM, Private CA e IAM
- Nombre de dominio registrado para la configuración de DNS
- AWS CLI, kubectl y eksctl configurados

### Paso 1: Creación del Clúster EKS Auto Mode

```bash
export CLUSTER_NAME="eks-automode-secure"
export AWS_REGION="us-east-1"

cat <<EOF > cluster-config.yaml
apiVersion: eksctl.io/v1alpha5
kind: ClusterConfig
metadata:
  name: ${CLUSTER_NAME}
  region: ${AWS_REGION}
  version: "1.32"
autoModeConfig:
  enabled: true
iam:
  withOIDC: true
vpc:
  clusterEndpoints:
    privateAccess: true
    publicAccess: true
EOF

eksctl create cluster -f cluster-config.yaml
```

### Paso 2: Configuración de AWS Certificate Manager

```bash
# Solicitar certificado público para ALB
export APP_DOMAIN="app.example.com"

aws acm request-certificate \
  --domain-name ${APP_DOMAIN} \
  --validation-method DNS \
  --region ${AWS_REGION}

# Guardar ARN del certificado
export PUBLIC_CERT_ARN=$(aws acm list-certificates \
  --query "CertificateSummaryList[?DomainName=='${APP_DOMAIN}'].CertificateArn" \
  --output text)
```

### Paso 3: Configuración de AWS Private CA

```bash
# Crear CA privada
aws acm-pca create-certificate-authority \
  --certificate-authority-configuration file://ca-config.json \
  --certificate-authority-type "ROOT" \
  --tags Key=Environment,Value=Production

# Guardar el ARN de la CA privada
export CA_ARN=$(aws acm-pca list-certificate-authorities \
  --query "CertificateAuthorities[?Status=='ACTIVE'].Arn" \
  --output text)

echo "CA privada ARN: ${CA_ARN}"
```

### Paso 4: Instalación y configuración de cert-manager

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

### Paso 5: Instalar el AWS PCA Issuer para cert-manager

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

aws iam create-policy \
  --policy-name AWSPCAIssuerPolicy \
  --policy-document file://pca-issuer-policy.json


#Asociar el IAM OpenID Connect provider al cluster

eksctl utils associate-iam-oidc-provider --region=us-east-1 --cluster=${CLUSTER_NAME} --approve

# Configurar cuenta de servicio con IRSA
eksctl create iamserviceaccount \
  --cluster=${CLUSTER_NAME} \
  --namespace=cert-manager \
  --name=aws-pca-issuer \
  --attach-policy-arn=arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):policy/AWSPCAIssuerPolicy \
  --approve

# Instalar el complemento AWS PCA Issuer
helm repo add awspca https://cert-manager.github.io/aws-privateca-issuer
helm repo update
helm install aws-pca-issuer awspca/aws-privateca-issuer \
  --namespace cert-manager
```

### Paso 6: Crear AWSPCAIssuer para emitir certificados

```bash
cat <<EOF > awspca-issuer.yaml
apiVersion: awspca.cert-manager.io/v1beta1
kind: AWSPCAIssuer
metadata:
  name: pca-issuer
  namespace: app-namespace
spec:
  arn: ${CA_ARN}
  region: ${AWS_REGION}
EOF


```

### Paso 7: Crear namespace para la aplicación

```bash
kubectl create namespace app-namespace

kubectl apply -f awspca-issuer.yaml
```

### Paso 8: Implementar el juego 2048 como aplicación de demostración

```bash
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
```

### Paso 9: Implementar el proxy NGINX con TLS

```bash
# Creamos un certificado para el proxy usando cert-manager
cat <<EOF > proxy-certificate.yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: nginx-proxy-cert
  namespace: app-namespace
spec:
  secretName: nginx-tls
  duration: 2160h0m0s  # 90 days
  renewBefore: 360h0m0s  # 15 days
  subject:
    organizations:
      - "Your Organization"
  dnsNames:
    - "nginx-proxy-service.app-namespace.svc.cluster.local"
    - "*.${APP_DOMAIN}"
  issuerRef:
    name: pca-issuer
    kind: AWSPCAIssuer
    group: awspca.cert-manager.io
EOF

kubectl apply -f proxy-certificate.yaml
```

```bash
# ConfigMap para NGINX
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
```

```bash
# Deployment del Proxy NGINX
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
```

### Paso 10: Configurar el Ingress con ALB

```bash
cat <<EOF > alb-ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: app-ingress
  namespace: app-namespace
  annotations:
    kubernetes.io/ingress.class: alb
    alb.ingress.kubernetes.io/scheme: internet-facing
    alb.ingress.kubernetes.io/certificate-arn: ${PUBLIC_CERT_ARN}
    alb.ingress.kubernetes.io/listen-ports: '[{"HTTPS":443}]'
    alb.ingress.kubernetes.io/ssl-policy: ELBSecurityPolicy-TLS13-1-2-2021-06
    alb.ingress.kubernetes.io/backend-protocol: HTTPS
    alb.ingress.kubernetes.io/healthcheck-protocol: HTTPS
    alb.ingress.kubernetes.io/healthcheck-port: "443"
    alb.ingress.kubernetes.io/healthcheck-path: /health
    alb.ingress.kubernetes.io/target-type: ip
spec:
  rules:
  - host: ${APP_DOMAIN}
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
```

### Paso 11: Configurar Route 53 para apuntar al ALB

```bash
# Esperar a que el Ingress tenga una dirección
echo "Esperando a que el ALB se aprovisione. Esto puede tomar unos minutos..."
kubectl wait --for=jsonpath='{.status.loadBalancer.ingress[0].hostname}' ingress/app-ingress -n app-namespace --timeout=5m

# Obtener la dirección DNS del ALB
export ALB_DNS=$(kubectl get ingress app-ingress -n app-namespace -o jsonpath='{.status.loadBalancer.ingress[0].hostname}')
echo "ALB DNS: ${ALB_DNS}"

# Configurar Route 53 (asumiendo que la zona ya existe)
export HOSTED_ZONE_ID=$(aws route53 list-hosted-zones \
  --query "HostedZones[?Name=='example.com.'].Id" \
  --output text | sed 's/\/hostedzone\///')

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

### Paso 12: Implementar Network Policies para mayor seguridad

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

---

## Consideraciones de Seguridad

### Gestión de Certificados

1. **Rotación Automática**: cert-manager se encarga de renovar automáticamente los certificados
2. **Monitoreo**: Configurar alertas para certificados próximos a expirar
3. **Auditoria**: Activar registros de AWS Private CA

### Hardening de NGINX

1. **Configuración de Ciphers**: Usar solo cifrados fuertes
2. **Updates**: Mantener la imagen de NGINX actualizada
3. **Minimización**: Usar imágenes base reducidas (Alpine)

---

## Monitoreo y Operación

### Métricas Clave

- Tasa de éxito de handshakes TLS
- Latencia de establecimiento de conexión
- Caducidad de certificados
- Tasa de errores SSL/TLS

### Configuración de Alarmas

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

---

## Pruebas de Verificación

Para validar la implementación, se recomiendan las siguientes pruebas:

### 1. Verificación de Encriptación Cliente-ALB

```bash
# Verificar certificado público
openssl s_client -connect ${APP_DOMAIN}:443 -servername ${APP_DOMAIN}
```

### 2. Verificación de Encriptación ALB-NGINX

```bash
# Crear pod de prueba
kubectl run test-curl --image=curlimages/curl --rm -it -- sh

# Desde el pod, verificar
curl -v --insecure https://nginx-proxy-service.app-namespace.svc.cluster.local:443/health
```

### 3. Verificación de funcionamiento del juego 2048

Abrir un navegador web y visitar `https://${APP_DOMAIN}/` para verificar que el juego 2048 se carga correctamente y que la conexión es segura (certificado válido).

---

## Conclusión

Esta arquitectura de referencia proporciona una solución completa para implementar encriptación end-to-end en entornos Amazon EKS Auto Mode, cumpliendo con requisitos de seguridad estrictos incluso cuando se trabaja con imágenes de contenedores de terceros que no pueden modificarse.

Al implementar esta solución, las organizaciones pueden:

- Cumplir con requisitos regulatorios de encriptación en tránsito
- Minimizar la superficie de ataque al mantener el tráfico encriptado
- Aprovechar servicios nativos de AWS para simplificar la operación
- Integrar de forma segura aplicaciones de terceros en sus arquitecturas cloud
- Beneficiarse de la encriptación automática entre nodos que proveen las instancias Nitro

---

## Referencias

1. [Documentación de Amazon EKS Auto Mode](https://docs.aws.amazon.com/eks/latest/userguide/automode.html)
2. [Mejores prácticas de seguridad de AWS para EKS](https://aws.github.io/aws-eks-best-practices/security/docs/)
3. [AWS Certificate Manager User Guide](https://docs.aws.amazon.com/acm/latest/userguide/acm-overview.html)
4. [AWS Private Certificate Authority](https://docs.aws.amazon.com/privateca/latest/userguide/PcaWelcome.html)
5. [Encriptación en tránsito en sistemas AWS Nitro](https://docs.aws.amazon.com/systems-manager/latest/userguide/nitro-system-encryption.html)
6. [Guía de Network Policies de Kubernetes](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
7. [Documentación de cert-manager](https://cert-manager.io/docs/)
8. [AWS PCA Issuer para cert-manager](https://github.com/cert-manager/aws-privateca-issuer)

---

*Este documento es una arquitectura de referencia y puede requerir ajustes según los requisitos específicos de cada organización.*

© 2025 - Arquitectura de Encriptación End-to-End para Amazon EKS Auto Mode
