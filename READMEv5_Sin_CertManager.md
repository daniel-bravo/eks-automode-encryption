# Guía Completa: Implementación de Encriptación End-to-End en EKS Auto Mode SIN Cert-Manager

Esta guía detalla la implementación de una arquitectura de encriptación completa en Amazon EKS Auto Mode, **eliminando cert-manager** y utilizando gestión manual de certificados AWS PCA junto con certificados públicos ACM para el despliegue del juego 2048 como aplicación de demostración.

## Índice
1. [Requisitos previos](#requisitos-previos)
2. [Arquitectura de la solución](#arquitectura-de-la-solución)
3. [Creación del clúster EKS Auto Mode](#creación-del-clúster-eks-auto-mode)
4. [Configuración de AWS Certificate Manager (ACM)](#configuración-de-aws-certificate-manager-acm)
5. [Configuración de AWS Private CA](#configuración-de-aws-private-ca)
6. [Generación manual de certificados privados](#generación-manual-de-certificados-privados)
7. [Despliegue de la aplicación 2048](#despliegue-de-la-aplicación-2048)
8. [Implementación del proxy NGINX](#implementación-del-proxy-nginx)
9. [Configuración del ALB con Ingress](#configuración-del-alb-con-ingress)
10. [Configuración de DNS](#configuración-de-dns)
11. [Verificación y pruebas](#verificación-y-pruebas)
12. [Solución de problemas comunes](#solución-de-problemas-comunes)
13. [Consideraciones de seguridad](#consideraciones-de-seguridad)

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
  - openssl
- Un nombre de dominio registrado que puedas controlar para la configuración de DNS

```bash
# Verificar que las herramientas estén instaladas correctamente
aws --version
kubectl version --client
eksctl version
openssl version
```

## Arquitectura de la solución

**Diferencia clave**: Esta arquitectura implementa las mismas capas de encriptación pero **sin cert-manager**:

1. **Cliente a ALB**: Encriptación HTTPS con certificados públicos (ACM) - gestionados automáticamente por AWS
2. **ALB a NGINX Proxy**: Encriptación HTTPS con certificados privados (AWS Private CA) - **gestionados manualmente**
3. **Dentro del clúster**: 
   - Tráfico HTTP entre NGINX Proxy y Pods (dentro del perímetro seguro)
   - Encriptación automática entre nodos gracias a instancias Nitro

**Fuentes oficiales de referencia**:
- [AWS Private CA Kubernetes Integration](https://docs.aws.amazon.com/privateca/latest/userguide/PcaKubernetes.html)
- [AWS Load Balancer Controller Annotations](https://kubernetes-sigs.github.io/aws-load-balancer-controller/latest/guide/ingress/annotations/)

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

Posteriormente, es necesario agregar los addons como metrics-server:

```bash
aws eks update-addon --cluster-name eks-auto-mode-secure-demo --addon-name metrics-server --addon-version latest --region us-east-1
```

## Configuración de AWS Certificate Manager (ACM)

**Fuente oficial**: [SSL certificates for Application Load Balancer](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/https-listener-certificates.html)

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

***NOTA***: Si se desea utilizar un certificado propio es necesario importarlo a ACM y una vez importado hacer referencia a este a través de su ARN.

## Configuración de AWS Private CA

**Fuente oficial**: [Issue private end-entity certificates](https://docs.aws.amazon.com/privateca/latest/userguide/PcaIssueCert.html)

**NOTA IMPORTANTE**: Este tutorial asume que ya tienes una AWS Private CA configurada y activa en tu cuenta.

Para obtener el ARN de tu CA existente:

```bash
# Listar todas las CAs en tu cuenta
aws acm-pca list-certificate-authorities --region ${AWS_REGION}

# Configurar el ARN de tu CA existente (reemplazar con tu ARN real)
export CA_ARN="arn:aws:acm-pca:us-east-1:123456789012:certificate-authority/12345678-1234-1234-1234-123456789012"

# Verificar que la CA está activa
aws acm-pca describe-certificate-authority --certificate-authority-arn ${CA_ARN} --query 'CertificateAuthority.Status'
```

Si necesitas crear una nueva CA privada, puedes hacerlo desde la **Consola de AWS > Certificate Manager > Private CAs** siguiendo estos pasos:

1. **Crear CA privada**:
   - Ir a AWS Certificate Manager > Private CAs
   - Clic en "Create private CA"
   - Seleccionar "Root CA"
   - Configurar los detalles de la organización
   - Crear y activar la CA

2. **Una vez creada, obtener su ARN** desde la consola y configurarlo en la variable de entorno arriba.

## Generación de certificados privados via Consola AWS

**Fuente oficial**: [AWS Certificate Manager Private CA Console Guide](https://docs.aws.amazon.com/privateca/latest/userguide/PcaIssueCert.html)

En lugar de usar CLI, vamos a generar los certificados directamente desde la **Consola de AWS** para mayor facilidad:

### Paso 1: Generar CSR localmente

Primero necesitamos generar la clave privada y el CSR (Certificate Signing Request) para NGINX:

```bash
# Configurar variables para el certificado interno
export INTERNAL_DOMAIN="nginx-proxy-service.app-namespace.svc.cluster.local"

# Crear directorio para certificados
mkdir -p certificates
cd certificates

# Generar clave privada para el servicio NGINX
openssl genrsa -out nginx-private-key.pem 2048

# Generar CSR para NGINX con múltiples nombres DNS
cat <<EOF > nginx.conf
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = Washington
L = Seattle
O = Mi Empresa
OU = IT
CN = ${INTERNAL_DOMAIN}

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${INTERNAL_DOMAIN}
DNS.2 = nginx-proxy-service
DNS.3 = nginx-proxy-service.app-namespace
EOF

# Generar CSR
openssl req -new -key nginx-private-key.pem -out nginx.csr -config nginx.conf

echo "CSR generado: nginx.csr"
echo "Clave privada: nginx-private-key.pem"

# Volver al directorio principal
cd ..
```

### Paso 2: Emitir certificado usando la Consola AWS

Ahora usaremos la **Consola de AWS** para emitir el certificado:

#### 2.1. Abrir la Consola de AWS Private CA
1. Ve a **AWS Console > Certificate Manager > Private CAs**
2. Selecciona tu CA privada existente
3. Clic en **"Issue certificate"**

#### 2.2. Configurar la solicitud de certificado
1. **Certificate signing request (CSR)**:
   - Selecciona **"Provide your own CSR"**
   - Abre el archivo `certificates/nginx.csr` en un editor de texto
   - Copia todo el contenido (incluyendo `-----BEGIN CERTIFICATE REQUEST-----` y `-----END CERTIFICATE REQUEST-----`)
   - Pega el contenido en el campo de texto de la consola

2. **Certificate template**:
   - Selecciona **"EndEntityServerAuthCertificate/V1"**

3. **Validity period**:
   - Ingresa **90** para Days
   - O selecciona el período que prefieras

4. **Signing algorithm**:
   - Deja el valor por defecto: **SHA256WITHRSA**

#### 2.3. Emitir el certificado
1. Clic en **"Issue certificate"**
2. **Importante**: Copia el **Certificate ARN** que aparece - lo necesitaremos después
3. Espera unos minutos a que el certificado se emita (estado debe cambiar a "Issued")

### Paso 3: Descargar el certificado desde la consola

Una vez emitido el certificado:

#### 3.1. Descargar usando la Consola
1. En la página de tu CA privada, ve a la pestaña **"Certificates"**
2. Encuentra tu certificado recién emitido
3. Clic en el **Certificate ID**
4. En la página de detalles del certificado:
   - Clic en **"Download certificate body"** → guarda como `certificates/nginx-cert.pem`
   - Clic en **"Download certificate chain"** → guarda como `certificates/nginx-cert-chain.pem`

#### 3.2. O descargar usando CLI (opcional)
Si prefieres usar CLI con el ARN del certificado:

```bash
# Reemplazar CERTIFICATE_ARN con el ARN copiado de la consola
export NGINX_CERT_ARN="arn:aws:acm-pca:us-east-1:123456789012:certificate-authority/your-ca-id/certificate/your-cert-id"

cd certificates

# Obtener el certificado emitido
aws acm-pca get-certificate \
  --certificate-authority-arn ${CA_ARN} \
  --certificate-arn ${NGINX_CERT_ARN} \
  --query 'Certificate' \
  --output text > nginx-cert.pem

# Obtener la cadena de certificados
aws acm-pca get-certificate \
  --certificate-authority-arn ${CA_ARN} \
  --certificate-arn ${NGINX_CERT_ARN} \
  --query 'CertificateChain' \
  --output text > nginx-cert-chain.pem

cd ..
```

### Paso 4: Crear certificado completo

```bash
cd certificates

# Crear certificado completo (certificado + cadena)
cat nginx-cert.pem nginx-cert-chain.pem > nginx-full-cert.pem

# Verificar que el certificado es válido
openssl x509 -in nginx-full-cert.pem -text -noout | grep -A5 "Subject:"

# Verificar que la clave privada coincide con el certificado
openssl x509 -noout -modulus -in nginx-full-cert.pem | openssl md5
openssl rsa -noout -modulus -in nginx-private-key.pem | openssl md5
# Los dos hashes deben ser idénticos

cd ..

echo "Certificado privado generado exitosamente para NGINX"
echo "Archivos creados:"
echo "  - certificates/nginx-private-key.pem (clave privada)"
echo "  - certificates/nginx-full-cert.pem (certificado completo)"
```

### Verificación visual en la consola

Para verificar que todo está correcto, en la **Consola de AWS**:

1. Ve a **Certificate Manager > Private CAs**
2. Selecciona tu CA
3. Pestaña **"Certificates"**
4. Deberías ver tu certificado con estado **"Issued"**
5. Los detalles deben mostrar los nombres DNS que configuraste

Esta aproximación es mucho más visual y fácil de seguir, especialmente para quienes prefieren interfaces gráficas sobre comandos CLI complejos.

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

**Cambio principal**: En lugar de usar cert-manager, instalaremos manualmente el certificado generado:

```bash
# Crear secret TLS manualmente con los certificados generados
kubectl create secret tls nginx-tls \
  --cert=certificates/nginx-full-cert.pem \
  --key=certificates/nginx-private-key.pem \
  --namespace=app-namespace

# Verificar que el secret se creó correctamente
kubectl get secret nginx-tls -n app-namespace
kubectl describe secret nginx-tls -n app-namespace

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
    alb.ingress.kubernetes.io/certificate-arn: ${PUBLIC_CERT_ARN}
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

# Verificar la creación del Ingress
kubectl get ingress -n app-namespace
```

## Configuración de DNS

Configuraremos Route 53 para dirigir el tráfico a nuestro ALB:

```bash
# Esperar a que el ALB se provisione
echo "Esperando a que el ALB se aprovisione (esto puede tomar varios minutos)..."
kubectl wait --for=jsonpath='{.status.loadBalancer.ingress[0].hostname}' ingress/app-ingress -n app-namespace --timeout=10m

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
# Verificar certificado del ALB (debe mostrar un certificado público válido)
echo | openssl s_client -connect ${APP_DOMAIN}:443 -servername ${APP_DOMAIN} 2>/dev/null | openssl x509 -noout -text | grep Issuer

# Verificar que el secret TLS se creó correctamente
kubectl get secret nginx-tls -n app-namespace -o jsonpath='{.data.tls\.crt}' | base64 -d | openssl x509 -text -noout | grep -A5 "Subject:"

# Crear pod de prueba para verificaciones internas
kubectl run test-curl --image=curlimages/curl --rm -it --restart=Never -- sh

# Desde el pod de prueba, verificar la conexión con el proxy NGINX
# curl -v --insecure https://nginx-proxy-service.app-namespace.svc.cluster.local:443/health

# Verificar conexión con el servicio backend
# curl -v http://app-backend-service.app-namespace.svc.cluster.local:80
```

Finalmente, abre un navegador y visita `https://${APP_DOMAIN}/` para verificar que el juego 2048 se carga correctamente y que la conexión es segura.

## Renovación manual de certificados via Consola AWS

**Importante**: Sin cert-manager, la renovación es manual. Aquí está el proceso usando la **Consola de AWS**:

### Script para verificar expiración

```bash
# Script para verificar expiración de certificados
cat <<EOF > check-cert-expiry.sh
#!/bin/bash
CERT_FILE="certificates/nginx-full-cert.pem"

if [ ! -f "\${CERT_FILE}" ]; then
    echo "Archivo de certificado no encontrado: \${CERT_FILE}"
    exit 1
fi

EXPIRY_DATE=\$(openssl x509 -enddate -noout -in \${CERT_FILE} | cut -d= -f2)
EXPIRY_EPOCH=\$(date -d "\${EXPIRY_DATE}" +%s)
CURRENT_EPOCH=\$(date +%s)
DAYS_UNTIL_EXPIRY=\$(( (EXPIRY_EPOCH - CURRENT_EPOCH) / 86400 ))

echo "Certificado expira en \${DAYS_UNTIL_EXPIRY} días (\${EXPIRY_DATE})"

if [ \${DAYS_UNTIL_EXPIRY} -le 30 ]; then
    echo "¡ADVERTENCIA! El certificado expira pronto. Renovar siguiendo estos pasos:"
    echo ""
    echo "1. Ir a AWS Console > Certificate Manager > Private CAs"
    echo "2. Seleccionar tu CA privada"
    echo "3. Clic en 'Issue certificate'"
    echo "4. Usar el CSR existente en certificates/nginx.csr"
    echo "5. Descargar el nuevo certificado"
    echo "6. Actualizar el secret en Kubernetes"
    echo ""
elif [ \${DAYS_UNTIL_EXPIRY} -le 7 ]; then
    echo "¡CRÍTICO! El certificado expira en menos de 7 días. ¡Renovar INMEDIATAMENTE!"
else
    echo "El certificado está vigente."
fi
EOF

chmod +x check-cert-expiry.sh
```

### Proceso de renovación paso a paso

Cuando necesites renovar (recomendado: 30 días antes de expirar):

#### 1. Usar el CSR existente para solicitar nuevo certificado
```bash
# El archivo certificates/nginx.csr puede reutilizarse
echo "Usar el archivo CSR existente: certificates/nginx.csr"
echo "Contenido del CSR:"
cat certificates/nginx.csr
```

#### 2. Emitir nuevo certificado en la Consola AWS
1. **AWS Console > Certificate Manager > Private CAs**
2. Seleccionar tu CA privada
3. Clic en **"Issue certificate"**
4. **"Provide your own CSR"** → usar `certificates/nginx.csr`
5. Misma configuración que antes:
   - Template: **EndEntityServerAuthCertificate/V1**
   - Validity: **90 days**
   - Algorithm: **SHA256WITHRSA**
6. **Issue certificate** y copiar el nuevo Certificate ARN

#### 3. Descargar nuevo certificado
- Descargar **certificate body** → `certificates/nginx-cert-new.pem`
- Descargar **certificate chain** → `certificates/nginx-cert-chain-new.pem`

#### 4. Actualizar archivos y secret en Kubernetes
```bash
cd certificates

# Crear nuevo certificado completo
cat nginx-cert-new.pem nginx-cert-chain-new.pem > nginx-full-cert-new.pem

# Verificar el nuevo certificado
openssl x509 -in nginx-full-cert-new.pem -text -noout | grep -A5 "Subject:"

# Verificar que coincide con la clave privada existente
openssl x509 -noout -modulus -in nginx-full-cert-new.pem | openssl md5
openssl rsa -noout -modulus -in nginx-private-key.pem | openssl md5
# Los hashes deben ser idénticos

# Backup del certificado anterior
kubectl get secret nginx-tls -n app-namespace -o yaml > nginx-tls-backup-$(date +%Y%m%d).yaml

# Crear nuevo secret temporalmente
kubectl create secret tls nginx-tls-new \
  --cert=nginx-full-cert-new.pem \
  --key=nginx-private-key.pem \
  --namespace=app-namespace

# Reemplazar el secret original
kubectl delete secret nginx-tls -n app-namespace
kubectl create secret tls nginx-tls \
  --cert=nginx-full-cert-new.pem \
  --key=nginx-private-key.pem \
  --namespace=app-namespace

# Reiniciar los pods de NGINX para cargar el nuevo certificado
kubectl rollout restart deployment/nginx-proxy -n app-namespace

# Limpiar archivos temporales
mv nginx-full-cert.pem nginx-full-cert-old.pem
mv nginx-full-cert-new.pem nginx-full-cert.pem

cd ..

echo "Certificado renovado exitosamente usando la Consola AWS"
```

### Programar verificaciones regulares

Crea un recordatorio para verificar certificados:

```bash
# Crear script de monitoreo semanal
cat <<EOF > weekly-cert-check.sh
#!/bin/bash
echo "=== Verificación semanal de certificados - \$(date) ==="
./check-cert-expiry.sh
echo ""
echo "Próxima verificación programada para: \$(date -d '+7 days')"
EOF

chmod +x weekly-cert-check.sh

# Ejecutar verificación inicial
./check-cert-expiry.sh
```

### Ventajas del método con Consola AWS:
- ✅ **Visual**: Interfaz gráfica fácil de usar
- ✅ **Verificación**: Puedes ver el estado del certificado en tiempo real
- ✅ **Histórico**: Lista de todos los certificados emitidos
- ✅ **Sin CLI**: No necesitas recordar comandos complejos
- ✅ **Validación**: La consola valida el CSR antes de emitir

### Recordatorios importantes:
- 📅 **Verificar semanalmente** con `./check-cert-expiry.sh`
- 🔔 **Renovar 30 días antes** de la expiración
- 💾 **Hacer backup** del secret antes de actualizar
- 🔄 **Reiniciar pods** después de actualizar certificados

## Solución de problemas comunes

### 1. Problema: El secret del certificado no se encuentra

Si ves un error como:
```
MountVolume.SetUp failed for volume "nginx-certs" : secret "nginx-tls" not found
```

Solución:
- Verifica que el secret existe: `kubectl get secret nginx-tls -n app-namespace`
- Regenera el secret si es necesario usando los comandos de la sección anterior

### 2. Problema: AWS PCA no puede emitir certificados

Verifica la configuración de la CA:

```bash
# Verificar estado de la CA
aws acm-pca describe-certificate-authority --certificate-authority-arn ${CA_ARN}

# La CA debe estar en estado "ACTIVE"
```

### 3. Problema: El certificado no es válido

Verifica el certificado generado:

```bash
# Verificar el contenido del certificado
openssl x509 -in certificates/nginx-full-cert.pem -text -noout

# Verificar que la clave privada coincide con el certificado
openssl x509 -noout -modulus -in certificates/nginx-full-cert.pem | openssl md5
openssl rsa -noout -modulus -in certificates/nginx-private-key.pem | openssl md5
# Los hashes deben ser idénticos
```

### 4. Problema: El ALB no se crea correctamente

Verifica los logs del controlador de AWS Load Balancer:

```bash
kubectl logs -n kube-system -l app.kubernetes.io/name=aws-load-balancer-controller
```

### 5. Problema: Los pods de NGINX no inician

Verifica que el secret TLS se haya creado correctamente:

```bash
kubectl describe secret nginx-tls -n app-namespace
kubectl describe pod -l app=nginx-proxy -n app-namespace
```

## Consideraciones de seguridad

1. **Renovación manual**: **CRÍTICO** - Debes establecer recordatorios para renovar certificados antes de que expiren (recomendado: 30 días antes).

2. **Monitoreo de expiración**:

```bash
# Script para verificar expiración de certificados
cat <<EOF > check-cert-expiry.sh
#!/bin/bash
CERT_FILE="certificates/nginx-full-cert.pem"
EXPIRY_DATE=\$(openssl x509 -enddate -noout -in \${CERT_FILE} | cut -d= -f2)
EXPIRY_EPOCH=\$(date -d "\${EXPIRY_DATE}" +%s)
CURRENT_EPOCH=\$(date +%s)
DAYS_UNTIL_EXPIRY=\$(( (EXPIRY_EPOCH - CURRENT_EPOCH) / 86400 ))

echo "Certificado expira en \${DAYS_UNTIL_EXPIRY} días"

if [ \${DAYS_UNTIL_EXPIRY} -le 30 ]; then
    echo "¡ADVERTENCIA! El certificado expira pronto. Considere renovarlo."
fi
EOF

chmod +x check-cert-expiry.sh
```

3. **Backup de certificados**: Mantén backups seguros de:
   - Claves privadas
   - Certificados
   - Configuración de la CA

4. **Acceso a secretos**: Limita quién puede acceder a los secretos del clúster que contienen los certificados.

5. **Auditoría**: Registra todas las operaciones de generación y renovación de certificados.

## Diferencias clave vs. cert-manager

| Aspecto | Con cert-manager | Sin cert-manager (esta guía) |
|---------|------------------|------------------------------|
| **Renovación** | Automática | Manual (scripted) |
| **Complejidad inicial** | Media (configurar issuers) | Baja (comandos directos) |
| **Mantenimiento** | Bajo | Alto (renovaciones manuales) |
| **Control** | Medio | Total |
| **Dependencias** | cert-manager + AWS PCA Issuer | Solo AWS CLI + openssl |
| **Apropiado para** | Producción con muchos certificados | Desarrollo, pocas apps, control total |

---

Esta guía proporciona una alternativa completa a cert-manager para implementar encriptación end-to-end en EKS Auto Mode, manteniendo el control total sobre el proceso de gestión de certificados mientras utilizas las mismas capacidades de AWS Private CA.
