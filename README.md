

**CIBERDEFENSA (V.TUCS.3.25.1)**

**Práctica Grupal N° 3**

## *“Realización de OSINT al ARSAT”*

Contenido

[**OSINT a la empresa de Telecomunicaciones ARSAT	3**](#osint-a-la-empresa-de-telecomunicaciones-arsat)

[Introducción	3](#introducción)

[1\. Perfil de la Organización	3](#1.-perfil-de-la-organización)

[2\. Huella Digital	3](#2.-huella-digital)

[Reconocimiento Inicial	3](#reconocimiento-inicial)

[Mapeo de la Superficie de Ataque Externa	4](#mapeo-de-la-superficie-de-ataque-externa)

[Análisis de Infraestructura DNS	5](#análisis-de-infraestructura-dns)

[Enriquecimiento de Datos y Detección Pasiva de Vulnerabilidades (Shodan)	5](#enriquecimiento-de-datos-y-detección-pasiva-de-vulnerabilidades-\(shodan\))

[Redes Sociales y Aplicaciones Móviles	5](#redes-sociales-y-aplicaciones-móviles)

[3\. Recolección de Información Pública	6](#3.-recolección-de-información-pública)

[Estructura organizacional	6](#estructura-organizacional)

[Correos Electrónicos y Datos de Contacto	7](#correos-electrónicos-y-datos-de-contacto)

[Documentos (Análisis de Metadatos)	7](#documentos-\(análisis-de-metadatos\))

[Análisis de los registros SPF y DMARC	8](#análisis-de-los-registros-spf-y-dmarc)

[Publicaciones y Portales de Datos Abiertos	8](#publicaciones-y-portales-de-datos-abiertos)

[4\. Tecnologías y Superficie de Exposición	9](#4.-tecnologías-y-superficie-de-exposición)

[Stack Tecnológico Web y Proveedores de Terceros	9](#stack-tecnológico-web-y-proveedores-de-terceros)

[Perfilado de Objetivos Críticos	10](#perfilado-de-objetivos-críticos)

[Fuga de Información Tecnológica	10](#fuga-de-información-tecnológica)

[Contexto de Vulnerabilidades	10](#contexto-de-vulnerabilidades)

[Escenario de Ataque Dirigido (Spear Phishing)	10](#escenario-de-ataque-dirigido-\(spear-phishing\))

[6\. Riesgos Reputacionales e Incidentes Públicos	11](#6.-riesgos-reputacionales-e-incidentes-públicos)

[1\. Incidente Público Confirmado: Brechas de Seguridad Física, Corrupción y Espionaje	11](#1.-incidente-público-confirmado:-brechas-de-seguridad-física,-corrupción-y-espionaje)

[2\. Riesgo de Pérdida de Confianza por Fuga de Datos en el Datacenter	11](#2.-riesgo-de-pérdida-de-confianza-por-fuga-de-datos-en-el-datacenter)

[3\. Impacto Mediático por Interrupción de Servicios a Nivel Nacional (DoS)	12](#3.-impacto-mediático-por-interrupción-de-servicios-a-nivel-nacional-\(dos\))

[4\. Percepción de Negligencia Técnica por Exposición de Metadatos	12](#4.-percepción-de-negligencia-técnica-por-exposición-de-metadatos)

[7\. Preguntas de Ciberdefensa	12](#7.-preguntas-de-ciberdefensa)

[Bibliografía/Referencias	15](#bibliografía/referencias)

[Evidencias	15](#evidencias)

# 

# OSINT a la empresa de Telecomunicaciones ARSAT {#osint-a-la-empresa-de-telecomunicaciones-arsat}

## Introducción {#introducción}

El presente trabajo práctico se enmarca en el rol de un equipo de Ciberinteligencia (Blue Team) encargado de aplicar técnicas de **OSINT (Open Source Intelligence)** de manera ética y legal, es decir, recolectando y analizando exclusivamente información pública y de libre acceso, sin infringir sistemas ni vulnerar credenciales.

La organización seleccionada para este análisis es **ARSAT (Empresa Argentina de Soluciones Satelitales S.A.)**, considerada un activo estratégico para la República Argentina por su rol en la conectividad satelital, la Red Federal de Fibra Óptica y el alojamiento de datos críticos del Estado. A lo largo de este informe, se identificará su huella digital, se evaluarán riesgos de ingeniería social y se propondrán medidas defensivas, demostrando cómo el OSINT puede contribuir a fortalecer la ciberdefensa nacional.

## 1\. Perfil de la Organización {#1.-perfil-de-la-organización}

ARSAT es la **Empresa Argentina de Soluciones Satelitales S.A.**, creada en 2006 por la Ley 26.092. [\[1\]](#bookmark=id.bwgs9p38r3s8)

* **Misión y servicios**: Su misión es garantizar la conectividad y la soberanía tecnológica del país. Ofrece servicios mayoristas de conectividad terrestre y satelital, alojamiento en su datacenter y servicios de nube y ciberseguridad.  
* **Su activos más críticos son**:  
  * **Dos satélites geoestacionarios**: El ARSAT-1 y el ARSAT-2.  
  * **Red Federal de Fibra Óptica (REFEFO)**: Más de 34.500 km de fibra que conectan más de 1.000 localidades y a más de 630 proveedores de internet (PyMEs y cooperativas). Es crucial para reducir la brecha digital.  
  * **Centro Nacional de Datos**: Uno de los más seguros de Latinoamérica, con certificación **TIER III** del Uptime Institute.

## 2\. Huella Digital {#2.-huella-digital}

### **Reconocimiento Inicial** {#reconocimiento-inicial}

La fase de reconocimiento pasivo inició con la identificación del dominio principal de la organización: www.arsat.com.ar. La inspección superficial de su sitio web oficial proporciona una visión corporativa estándar, destacando las unidades de negocio principales (conectividad terrestre y satelital, nube, datacenter y ciberseguridad). Este dominio actúa como el punto de anclaje principal para comenzar a mapear la infraestructura tecnológica expuesta en internet.

Para expandir esta huella digital más allá de la navegación web tradicional, se procedió a utilizar la herramienta **theHarvester**. Esta utilidad permite automatizar la recolección pasiva de correos electrónicos, subdominios y direcciones IP desde diversas fuentes públicas , lo cual resulta fundamental para dimensionar la superficie de ataque externa durante el inicio de una auditoría OSINT.

Podemos usar la herramienta TheHarvester la cual automatiza la recopilación de correos, subdominios e IPs desde fuentes públicas para el reconocimiento inicial en auditorías OSINT.

### **Mapeo de la Superficie de Ataque Externa** {#mapeo-de-la-superficie-de-ataque-externa}

Mediante el uso de la herramienta theHarvester [**\[E01\]**](#bookmark=id.jndb45dtw5oh), se automatizó la recolección de activos expuestos en fuentes públicas, logrando perfilar la arquitectura tecnológica de ARSAT. Lejos de ser una simple lista de dominios, el análisis de los más de 280 *hosts* identificados revela una huella digital extensa que amplía considerablemente la superficie de ataque:

* **Exposición de Entornos de Desarrollo y Pruebas:** Se detectó una gran cantidad de subdominios estructurados bajo las nomenclaturas dev, qa y devops (por ejemplo, test-lambda.arsat.com.ar, portal.qa.arsat.com.ar). Desde la perspectiva de un atacante, la exposición pública de estos entornos es altamente atractiva, ya que históricamente suelen poseer configuraciones de seguridad más laxas, credenciales por defecto o versiones de software aún no parcheadas en comparación con los entornos de producción.  
* **Infraestructura DevOps y Telemetría:** El reconocimiento de subdominios expuso el *stack* tecnológico utilizado por los equipos internos. Se evidenció el uso de repositorios de código (GitLab), herramientas de orquestación y contenedores (Portainer, ClusterControl), y sistemas de monitoreo/trazabilidad (Grafana, Prometheus, Sentry, Elastic). Identificar estas tecnologías facilita enormemente la búsqueda dirigida de exploits (CVEs) específicos para dichas plataformas.  
* **Portales de Acceso y Colaboración Interna:** Se lograron mapear puntos críticos de entrada a la red corporativa, destacando la VPN institucional (portal.vpn.arsat.com.ar) y paneles de autenticación unificada o Single Sign-On (como authelia.dev.arsat.com.ar y sso-back.devops.arsat.com.ar). Adicionalmente, se identificó la infraestructura de comunicación interna de los empleados mediante plataformas como Mattermost, Zulip y BigBlueButton (bbb.arsat.com.ar). Estos paneles de inicio de sesión públicos son el objetivo principal para ataques de fuerza bruta, rociado de contraseñas (*password spraying*) o *credential stuffing*.  
* **Gestión de Redes (ASNs):** Se identificaron los Sistemas Autónomos (ASN 13335, 400940 y 52361), lo cual confirma que ARSAT administra sus propias políticas de enrutamiento BGP. Esto es coherente con su rol operativo, pero también demarca con precisión los bloques de direcciones IP (181.209.x.x y 186.33.x.x) que son de su propiedad exclusiva para futuros escaneos pasivos.

### **Análisis de Infraestructura DNS** {#análisis-de-infraestructura-dns}

Mediante la ejecución de la herramienta dnsrecon, se logró enumerar la infraestructura pública de DNS del dominio arsat.com.ar [**\[E02\]**](#bookmark=id.ipwa9ec761bi), obteniendo los siguientes hallazgos clave para la fase de reconocimiento:

* **Servidores de Nombres (NS) y Fingerprinting:** Se identificaron los servidores con autoridad sobre el dominio (ns4, ns5 y ns6). Durante el escaneo, se logró obtener la versión exacta del software utilizado: BIND versión 9.18.49 operando sobre Debian. Esta fuga de información es un dato sensible, ya que permite perfilar los servidores en busca de vulnerabilidades conocidas (CVEs) para esa versión específica.  
* **Comunicaciones Unificadas (Registros SRV):** Se descubrieron registros de servicios internos expuestos, revelando el uso de infraestructura de telefonía VoIP (sip.arsat.com.ar) y un servidor de mensajería instantánea o chat corporativo (XMPP) operando en el puerto 5269\.  
* **Servidores de Correo (MX):** Se mapeó la infraestructura de recepción de correos, identificando los nodos relay.arsat.com.ar y smtp.arsat.com.ar.  
* **Seguridad DNS:** Se verificó que el dominio tiene implementado DNSSEC con sus respectivas firmas criptográficas (ZSK y KSK), lo cual protege a la organización contra ataques de envenenamiento de caché DNS. Además, se identificaron los registros TXT correspondientes a las políticas de seguridad de correo.

### **Enriquecimiento de Datos y Detección Pasiva de Vulnerabilidades (Shodan)** {#enriquecimiento-de-datos-y-detección-pasiva-de-vulnerabilidades-(shodan)}

Para profundizar en el análisis de la infraestructura descubierta en fases anteriores, se cruzó el listado de direcciones IP obtenidas con el motor de búsqueda de dispositivos expuestos Shodan [**\[E03\]**](#bookmark=id.bca0filfde7w). Este procedimiento pasivo permitió identificar un vector de riesgo significativo alojado en la dirección IP 186.33.208.25.

De acuerdo con los registros de la plataforma, este *host* expone el puerto 123/UDP, correspondiente al protocolo de sincronización de tiempo (NTP). El análisis del *banner* capturado revela una fuga de información sensible respecto a la arquitectura del servidor:

* **Divulgación del Sistema Operativo y Servicio:** El registro detalla que el equipo opera bajo el sistema FreeBSD/12.2-STABLE y ejecuta el demonio ntpd en la versión 4.2.8p15.  
* **Vulnerabilidades Inferidas (CVEs):** La exposición pública de la versión exacta del software permite a los motores de inteligencia asociarlo automáticamente con debilidades conocidas. Shodan alerta sobre al menos 5 vulnerabilidades aplicables a esta versión, destacándose fallos críticos (CVSS 9.8) como el **CVE-2018-12327** y el **CVE-2018-7183**. Estos reportes describen desbordamientos de búfer (*buffer overflow*) que, en un escenario de ataque real, podrían permitir a un actor malicioso la ejecución remota de código o la escalada de privilegios.

Desde la perspectiva de la ciberdefensa, aunque no se ha realizado una explotación activa para confirmar el fallo, la sola exposición de este servicio desactualizado representa una vulnerabilidad crítica en el perímetro externo de la organización que requeriría parcheo y remediación inmediata.

### **Redes Sociales y Aplicaciones Móviles** {#redes-sociales-y-aplicaciones-móviles}

**Análisis de Perfiles Oficiales (SOCMINT)**

Para completar el mapeo de la huella digital y evitar la inclusión de falsos positivos o cuentas no oficiales, se procedió a inspeccionar el código fuente del sitio web principal (arsat.com.ar). Esta técnica permitió confirmar de manera fehaciente los canales de comunicación institucionales vinculados directamente por la organización (evidencia en [E04](#bookmark=id.rqnhc5xj7kh)).

Los perfiles oficiales identificados son:

* **LinkedIn:** [linkedin.com/company/2773967/](http://linkedin.com/company/2773967/)  
* **X (Twitter):** [x.com/ARSATSA](http://x.com/ARSATSA)  
* **Facebook:** [facebook.com/arsatsa/](http://facebook.com/arsatsa/)  
* **Instagram:** [instagram.com/arsatok](http://instagram.com/arsatok)  
* **YouTube:** [youtube.com/@ARSATSA](http://youtube.com/@ARSATSA) (ID de canal:UCzMa-xDrzoFGPdmhsewDiA)

Desde la perspectiva del Blue Team, la presencia en **LinkedIn** representa la mayor superficie de exposición técnica, ya que permite a un atacante perfilar a los empleados, conocer sus roles específicos (como administradores de redes o desarrolladores) y mapear el organigrama interno para diseñar campañas dirigidas de Spear Phishing.

**Mapeo de Aplicaciones Móviles**

Mediante el uso de operadores de búsqueda avanzada (Google Dorks) orientados a las principales tiendas de distribución digital, se identificaron aplicaciones móviles bajo la administración de ARSAT, específicamente vinculadas a su plataforma de streaming de contenidos:

| Plataforma | Nombre de la App | Identificador de Paquete | Enlace de Tienda |
| :---- | :---- | :---- | :---- |
| **Android (Google Play)** | CINE.AR Play | com.arsat.odeon.mobile | [Enlace](https://play.google.com/store/apps/details?id=com.arsat.odeon.mobile&hl=es) |
| **iOS (App Store)** | CINE.AR Play | id1236249929 | [Enlace](https://apps.apple.com/be/app/cine-ar-play/id1236249929) |

## 3\. Recolección de Información Pública {#3.-recolección-de-información-pública}

### **Estructura organizacional** {#estructura-organizacional}

Durante la investigación se localizó en el sitio oficial de ARSAT el organigrama correspondiente al año 2026\. Este permitió identificar su estructura general y áreas relevantes para la ciberdefensa, como las gerencias de Ciberseguridad, Tecnología Informática, Operaciones y Servicios Espaciales.

La información fue complementada con perfiles públicos de LinkedIn, donde se observaron cargos vinculados con infraestructura de datacenter, networking, soporte técnico, innovación y operación del NOC.

La combinación de ambas fuentes permite reconstruir parcialmente la estructura tecnológica de la organización. Desde una perspectiva defensiva, esta información resulta sensible porque podría utilizarse para seleccionar objetivos y diseñar campañas de spear phishing más creíbles. ORGANIGRAMA [\[2\]](#bookmark=id.a4e3e9h4pfhv)

### **Correos Electrónicos y Datos de Contacto** {#correos-electrónicos-y-datos-de-contacto}

Mediante el uso de la herramienta theHarvester, se recolectaron direcciones de correo electrónico expuestas públicamente, identificando casillas de contacto operativo como `soportecac@arsat.com.ar` y `reclamos.interferencias@arsat.com.ar`. Desde una perspectiva defensiva, la exposición de correos pertenecientes a áreas de soporte y reclamos representa un vector de riesgo para posibles campañas de *Spear Phishing* o Ingeniería Social, ya que el personal de estas áreas interactúa constantemente con remitentes externos desconocidos.

Como apunte analítico del Blue Team en la depuración de información, la recolección también arrojó una dirección ajena a la organización: `cmartorella@edge-security.com`. Esto representa un falso positivo clásico derivado de la firma del creador de la propia herramienta theHarvester, evidenciando la necesidad de validar y curar siempre los resultados crudos obtenidos durante el proceso de OSINT. [**\[E01\]**](#bookmark=id.jndb45dtw5oh)

### **Documentos (Análisis de Metadatos)** {#documentos-(análisis-de-metadatos)}

Como parte de la recolección pasiva, se buscaron documentos ofimáticos expuestos en la infraestructura de la organización. Durante este proceso, se identificó que ARSAT utiliza subdominios vinculados a servicios de almacenamiento (S3) y redes de distribución de contenido (CDN) para alojar información pública del Estado Nacional.

Se procedió a la descarga de un documento de prueba alojado en la URL [https://s3.arsat.com.ar/cdn-bo-001/suplementos/2001/01/04/primera-seccion\_04-01-2001\_suplemento-1.pdf](https://s3.arsat.com.ar/cdn-bo-001/suplementos/2001/01/04/primera-seccion_04-01-2001_suplemento-1.pdf) [**\[E06\]**](#bookmark=id.q0u1vv4qd56l), el cual corresponde a una publicación del Boletín Oficial.

Mediante el uso de la herramienta de línea de comandos exiftool, se extrajo la metadata incrustada en el archivo [**\[E07\]**](#bookmark=id.25h65by7dijd), obteniendo los siguientes resultados críticos:

* **Autor/Usuario interno:** MAVILA  
* **Software Creador:** Adobe PageMaker 6.52  
* **Productor (Exportación):** Acrobat Distiller 3.01 for Windows  
* **Sistema Operativo Inferido:** Windows

**Análisis de Riesgo Defensivo:**

Desde la perspectiva del Blue Team, este hallazgo evidencia la ausencia de políticas de sanitización de metadatos (Data Loss Prevention o DLP) en los archivos distribuidos por la red de ARSAT. Aunque el documento original provenga de otro organismo del Estado, la plataforma de ARSAT actúa como vector de exposición. Un atacante que automatice la descarga masiva de estos PDF puede recolectar cientos de nombres de usuarios (como el expuesto "MAVILA") y perfilar el stack tecnológico histórico de las dependencias gubernamentales. Esta información es fundamental para la creación de diccionarios de usuarios personalizados y para la planificación de campañas de Spear Phishing o ataques de fuerza bruta.

### **Análisis de los registros SPF y DMARC** {#análisis-de-los-registros-spf-y-dmarc}

Mediante consultas DNS públicas se analizaron los registros TXT asociados al dominio `arsat.com.ar`. Se identificó un registro SPF que enumera distintas direcciones IP y servicios externos autorizados para el envío de correo electrónico en representación de la organización, incluyendo infraestructura vinculada con Microsoft, Amazon SES, EmlBlue y ML Send. [**\[E02\]**](#bookmark=id.ipwa9ec761bi)

El registro finaliza con la directiva `-all`, lo que representa una política restrictiva frente a servidores que no se encuentren expresamente autorizados. Asimismo, se verificó la existencia de una política DMARC configurada como `p=quarantine` y aplicada al 100 % de los mensajes. Esto indica que los correos que no superen los controles de autenticación deben ser tratados como sospechosos y enviados a cuarentena.

La implementación de SPF y DMARC reduce el riesgo de suplantación directa del dominio institucional. Sin embargo, no elimina completamente los ataques de phishing, ya que un atacante todavía podría utilizar dominios visualmente similares, cuentas comprometidas o servicios externos para engañar a empleados y proveedores.

### **Publicaciones y Portales de Datos Abiertos** {#publicaciones-y-portales-de-datos-abiertos}

Durante la recolección de información pública, se identificó la existencia de un portal oficial de datos abiertos (`datos.arsat.com.ar`). Al explorar sus publicaciones, se localizó un *dataset* específico referente a la "Cobertura Satélite ARSAT-1" (`https://datos.arsat.com.ar/dataset/cobertura-satelite-arsat-1`), evidenciado en los resultados de recolección de URLs interesantes de la herramienta theHarvester \[E01\].

Del mismo se extrajo un archivo público en formato CSV (`datos-cobertura-banda-ku-arsat1-v2.csv`) que contiene miles de coordenadas geográficas exactas estructuradas como polígonos, las cuales delimitan matemáticamente la huella de cobertura del satélite en la Banda Ku sobre el territorio y océanos adyacentes [**\[E08\]**](#bookmark=id.65dkegi4mwgt).

**Análisis Defensivo (Blue Team):** Si bien la información comercial sobre la cobertura satelital es inherentemente pública, el descubrimiento de este portal es relevante para la ciberdefensa. El mapeo de repositorios de *Open Data* institucionales es un paso crítico, ya que estos portales gestionados por áreas operativas pueden sufrir de configuraciones erróneas o fallos en los procesos de curación de datos. Un error humano al publicar *datasets* podría derivar en la exposición accidental de telemetría sensible, ubicaciones exactas de estaciones terrenas críticas (gateways) o parámetros técnicos que no deberían ser de dominio público, facilitando el reconocimiento a actores maliciosos y ciberdelincuentes.

## 4\. Tecnologías y Superficie de Exposición {#4.-tecnologías-y-superficie-de-exposición}

### **Stack Tecnológico Web y Proveedores de Terceros** {#stack-tecnológico-web-y-proveedores-de-terceros}

Para identificar las tecnologías específicas que soportan los servicios web visibles de la organización, se realizó un escaneo pasivo sobre el dominio principal (`www.arsat.com.ar`) utilizando la herramienta Wappalyzer [**\[E05\]**](#bookmark=id.rqnhc5xj7kh).

El análisis de los resultados extraídos revela la siguiente arquitectura base y dependencias de terceros:

* **Gestor de Contenidos (CMS):** El sitio está construido sobre **WordPress**.  
* **Lenguaje y Base de Datos:** Utiliza **PHP** como lenguaje de programación del lado del servidor y **MySQL** para la gestión de bases de datos.  
* **Proveedores de Plugins y Extensiones:** Se identificó una alta dependencia de herramientas de terceros para el diseño y la funcionalidad del sitio. Entre ellas destacan **Elementor** (Page builder), **Contact Form 7** (formularios), **Yoast SEO** (optimización en buscadores) y **WPML** (traducción multilenguaje).  
* **Librerías Frontend:** El sitio expone el uso de librerías JavaScript como jQuery, Lodash, Modernizr y Swiper.

**Análisis Defensivo (Blue Team):** Desde una postura de ciberdefensa, la identificación de este stack tecnológico es crítica. Si bien WordPress es un estándar en la industria, su arquitectura basada en plugins de múltiples proveedores de terceros expande significativamente la superficie de ataque. Un atacante (o un escáner automatizado como WPScan) podría utilizar esta información para enumerar las versiones exactas de los plugins instalados. Si alguna de estas extensiones (como *Contact Form 7* o *Elementor*) sufre una vulnerabilidad de día cero (Zero-Day) o carece de actualizaciones, podría ser explotada para lograr una inyección de código (XSS o SQLi) o evadir los controles de acceso, comprometiendo la integridad del sitio web público de la organización.

5\. Riesgos de Ingeniería Social y Spear Phishing

El análisis pasivo de redes sociales (SOCMINT) permite a los actores maliciosos identificar perfiles clave dentro de una organización para diseñar ataques altamente personalizados, técnica conocida como *Spear Phishing*.

### **Perfilado de Objetivos Críticos** {#perfilado-de-objetivos-críticos}

 A través del análisis de interacciones públicas en publicaciones corporativas en LinkedIn, se identificó al personal técnico con acceso privilegiado. Específicamente, se logró perfilar a Fernando Alvarez, quien ocupa el cargo crítico de "Jefe de Infraestructura IT \- Datacenter Tier III" con base en Benavídez, Provincia de Buenos Aires.

### **Fuga de Información Tecnológica** {#fuga-de-información-tecnológica}

 La revisión del historial laboral público de este perfil reveló de manera explícita el stack tecnológico utilizado en el Datacenter de ARSAT. El empleado detalla experiencia directa en la administración, implementación y soporte de plataformas IaaS utilizando **Apache CloudStack**, además de virtualización específica con **XenServer/VMware** y orquestación con Kubernetes. El uso de Apache CloudStack por parte de la organización se encuentra, además, públicamente validado en el sitio web oficial del proveedor de software (ShapeBlue), donde ARSAT figura como cliente.

### **Contexto de Vulnerabilidades**  {#contexto-de-vulnerabilidades}

La plataforma Apache CloudStack cuenta con reportes de seguridad recientes y críticos. Si bien existen vulnerabilidades conocidas para ciertos hipervisores, como el CVE-2026-25077 (RCE en KVM) o el CVE-2026-25199 (Vulnerabilidad en Proxmox), un atacante que haya perfilado correctamente a este empleado sabrá que su infraestructura corre sobre XenServer/VMware. Por lo tanto, el riesgo principal radica en fallas transversales de la plataforma, como el **CVE-2025-66171** (una vulnerabilidad crítica en el plugin de Backups que permite a cualquier usuario crear máquinas virtuales desde respaldos ajenos) o el **CVE-2025-59454** (fuga de datos a través de APIs por fallos en controles de acceso).[\[3\]](#bookmark=id.clrlbiffb9k8) [\[4\]](#bookmark=id.cxr9y3ewulc6) [\[5\]](#bookmark=id.p0bo93gtbygz)

### **Escenario de Ataque Dirigido (Spear Phishing)** {#escenario-de-ataque-dirigido-(spear-phishing)}

 Si bien el correo electrónico personal del empleado no se encuentra expuesto de forma directa en su perfil, un atacante puede inferirlo fácilmente cruzando la nomenclatura estándar de la empresa (descubierta en la fase de extracción de metadatos, ej. `falvarez@arsat.com.ar`) o bien contactarlo directamente mediante mensajes privados en LinkedIn.

Con la información recolectada, el atacante tiene todos los elementos para ejecutar un ataque de ingeniería social con una altísima probabilidad de éxito:

1. **Suplantación de Identidad (Spoofing):** El atacante puede falsificar un correo simulando ser el equipo de soporte técnico de **ShapeBlue** (proveedor oficial de CloudStack).  
2. **Señuelo (Pretexto):** El mensaje haría referencia directa a la necesidad urgente de aplicar parches de mitigación y actualizar la infraestructura a las versiones **4.22.0.1** o **4.20.3.0**. El correo advertiría que no hacerlo expone los datos de los clientes del Datacenter Tier III en Benavídez a fugas de datos (CVE-2025-59454) y accesos no autorizados a los backups (CVE-2025-66171).  
3. **Ejecución:** El correo incluiría un enlace fraudulento hacia una actualización falsa o un documento adjunto malicioso (supuesto "Manual de Mitigación de ShapeBlue") que, al ser ejecutado por el Jefe de Infraestructura, otorgaría al atacante acceso inicial directo a los sistemas más críticos de la organización, evadiendo los controles perimetrales tradicionales.

## 6\. Riesgos Reputacionales e Incidentes Públicos {#6.-riesgos-reputacionales-e-incidentes-públicos}

ARSAT se posiciona como el activo estratégico encargado de defender la soberanía tecnológica de la Nación, administrando redes críticas y "el Centro Nacional de Datos más seguro del país". Sin embargo, la recolección de información mediante fuentes abiertas (OSINT) reveló vulnerabilidades latentes y un incidente público reciente de extrema gravedad que comprometen severamente su reputación.

A partir de los hallazgos, se identifican los siguientes incidentes y riesgos reputacionales:

### **1\. Incidente Público Confirmado: Brechas de Seguridad Física, Corrupción y Espionaje** {#1.-incidente-público-confirmado:-brechas-de-seguridad-física,-corrupción-y-espionaje}

El riesgo reputacional más devastador para la organización se ha materializado recientemente en un escándalo público que involucra la sustracción de infraestructura crítica. Se reportó el robo de equipamiento perteneciente a la Red Federal de Fibra Óptica (REFEFO) almacenado en 15 "shelters" (contenedores) dentro de un depósito tercerizado a la empresa ALS en San Fernando, resultando en pérdidas millonarias.

Desde la perspectiva de seguridad, el incidente evidenció una negligencia absoluta en los controles físicos del proveedor contratado: las cámaras de videovigilancia no funcionaban desde hacía más de un año, los cercos perimetrales estaban defectuosos y no había personal de custodia suficiente. La investigación judicial de este robo destapó un entramado de corrupción y contrataciones amañadas que derivó en el allanamiento y detención del expresidente de ARSAT, Facundo Leal. Durante los operativos se descubrió una suma multimillonaria no declarada, narcóticos y, lo más alarmante para una empresa de telecomunicaciones estatales, **equipamiento profesional de inteligencia militar** (inhibidores de señal, teléfonos satelitales, micrófonos ocultos y rastreadores). Este hecho destruye la confianza pública en la cúpula directiva y expone la vulnerabilidad de la cadena de suministro físico de la organización.

### **2\. Riesgo de Pérdida de Confianza por Fuga de Datos en el Datacenter** {#2.-riesgo-de-pérdida-de-confianza-por-fuga-de-datos-en-el-datacenter}

 Sumado a los problemas físicos, ARSAT enfrenta riesgos lógicos severos. La empresa aloja información sensible de importantes instituciones públicas y privadas. La explotación de vulnerabilidades identificadas en su plataforma base, Apache CloudStack, podría derivar en la exposición de esta información. Fallos transversales documentados, como el **CVE-2025-59454** (que permite acceder a información de la red mediante APIs sin la validación adecuada) o el **CVE-2025-66171** (que permite a cualquier usuario crear máquinas virtuales a partir de los respaldos de otros clientes), destruirían la confianza en la confidencialidad del Datacenter Tier III.

### **3\. Impacto Mediático por Interrupción de Servicios a Nivel Nacional (DoS)** {#3.-impacto-mediático-por-interrupción-de-servicios-a-nivel-nacional-(dos)}

A través de la REFEFO, la empresa provee conectividad a cooperativas, pymes, localidades remotas y bases antárticas. Si un atacante lograra una Denegación de Servicio (DoS), el resultado sería un "apagón digital" masivo. Este escenario es factible ya sea explotando el servicio NTP vulnerable (FreeBSD ntpd 4.2.8p15) detectado mediante Shodan en la IP pública `186.33.208.25`, o abusando de fallas en los límites de recursos de CloudStack, como el **CVE-2025-69233**, que permite degradar la infraestructura hasta causar indisponibilidad.

### **4\. Percepción de Negligencia Técnica por Exposición de Metadatos** {#4.-percepción-de-negligencia-técnica-por-exposición-de-metadatos}

Finalmente, el descubrimiento de fuga sistemática de metadatos en documentos de dominio público expone una debilidad en los controles básicos de prevención de pérdida de datos (DLP). El análisis OSINT reveló la publicación de documentos exponiendo nombres de usuarios internos (ej. "MAVILA") y el uso de software obsoleto (Acrobat Distiller 3.01). Si bien es menos destructivo operativamente, que el organismo líder en ciberseguridad filtre su propia telemetría interna por descuidos humanos degrada fuertemente su imagen de profesionalismo técnico ante la comunidad de seguridad.

## 7\. Preguntas de Ciberdefensa {#7.-preguntas-de-ciberdefensa}

**1\. ¿Por qué la organización puede considerarse una infraestructura o activo estratégico para Argentina?** ARSAT es una infraestructura crítica y un activo estratégico porque es la empresa del Estado Nacional encargada de defender y ejercer la soberanía tecnológica y satelital del país. Administra activos irremplazables cuya interrupción afectaría gravemente el funcionamiento del Estado y la economía: opera los satélites geoestacionarios ARSAT-1 y 2 (que brindan conectividad a zonas remotas y bases antárticas), gestiona la Red Federal de Fibra Óptica (REFEFO) que conecta a más de 1000 localidades, y aloja el Centro Nacional de Datos Tier III, resguardando información sensible de instituciones públicas y privadas.

**2\. ¿Qué actores podrían estar interesados en obtener información sobre la organización (APT, ciberdelincuentes, hacktivistas, insiders o Estados extranjeros)? Justifique.**

* **Insiders (Amenaza Interna):** Como quedó evidenciado en el reciente allanamiento a la cúpula directiva (Facundo Leal), existen altos ejecutivos involucrados en redes de corrupción y robo de materiales de la REFEFO, quienes además poseían equipamiento militar de inteligencia (micrófonos ocultos, inhibidores) para grabar y extorsionar internamente.  
* **Estados Extranjeros / APTs:** Debido al hallazgo de equipos de espionaje satelital ingresados presuntamente sin control y a los vínculos informales con la política exterior estadounidense, agencias de inteligencia extranjeras (APT) tendrían un alto interés en interceptar las comunicaciones de fibra óptica nacional o vulnerar el Datacenter gubernamental.  
* **Ciberdelincuentes:** Grupos de *Ransomware* podrían buscar explotar las vulnerabilidades críticas en Apache CloudStack (ej. CVE-2026-25077 o CVE-2025-59454) para secuestrar máquinas virtuales de clientes privados y estatales, o exfiltrar datos para doble extorsión.

**3\. ¿Qué información obtenida mediante OSINT considera más sensible?** La información más sensible obtenida es el **cruce entre la fuga de metadatos, la exposición de infraestructura obsoleta y el perfilado de empleados**. Se descubrieron subdominios de entornos de desarrollo expuestos (`dev` y `qa`), el uso de un servicio NTP obsoleto y vulnerable a *Buffer Overflow* (FreeBSD ntpd 4.2.8p15 en la IP `186.33.208.25`), y archivos PDF públicos que exponen la nomenclatura de usuarios internos (ej. `MAVILA`). Todo esto, sumado al perfil exacto del stack tecnológico (CloudStack) revelado en LinkedIn por el Jefe de Infraestructura, le entrega a un atacante el mapa completo para vulnerar la red.

**4\. ¿Cuáles son los tres principales riesgos identificados?**

1. **Riesgo Físico y de Cadena de Suministro:** Extrema vulnerabilidad en los depósitos físicos (ALS) y corrupción interna (insiders), evidenciada por el robo de shelters de la REFEFO y cámaras de videovigilancia inoperativas.  
2. **Riesgo de Explotación de Infraestructura Crítica:** La presencia de servicios expuestos en Shodan (NTP) y el uso de plataformas base (Apache CloudStack) con vulnerabilidades conocidas severas que permiten la ejecución remota de código (RCE) y acceso no autorizado a copias de seguridad de clientes.  
3. **Riesgo de Ingeniería Social Dirigida:** La facilidad para realizar *Spear Phishing* al cruzar la validación de cargos críticos en redes sociales con la filtración de estructuras de nombres de usuario institucionales en documentos públicos.

**5\. Proponga al menos cinco medidas para reducir la exposición pública de información sensible.**

1. **Implementar políticas de Sanitización (DLP):** Auditar y limpiar sistemáticamente los metadatos de cualquier documento ofimático (PDF, Word) antes de publicarlo en los portales web o repositorios `s3.arsat.com.ar`.  
2. **Ocultar Entornos No Productivos:** Retirar de los registros DNS públicos y bloquear el acceso externo a todos los subdominios de pruebas (`dev`, `qa`, `devops`, `test-lambda`), forzando su acceso únicamente mediante la VPN institucional.  
3. **Concientización en Seguridad (OPSEC/SOCMINT):** Capacitar al personal crítico (como los administradores del Datacenter) sobre los riesgos de sobre-exponer el software específico (ej. XenServer, versiones de CloudStack) que manejan en sus perfiles públicos de LinkedIn.  
4. **Gestión de Vulnerabilidades del Perímetro:** Actualizar inmediatamente el servicio NTP expuesto en `186.33.208.25` y aplicar los parches correspondientes de Apache CloudStack (actualizando a versiones 4.20.3.0 o 4.22.0.1).  
5. **Auditoría Estricta de Proveedores Físicos y Lógicos:** Exigir SLAs de seguridad verificables a terceros, como asegurar el funcionamiento continuo de los sistemas de CCTV en los depósitos de almacenamiento de hardware de telecomunicaciones.

**6\. ¿Cómo podría contribuir la información obtenida a una campaña de ciberinteligencia?** Ahorra casi la totalidad de la fase de reconocimiento activo para un actor malicioso. Con la información recolectada mediante OSINT, un atacante sabe exactamente qué tecnologías vulnerar (ntpd, WordPress, CloudStack), quién es el encargado de administrarlas (Jefe de Datacenter), y cómo está conformada su dirección de correo en base a la fuga de metadatos corporativos. Esto permite lanzar una campaña de *Spear Phishing* altamente creíble suplantando al proveedor oficial (ShapeBlue) para obtener acceso inicial, sin activar las alarmas perimetrales del SOC.

**7\. Si usted fuera el Director Nacional de Ciberdefensa y sólo dispusiera de presupuesto para proteger tres activos de la organización analizada, ¿cuáles elegiría y por qué?**

1. **Centro Nacional de Datos (Datacenter Tier III):** Porque alberga los datos más críticos del Estado Nacional y de clientes privados. Su vulneración mediante ataques lógicos (ej. robo de backups entre tenants por CVE-2025-66171) implicaría una fuga de datos gubernamentales sin precedentes.  
2. **Red Federal de Fibra Óptica (REFEFO):** Porque es el "sistema nervioso" de las telecomunicaciones terrestres argentinas. Su caída aislaría a cientos de cooperativas, PYMES y pueblos del interior del país, lo cual representa un riesgo directo para el funcionamiento socioeconómico.  
3. **Infraestructura Satelital (ARSAT-1 y ARSAT-2):** Porque garantizan la soberanía de las posiciones orbitales otorgadas al país y son el único medio para proveer telecomunicaciones de emergencia a zonas remotas y bases antárticas donde la fibra óptica no llega.

**8\. Utilizando sus hallazgos, identifique al menos tres técnicas MITRE ATT\&CK que podrían ser utilizadas por un atacante.**

* **T1589 \- Gather Victim Identity Information:** El atacante utiliza herramientas (como theHarvester) y análisis de metadatos (Exiftool en PDFs) para recolectar direcciones de correo corporativas y convenciones de nombres de usuarios válidos para ataques posteriores.  
* **T1566.002 \- Phishing: Spearphishing Link / Attachment:** Utilizando la inteligencia de perfiles de LinkedIn (SOCMINT), el atacante envía un correo engañoso con un pretexto técnico hiper-personalizado al administrador del Datacenter para que haga clic en un enlace o descargue un manual malicioso.  
* **T1190 \- Exploit Public-Facing Application:** El atacante aprovecha debilidades en servicios expuestos a internet, como la explotación del desbordamiento de búfer en el servidor NTP desactualizado descubierto en Shodan o la inyección de plantillas KVM maliciosas en el portal público de Apache CloudStack (CVE-2026-25077).

## 

## Bibliografía/Referencias {#bibliografía/referencias}

1. Fabaro, A. (2025, May 22). 19° Aniversario del ARSAT. [https://www.arsat.com.ar/19-aniversario-de-arsat/](https://www.arsat.com.ar/19-aniversario-de-arsat/)  
2. Organigrama 2026 ARSAT. Arsat.com.ar. [https://datos.arsat.com.ar/dataset/2721b2d9-5319-452b-be68-d5e086fb7aba/resource/80da5926-461e-45ec-8a7f-388337655667/download/organigrama-02-2025.pdf](https://datos.arsat.com.ar/dataset/2721b2d9-5319-452b-be68-d5e086fb7aba/resource/80da5926-461e-45ec-8a7f-388337655667/download/organigrama-02-2025.pdf)  
3. Nvd \- cve-2026-25077. (n.d.). Nist.gov. From [https://nvd.nist.gov/vuln/detail/CVE-2026-25077](https://nvd.nist.gov/vuln/detail/CVE-2026-25077)  
4. Petrova, I. (2026, May 8). ShapeBlue security advisory: Security fixes in CloudStack 4.20.3.0 and 4.22.0.1. ShapeBlue; The CloudStack Company. [https://www.shapeblue.com/shapeblue-security-cloudstack-4-20-3-0-and-4-22-0-1/](https://www.shapeblue.com/shapeblue-security-cloudstack-4-20-3-0-and-4-22-0-1/)  
5. Petrova, I. (2025, November 27). ShapeBlue security advisory for CVE-2025-59302 and CVE-2025-59454. ShapeBlue; The CloudStack Company. [https://www.shapeblue.com/shapeblue-security-advisory-for-cve-2025-59302-and-cve-2025-59454/](https://www.shapeblue.com/shapeblue-security-advisory-for-cve-2025-59302-and-cve-2025-59454/)  
6. Bigozzi, R. (2026, June 14). Las claves del robo en el depósito de ARSAT que desató una ola de causas de corrupción, drogas y espionaje. Infobae. [https://www.infobae.com/judiciales/2026/06/14/las-claves-del-robo-en-el-deposito-de-arsat-que-desato-una-ola-de-causas-de-corrupcion-drogas-y-espionaje/](https://www.infobae.com/judiciales/2026/06/14/las-claves-del-robo-en-el-deposito-de-arsat-que-desato-una-ola-de-causas-de-corrupcion-drogas-y-espionaje/)  
7. Nacion, L. A. \[@lanacion\]. (n.d.). ARSAT: corrupción, drogas e inteligencia ¿QUÉ PASÓ? \[Video\]. Youtube. From [https://www.youtube.com/watch?v=3zl-lkFsIRI](https://www.youtube.com/watch?v=3zl-lkFsIRI)

## Evidencias {#evidencias}

1. E01-theharvester\_arsat.txt  
2. E02-dnsrecon\_arsat.txt  
3. E03-Shodan 186.33.208.25.png  
4. E04-Redes Sociales.jpeg  
5. E05-wappalyzer\_arsat-com.ar.csv  
6. E06-primera-seccion\_04-01-2001\_suplemento.pdf  
7. E07-exiftool\_pdf.txt  
8. E08-datos-cobertura-banda-ku-arsat1-v2.csv