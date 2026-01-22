# workbench-script

## Resumen

workbench-script es el componente de recopilación de datos del ecosistema [eReuse](https://ereuse.org/). Su función principal es extraer información sobre los componentes de un PC y generar un fichero snapshot en formato JSON que puede utilizarse para inventario, trazabilidad y diagnóstico en procesos de reutilización y reciclaje de dispositivos electrónicos.

El programa trata de ser simple y minimalista, está diseñado para funcionar por defecto de forma intuitiva y sin configuración previa. Este programa solo hace esencialmente dos funcionalidades:

1. Recopila datos del PC y los guarda como fichero *snapshot* y, opcionalmente, los puede enviar al servicio de inventario [devicehub-django](https://farga.pangea.org/ereuse/devicehub-django/)
2. Opcionalmente borra discos (esta característica está en desarrollo y todavía no se puede probar)

Modalidades de ejecución del programa:

1. [Arranque desde memoria USB](#arranque-desde-memoria-usb)
2. [Arranque desde red](#arranque-desde-red) (mediante [PXE](https://es.wikipedia.org/wiki/Entorno_de_ejecuci%C3%B3n_de_prearranque))
3. [Arranque desde tu propio sistema operativo](#arranque-desde-tu-propio-sistema-operativo). Con propósito de prueba rápida o desarrollo

Modalidades de envío de los *snapshots*:

1. Envío simple (sin firmar).
2. Con firma (en formato de [credencial verificable](https://en.wikipedia.org/wiki/Verifiable_credentials)) y mediante el servicio [idhub](https://farga.pangea.org/ereuse/idhub). Este servicio se puede probar, pero de momento es experimental.
3. En compatibilidad con el anterior servicio obsoleto de [devicehub-teal](https://github.com/eReuse/devicehub-teal).

## Configuración del programa

workbench-script está diseñado para funcionar por defecto de forma intuitiva y sin configuración previa.

Se puede especificar un fichero de configuración con el argumento `--config`, y en `settings.ini.example` se puede encontrar un ejemplo de configuración.

Todos las configuraciones son opcionales, y están desactivadas o comentadas en [settings.ini.example](./settings.ini.example)

Normalmente la configuración básica consta de:

- url: URL hacia devicehub
- token: auth_token de devicehub

Otras configuraciones de interés:

- legacy: para retrocompatibilidad con la anterior versión de devicehub
- url_wallet: URL hacia idhub (en caso de querer firmar con credenciales verificables)
- wb_sign_token: auth_token para usuario de idhub
- disable_qr: no mostrar QR en el registro de un equipo (útil en modo desarrollo)

## Arranque desde memoria USB

El [arranque desde memoria USB](https://es.wikipedia.org/wiki/Memoria_USB) es la forma más sencilla de arrancar workbench, dado que es un entorno con todas las herramientas para poder analizar los componentes del PC.

Puedes descargar la ISO de la última versión estable [aquí](https://docs.ereuse.org/workbench-script-iso/v2025.1.iso).

Una vez descargada, utiliza la herramienta de [balenaEtcher](https://etcher.balena.io/) para cargar la ISO en la memoria USB.

La ISO tiene por un lado el entorno necesario para ejecutar workbench-script y por otro, una partición persistente con la configuración y los ficheros que se irán generando.

Esta partición persistente tiene una configuración por defecto que está enlazada con el devicehub de https://demo.ereuse.org para modificar esta configuración, necesitas modificar la partición persistente.

### Modificar la partición persistente

En esta configuración, workbench-script usa una partición persistente [FAT16](https://1984.lsi.us.es/wiki-ssoo/index.php/FAT#FAT_16) que guarda:

1. La configuración de ejecución del programa.
2. Snapshots de PCs previamente analizados usando la herramienta.

Para entrar, en *Windows* verás que esta se monta automáticamente, es una unidad que por defecto tiene 100 MB.

Para modificarla desde GNU/Linux la partición es oculta y la tienes que encontrar (con `lsblk` o `dmesg`) y montar manualmente con el comando `mount`.

> [!NOTE]
> FAT16? Sí, nos gustaría mejorar el sistema de montaje de la partición persistente. Bienvenidas las sugerencias

### Avanzado: Generar una ISO para el USB

No es necesario generar tu propia ISO para poder usar workbench-script, si quieres modificar la configuración

Para crear una imagen ISO y preparar un USB que arranque con Workbench, primero debes generar una versión personalizada de Workbench con tu configuración específica. Como mínimo, necesitas un archivo `settings.ini` que contenga la URL de tu instancia de DeviceHub y el token de acceso.

Existen dos métodos para generar la ISO:

#### Opción 1. Generar la ISO con Docker (Método recomendado)

Este método es el más sencillo y compatible con cualquier sistema operativo (incluyendo Windows, macOS y otras distribuciones de GNU/Linux o BSD). Solo necesitas tener Docker instalado en tu máquina.

> [!NOTE]
> Se ha detectado que `deploy-workbench.sh` no funciona correctamente en distribuciones basadas en Ubuntu 24.04.

Una vez instalado Docker, ejecuta el siguiente comando en la terminal:

```sh
docker compose up
```

Este comando creará un contenedor de Docker con el script de Workbench y generará una ISO que incluirá tanto el script como el archivo `settings.ini` de tu directorio. La ISO resultante se guardará en:

```sh
iso/workbench_debug.iso
```

#### Opción 2. Generando la ISO directamente en tu máquina

> [!NOTE]
> `deploy-workbench.sh` se ha diseñado para funcionar en debian estable, en otros sistemas podría no funcionar, usa entonces el método con docker

Si prefieres generar la ISO sin Docker, puedes hacerlo manualmente ejecutando el script `deploy-workbench.sh`. Para ello, primero debes instalar las dependencias necesarias con el siguiente script:

```sh
./install-dependencies.sh
```

Luego, ejecuta:

```sh
./deploy-workbench.sh
```

Este proceso generará la ISO en el directorio `iso/workbench_debug.iso`.

#### Probar arranque de la ISO

Puedes probar la ISO desde tu propio equipo con las utilidades disponibles en el Makefile. Este Makefile proporciona comandos para desplegar el sistema Workbench, gestionar dependencias y arrancar imágenes ISO con QEMU.

Antes de usar el `Makefile`, instala las dependencias necesarias:

```sh
./install-dependencies.sh
```

### Arranque de Imágenes ISO

```sh
make boot_iso ISO_FILE=iso/workbench_production.iso
```

O bien:

```sh
make boot_iso ISO_FILE=iso/workbench_debug.iso
```

También es posible arrancar desde un live USB:

```sh
make boot_iso_from_usb USB_DEVICE=/dev/sda
```

## Arranque desde red

[Arranque desde red](https://es.wikipedia.org/wiki/Arranque_desde_red) es un poco más laborioso que el arranque con memoria USB pero más eficiente para aquellas entidades que analizan habitualmente muchos equipos al día

Como requerimiento necesitarás un servidor al que los otros equipos se conectarán para que estos puedan descargar la ISO de workbench-script, adicionalmente, en este servidor actuará como la *memoria persistente*: servirá la configuración que se va a ejecutar en los PCs, y guardará los snapshots resultantes.

Este repositorio dispone de una instalación automatizada pero no idempotente, la iremos mejorando progresivamente, visita aquí el manual: [pxe/README-es.md](pxe/README-es.md)

## Arranque desde tu propio sistema operativo

El script solo necesita `python` en tu sistema y no tiene dependencias externas, el problema es que necesita de otros programas que analizan los componentes y quizá no tengas instalados, lo puedes hacer con el siguiente comando:

```sh
./install-dependencies.sh
```

Esta sección también la podríamos considerar en cierta manera, un rápido *entorno de desarrollo* de la herramienta.

## Actualizar y revisar traducciones

Para actualizar estado de traducciones contra la versión más reciente de workbench, ejecutar:

```
make es_gen
```

Aparecerán modificaciones autogeneradas y pendientes de corregir en los siguientes ficheros:

```
locale/es/LC_MESSAGES/messages.mo (binario)
locale/es/LC_MESSAGES/messages.po
```

Para forzar la localización a español (por si el sistema no está así por defecto), arrancar así:

```
LC_ALL=es_ES.UTF-8 python workbench-script.py
```

## Acerca de eReuse

workbench-script es una herramienta desarrollada por [eReuse](https://ereuse.org/) que permite recopilar datos de los PCs con el propósito de aportar trazabilidad durante todo su ciclo de vida. Forma parte del ecosistema de software libre de eReuse, orientado a fomentar la reutilización de dispositivos electrónicos, facilitar su diagnóstico y asegurar una gestión responsable desde el uso hasta el reciclaje.

## Licencia

DeviceHub está licenciado como [GNU Affero General Public License v3.0](LICENSE).
