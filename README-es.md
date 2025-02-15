## Resumen

1. workbench solo hace dos funcionalidades:
    1. recopila datos del PC y los guarda como fichero snapshot o los sube a devicehub
    2. opcionalmente borra discos

### Hoja de ruta (2024)

A través de un proyecto de ISOC se van a trabajar las dos funcionalidades siguientes:

- F1: Borrado de discos SSD
- F2: Firma criptográfica de snapshots, conversión de los snapshots en credenciales verificables o evidencias

## Detalle funcionalidad

1. Genera snapshot
2. Guarda snapshot en el path que indicas
3. Envía a una URL si le pasas URL y token
4. Borra
   1. borrado basico como hay ahora
   2. borrado baseline como hay ahora
   3. borrado enhanced como hay ahora
   4. borrado ata para quien lo soporte
   5. borrado nvme para quien lo soporte

Comentarios sobre el borrado:

1. Comentario de borrado por encriptación: no borra por encriptacion porque lo unico que hace es quitar las claves de encriptacion. Depende de que tu disco esté cifrado. Si tu disco no está cifrado por hardware, entonces no funcionará este tipo de borrado (pendiente revisar).
2. El borrado 4.4 y 4.5 no siguen especificamente un estándar, pero creo que son mejores.

## Uso del script

Detalles del uso del script para técnicos

El script está diseñado para funcionar por defecto de forma intuitiva y sin configuración previa

Se puede especificar un fichero de configuración con el argumento `--config`, y en `settings.ini.example` se puede encontrar un ejemplo de configuración

## Enfoque

workbench-script trata de ser simple y minimalista, una función principal y funciones de soporte la lectura de las diferentes funcionalidades.

## Generar una ISO para el USB

Para crear una imagen ISO y preparar un USB que arranque con Workbench, primero debes generar una versión personalizada de Workbench con tu configuración específica. Como mínimo, necesitas un archivo `settings.ini` que contenga la URL de tu instancia de DeviceHub y el token de acceso.

Existen dos métodos para generar la ISO:

### 1. Usando Docker (Método recomendado)

Este método es el más sencillo y compatible con cualquier sistema operativo (incluyendo Windows y macOS). Solo necesitas tener Docker instalado en tu máquina.

Una vez instalado Docker, ejecuta el siguiente comando en la terminal:

```bash
docker compose up
```

Este comando creará un contenedor de Docker con el script de Workbench y generará una ISO que incluirá tanto el script como el archivo `settings.ini` de tu directorio. La ISO resultante se guardará en:

```bash
iso/workbench_debug.iso
```

### 2. Generando la ISO directamente en tu máquina

Si prefieres generar la ISO sin Docker, puedes hacerlo manualmente ejecutando el script `deploy-workbench.sh`. Para ello, primero debes instalar las dependencias necesarias con el siguiente script:

```bash
install-dependencies.sh
```

Luego, ejecuta:

```bash
deploy-workbench.sh
```

Este proceso generará la ISO en el directorio `iso/workbench_debug.iso`.

> [!NOTE]
> Se ha detectado que `deploy-workbench.sh` no funciona correctamente en distribuciones basadas en Ubuntu 24.04.

## Testear la ISO Generada (Solo para linux)

Para testear la ISO Generada, se proveé un Makefile. Este Makefile proporciona comandos para desplegar el sistema Workbench, gestionar dependencias y arrancar imágenes ISO con QEMU.

Antes de usar el `Makefile`, instala las dependencias necesarias:

```bash
make install_dependencies
```

### Arranque de Imágenes ISO

```bash
make boot_iso ISO_FILE=iso/workbench_production.iso
```

O bien:

```bash
make boot_iso ISO_FILE=iso/workbench_debug.iso
```

También es posible arrancar desde un live USB:

```bash
make boot_iso_from_usb USB_DEVICE=/dev/sda
```

