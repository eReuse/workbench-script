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

## Generar ISO para el USB

Para generar la iso y preparar un usb que arranque con workbench necesitas generarte una workbench de este, con tu configuración específica

Ejecuta `./deploy-workbench.sh`
