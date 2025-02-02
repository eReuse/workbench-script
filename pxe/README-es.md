# workbench via PXE

## Introducción

Permite arrancar workbench a través de la red en vez de por USB. Utiliza la misma imagen generada por el script [deploy-workbench.sh](../deploy-workbench.sh), pero en el formato compatible con el arranque por red en vez de la iso.

Ejecuta el siguiente script en un servidor debian estable que estará dedicado a la gestión del pxe server

```
./install-pxe.sh
```

Este servidor aporta un servicio de arranque por red tipo PXE, y no hace colisión con un servidor DHCP existente.

## Funcionamiento

El servidor PXE ofrece a la máquina que arranca un *debian live* a través de [NFS](https://es.wikipedia.org/wiki/Network_File_System). Una vez arrancado, ejecuta el `workbench-script.py` con la configuración remota del servidor PXE. Cuando ha terminado, también guarda en el mismo servidor PXE el snapshot resultante. También lo puede guardar en devicehub si se especifica en la variable `url` de la configuración `settings.ini`.

## Probarlo todo en localhost

Preparar configuración de `.env` tal como:

```
server_ip=10.0.2.2
nfs_allowed_lan=10.0.2.0/24
tftp_path='/srv/pxe-tftp'
nfs_path='/srv/pxe-nfs'
```

Red y host 10.0.2.2? Esta es la forma en que el programa *qemu* hace red en localhost, 10.0.2.2 es la dirección de localhost que saliendo de qemu es traducida como 127.0.0.1

Desplegar servidores TFTP y NFS en el mismo ordenador, para permitir nfs inseguro:

```
DEBUG=true ./install-pxe.sh
```

Los directorios inseguros contienen configuración y snapshots de workbench, nada importante supongo. Aún así, `DEBUG=true` no se recomienda para un entorno de producción para evitar sorpresas.


Y para terminar, probar el cliente PXE con el siguiente comando:

```
make test_pxe
```

## Recursos

El servicio PXE

- Originalmente inspirado en este artículo https://farga.exo.cat/exo/wiki/src/branch/master/howto/apu/apu-installer.md
- https://github.com/eReuse/workbench-live/blob/feature/pxe/docs/PXE-setup.md
- https://wiki.debian.org/PXEBootInstall
- https://wiki.debian.org/DebianInstaller/NetbootFirmware
- [In this presentation](https://people.debian.org/~andi/LiveNetboot.pdf), recomienda página 12 [4.6 Building a netboot image](https://live-team.pages.debian.net/live-manual/html/live-manual/the-basics.en.html#236) [4.7 Webbooting](https://live-team.pages.debian.net/live-manual/html/live-manual/the-basics.en.html#275)
