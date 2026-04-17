## AEE - Bitacora III - Operacion Escudo

**Módulo:** Sistemas Informaticos 
**Alumno:** Álvaro López De San Román
**Fecha:** 2026-04-17

---

## Índice
1. [Fundamentos de Seguridad y Auditoria](#1-fundamentos-de-seguridad-y-auditoria)
2.[Reto A  - Script Auditoria](#2-fase-práctica--reto-a-auditoría-de-accesos-script-bash)
3.[Reto B - Configuracion](#3-fase-práctica--reto-b-configuración-ufw)
4.[Referencias](#4-referencias)
---

## 1. Fundamentos de Seguridad y Auditoria 

### 1.1 Anatomia de Syslog: Facility y Server

Syslog es un sistema estándar de emensajeria de eventos en Linux, lo que haces es clasificar cada mensaje esta cruszando de ambos lados ose que va cogiendo de dos variables que son idependientes de taal forma que esa es la funcion que tiene:

| variable | ¿Que es lo que hace? | Ejemplo |
| --- | --- | --- |
| Facilidad (Facility) | Es el componente del sistema que genera ese log que vemos | 'auth', 'kern', 'cron', 'daemon' |
| Prioridad (Severity) | Esta funcion lo que hace que tan grave es el evento que acontece esa parte del programa | 'debug', 'info', 'notice', 'warning' |

Cuando se combina Facility con un nivel bastante alto de serverity, el sistema que hay dentro sabe de donde viene el mensaje y sobretodo cuanta urgencia y importancia tiene. Por ejemplo, un mensaje 'auth.warning', indica al subsistema que se ha registrado en un alto nivel , o como un inetento fallido.

> En práctica, el  `rsyslog` recoge estos mensajes y los escribe en archivos como `/var/log/auth.log` o `/var/log/syslog`, según las reglas de enrutamiento configuradas [3].

---

### 1.2 ¿Por qué es grave que `/var/log/auth.log` sea legible por usuarios no privilegiados?

El archivo /var/log/auth.log registra todos los eventos de autenticación del sistema: inicios de sesión, fallos de contraseña, uso de `sudo`, cambios de usuario con `su`, y conexiones SSH entrantes con sus direcciones IP de origen.

Si somos un usuario sin privilegios puede leer ese archivo:

- Puede ver qué usuarios existen en el sistema y cuáles están activos.
- Puede identificar ventanas horarias en las que el administrador no está conectado.
- Puede detectar qué IPs tienen acceso permitido, facilitando ataques de suplantación.
- En entornos multiusuario, puede espiar la actividad de otros usuarios y del propio administrador.

En definitiva, expone el “mapa de movimientos” del sistema. Un atacante que ya está dentro del servidor como usuario sin privilegios obtendría inteligencia valiosa para escalar privilegios [5].

Los permisos correctos para este archivo deben ser `640` (lectura/escritura para `root`, lectura para el grupo `adm`, ninguno para el resto):

```bash
# Verificar permisos actuales estos son los comandos que harian falta 
ls -la /var/log/auth.log
# Y para corregir estos serian los comandos mas necesitados 
sudo chmod 640 /var/log/auth.log
sudo chown root:adm /var/log/auth.log
```

-----

### 1.3 Diferencia entre un fallo SSH remoto y un fallo de contraseña local

Aunque ambos generan entradas en /var/log/auth.log`, los campos del mensaje son distintos:

| Campo | Fallo SSH | Fallo de contraseña local |
| --- | --- | --- |
| Proceso | 'ssh[PID]' | 'login[PID]' O nos pide '[PID]'
| Mensaje | 'Failed paswwd for invalid user ... | 'FAILED LOGIN (1)' |
| IP origen | Si Aparece (Dirrecion del atacante del cliente atacante ) | No aplica no hay IP
| Puerto | Si Aparece (Dirrecion del atacante del cliente SSH ) | No aplica
| Nombre Usuario |  Puede ser un ususario existente | Suele ser un usuario ya existente dentro del servidor 

Esta diferencia qu enos encontramos aqui es un caso basico de analisis en dond ela presencia del IP externa y un puerto se identifca e inmediato un ataque de fuerza bruta por asi decirlo a la red, mientras que un fallo sin IP apunta a un acceso fisico no autorizado al equipo [5].

## 1.4 Log Management y cumplimiento RGPD

Gestionar los logs solo en la máquina local que podría ser atacada es un error de seguridad serio. La práctica profesional es enviar los logs a un servidor externo seguro. Las ventajas son las siguientes:

1. Integridad de la evidencia: Si el servidor es comprometido y el atacante borra `/var/log/auth.log`, los logs ya están a salvo en el servidor externo. El rastro no se puede eliminar.
2. Cumplimiento del RGPD Reglamento General de Protección de Datos: El RGPD exige que los sistemas que tratan datos personales puedan demostrar la trazabilidad de los accesos. Los logs centralizados con sellado de tiempo demuestran que se ha aplicado una política de auditoría continua.
3. Correlación de eventos: Un servidor centralizado permite cruzar eventos de varias máquinas simultáneamente para detectar ataques coordinados que no serían visibles desde una sola máquina.
4. Disponibilidad: Los logs siguen accesibles aunque el servidor original esté caído o haya sido formateado para recuperarse de un incidente.

> Como señala Alonso Alegre Díez, la gestión centralizada de logs no es solo una buena práctica técnica, sino un requisito de cumplimiento legal en entornos donde se procesan datos de usuarios [4].

-----

## 2. Fase Práctica — Reto A: Auditoría de Accesos (Script Bash)

### 2.1 Pasos ejecutados

Paso 1 — Generar intentos fallidos de SSH desde host:

Desde PowerShell en el equipo anfitrión, ejecutar 5 veces con usuario falso:

- powershell
ssh administrador_falso@<IP_DEL_SERVIDOR>
# Introducir contraseña incorrecta cuando la pida
```

**Paso 2 — Verificar que los intentos quedan registrados:**

```bash
sudo grep "Failed password" /var/log/auth.log | tail -20
```

**Paso 3 — Ver el script automatizado:**

El script se encuentra en `scripts/check_intruders.sh`.

Para ejecutarlo:

```bash
chmod +x scripts/check_intruders.sh
sudo bash scripts/check_intruders.sh
```

**Paso 4 — Ver el reporte generado:**

```bash
cat alertas.txt
```
-----

### 2.2 Captura del análisis forense manual

-----

## 3. Fase Práctica — Reto B: Configuración UFW

### 3.1 Comandos ejecutados en orden

```bash
# 1. Instalar UFW si no está instalado
sudo apt install ufw -y

# 2. Establecer política por denegar todo el tráfico entrante
sudo ufw default deny incoming

# 3. Permitir todo el tráfico saliente 
sudo ufw default allow outgoing

# 4. Permitir ÚNICAMENTE SSH (
sudo ufw allow 22/tcp

# 5. Bloquear ICMP (ping) — 
sudo nano /etc/ufw/before.rules
# (Buscar la sección ICMP y cambiar ACCEPT por DROP en echo-request)

# 6. Activar el firewall
sudo ufw enable

# 7. Verificar estado con reglas numeradas
sudo ufw status numbered

# 8. Verificar estado detallado
sudo ufw status verbose
```

## 4. Referencias

[1] W. Acosta Lugo, *Guía de uso de BBDD Académicas para Ciclos Formativos*, Sevilla, España: Departamento de Informática, 2026. [En línea]. Disponible en: https://drive.google.com/file/d/1Zg4LNDAs55OgEK1gmqbGx8NZyc1CdJjM/view?usp=sharing

[2] IEEE, *IEEE Editorial Style Manual for Authors*, IEEE Periodicals, 2023. [En línea]. Disponible en: https://journals.ieeeauthorcenter.ieee.org/your-role-in-article-production/ieee-editorial-style-manual/

[3] Canonical Ltd., “Ubuntu Server documentation,” *Ubuntu Documentation*, 2025. [En línea]. Disponible en: https://ubuntu.com/server/docs/explanation/intro-to/security/

[4] M. B. Alonso Alegre Díez, “Gestión de Logs,” Trabajo Fin de Máster, Universidad Internacional de La Rioja (UNIR), 2016. [En línea]. Disponible en: https://reunir.unir.net/bitstream/handle/123456789/3618/ALONSO-ALEGRE%20DIEZ%2C%20MARIA%20BEGO%C3%91A.pdf

[5] S. McClure, J. Scambray y G. Kurtz, *Hacking Exposed: Network Security Secrets & Solutions*, 3ª ed. Nueva York, NY, EE. UU.: McGraw-Hill Education, 2001. Disponible en: https://github.com/jwx0539/hackingLibrary/blob/master/McGraw.Hill.Hacking.Exposed.Network.Security.Secrets.And.Solutions.3rd.Edition.Sep.2001.ISBN.0072193816.pdf
