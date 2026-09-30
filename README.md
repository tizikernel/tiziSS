<div align="center">

<img src="https://i.imgur.com/NnWf7Fm.png" width="100%" height="3px">

# TiziSS AntiCheat — UNKNOWN Scanner

<p align="center">
  <em>Desarrollado para la comunidad de Free Fire, por UNKNOWN Security Team.</em>
</p>

<img src="https://i.imgur.com/NnWf7Fm.png" width="100%" height="3px">

</div>

## Introducción

**TiziXit AntiCheat** es un scanner forense para dispositivos Android orientado a la detección de hacks, modificaciones y herramientas de bypass para  **Free Fire Normal y MAX**. Ejecutado vía `Termux` con conexión inalámbrica, realiza un análisis profundo del dispositivo en segundos, sin necesidad de root ni acceso físico al teléfono.

El proyecto es mantenido y desarrollado por **UNKNOWN Security Team** como infraestructura anti-cheat para torneos y comunidades competitivas.

<img src="https://i.imgur.com/NnWf7Fm.png" width="100%" height="3px">

## ¿Por qué usar TiziXit?

- **Automatización total** — El scanner realiza todo el proceso de forma autónoma vía ADB, sin intervención manual del operador.
- **Cobertura profunda** — Detecta desde herramientas de root y bypass de integridad hasta modificaciones de assets.
- **Reporte instantáneo** — Genera un log detallado por dispositivo y lo envía automáticamente al backend con veredicto, HWID y señales detectadas.
- **Panel de administración** — Los resultados son accesibles desde el admin panel con estadísticas, historial y sistema de baneos.
- **Análisis Premium (BugReport)** — Modo avanzado de análisis a nivel kernel mediante BugReport ZIP, con detección de módulos ocultos, timing ADB y más.

<img src="https://i.imgur.com/NnWf7Fm.png" width="100%" height="3px">

## Detecciones — v1.7.0

| Módulo | Descripción |
|--------|-------------|
| `Root / Magisk / APatch / KernelSU` | Detecta acceso root por múltiples vectores: binarios, directorios, procesos y propiedades del sistema |
| `KernelSU Next` | Detección específica de la variante KernelSU Next (`/data/adb/ksunext`) |
| `SuSFS` | Detección de ocultamiento de root a nivel kernel via SuSFS, incluyendo variante `-16k` |
| `Play Integrity Fix (PIF)` | Detecta módulos PIF, TrickyStore y el tag `V/pif` en logcat en runtime |
| `Shamiko / Zygisk` | Detección de bypass de hide list y módulos Zygisk activos |
| `LSPosed / LSPatch / Xposed` | Frameworks de hooks a nivel de sistema |
| `Shizuku / Brevent` | Apps de elevación de permisos sin root completo |
| `Fake GPS / Mock Location` | Detecta apps de GPS falso y permisos de mock location activos |
| `ueventd / Kernel Events` | Detecta manipulación de eventos a nivel kernel via ueventd |
| `BuddyPanda / PandaPatch` | Detecta injectors por paquete, proceso activo y artefactos en disco |
| `Virtual Cam / sxoutput` | Detecta cámaras virtuales, sxoutput y USB Gadget FileSystem (UsbFfs/v4l2) |
| `Scrcpy / Espejamiento` | Detecta espejamiento de pantalla activo vía scrcpy, Vysor y similares |
| `GG Mouse / GameSiru / Chronos` | Herramientas de control externo y emulación de input |
| `Keymappers / Controles externos` | Mantis Gamepad, Panda Gamepad, Octopus, Flydigi y similares |
| `Wallhack / Shaders modificados` | Detección de assets no-UnityFS y modificaciones de contentcache |
| `OBB modificado` | Verificación de firmas UnityFS dentro del OBB del juego |
| `APK integrity` | Verificación de SHA256 del APK instalado |
| `Device Spoofing` | Detecta adulteración de Android ID, serial de hardware y apps de spoof de IMEI |
| `CA Certs / MITM` | Detecta certificados CA de usuario instalados (Fiddler, mitmproxy, etc.) |
| `Proxy / VPN activos` | Verificación de proxy del sistema y apps de VPN activas |
| `Conexiones TCP sospechosas` | Detecta relay ports, conexiones ADB TCP remotas y puertos de inyección |
| `ADB USB activo` | Detecta depuración USB habilitada durante el análisis |
| `Fake Time / Speed Hack` | Detección de alteraciones de fecha/hora y aceleración del tiempo del sistema |
| `Procesos sospechosos (delta)` | Comparación de snapshot de procesos antes y después del escaneo |
| `Logcat delta` | Análisis diferencial de logcat buscando eventos de inyección o hooks |
| `Replay modificado` | Análisis de timestamps y patrones en archivos de replay del juego |
| `BugReport — Análisis Premium` | Análisis de BugReport ZIP a nivel kernel: root, timing ADB, TCP remoto, módulos ocultos |

<img src="https://i.imgur.com/NnWf7Fm.png" width="100%" height="3px">

## Requisitos

- **Termux** instalado en el dispositivo
- Dispositivo objetivo con **Depuración Inalámbrica** habilitada
- Conexión a la misma red WiFi que el dispositivo a analizar

<img src="https://i.imgur.com/NnWf7Fm.png" width="100%" height="3px">

## Instalación

```bash
pkg update && pkg install git android-tools -y
git clone https://github.com/tizikernel/tiziSS
cd tiziSS
chmod +x scanner.sh
bash scanner.sh
```

<img src="https://i.imgur.com/NnWf7Fm.png" width="100%" height="3px">

## Contacto

¿Bugs, sugerencias o acceso Premium?  
Discord: **unknownnnnn.444**

<img src="https://i.imgur.com/NnWf7Fm.png" width="100%" height="3px">

## 🎗 Licencia

Copyright © UNKNOWN Security Team 2025–2030  
Código privado. Ingeniería inversa prohibida.
