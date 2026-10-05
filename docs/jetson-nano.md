# Jetson Orin Nano — Conceptos: qué es cada cosa y para qué sirve

> Solo Jetson. Sin audeep. Datos reales de tu placa (`jetsonorinnano-desktop`, `192.168.1.21`).

## 1. La placa: Orin Nano (no es la "Nano" clásica)

**Qué es:** tu placa es una **Jetson Orin Nano** (Ampere, `aarch64`), no la Jetson Nano original (Maxwell, ya descontinuada). Se confirma por el kernel `5.15.185-tegra` y `nvidia-smi` que reporta GPU `Orin (nvgpu)`.

**Para qué sirve saberlo:** los tutoriales de la Nano vieja (JetPack 4, CUDA 10) **no te sirven**; el tuyo usa JetPack 6 / L4T R36. Todo lo que instales (PyTorch, TensorRT) debe ser versión para Orin + JetPack 6.

## 2. L4T y JetPack (R36.5 / 6.2.2)

**Qué es:** **L4T** (Linux for Tegra) es el Ubuntu modificado por NVIDIA para Jetson (tu `36.5.0`). **JetPack** es el paquete completo: L4T + driver + CUDA + cuDNN + TensorRT + multimedia. Tu meta-paquete: `nvidia-jetpack 6.2.2`.

**Para qué sirve:** es la unidad de compatibilidad. Todo (PyTorch, DeepStream) se elige **por versión de JetPack**, no por versión de Ubuntu.

## 3. Ubuntu 22.04 + kernel tegra

**Qué es:** `Ubuntu 22.04.5 LTS (Jammy)`, kernel `5.15.185-tegra #1 SMP PREEMPT`. El sufijo `-tegra` indica kernel con parches de NVIDIA (drivers de GPU, CSI, power).

**Para qué sirve:** sabes que `apt` normal funciona, pero el kernel y drivers vienen de NVIDIA, no de Ubuntu vanilla: no lo actualices a un kernel genérico o pierdes la GPU.

## 4. Driver NVIDIA y `nvidia-smi`

**Qué es:** el driver (540.5) es el que habla con el hardware. `nvidia-smi` muestra driver + **versión máxima de CUDA soportada (12.6)**.

**Para qué sirve:** es tu termómetro rápido: si `nvidia-smi` ve la GPU `Orin`, el driver está sano. El CUDA que instales debe ser ≤ 12.6.

## 5. CUDA Toolkit y `nvcc` (+ el PATH)

**Qué es:** el Toolkit trae el compilador `nvcc` y headers para programar la GPU. Vive en `/usr/local/cuda-12.6/bin/nvcc` (vía alias `/usr/local/cuda → /etc/alternatives/cuda`).

**Para qué sirve:** compilar código CUDA y que PyTorch encuentre los headers. Estaba instalado pero **invisible** porque ese directorio no estaba en `$PATH`; se arregló exportándolo en `~/.profile` (los shells login siempre lo leen; el `.bashrc` tiene un guard que lo salta en sesiones no interactivas).

## 6. cuDNN 9.3.0

**Qué es:** librería de primitivas de redes neuronales (convoluciones, etc.) que PyTorch/TensorRT usan por debajo. La tuya: `libcudnn9-cuda-12 9.3.0.75` + headers + samples.

**Para qué sirve:** sin cuDNN, PyTorch con CUDA no acelera nada. Ya la tienes para CUDA 12 (mejor que la 8.9.7 del tutorial de Windows, que era para CUDA 11).

## 7. TensorRT 10.3

**Qué es:** optimizador que convierte un modelo entrenado en un **motor** rápido (FP16/INT8) para inferencia en el borde.

**Para qué sirve:** es lo que hace que tu Orin Nano infiera en local sin nube. Ya instalado (`libnvinfer* 10.3.0.30`). El tutorial de Windows ni lo menciona; en Jetson es pieza central.

## 8. PyTorch — lo único que falta

**Qué es:** el framework de entrenamiento/inferencia de la guía (elegía entre CUDA 11.8/12.1/12.4). En tu Jetson: **no instalado** (`No module named 'torch'`).

**Para qué sirve / qué hacer:** hay que instalar la **wheel de NVIDIA para ARM + JetPack 6** (la de PyPI normal es x86 y no trae CUDA para Tegra), y verificar `torch.cuda.is_available() → True`. Pendiente.

## 9. `nvpmodel` — modos de poder

**Qué es:** tu placa está en modo **15W** (IDs: `0=15W`, `1=25W`, `2=MAXN_SUPER`).

**Para qué sirve:** limita CPU/GPU para no quemar la fuente ni la placa. Para inferencia pesada se sube a `25W`/`MAXN_SUPER` (`sudo nvpmodel -m 1/2`); para pruebas, 15W basta y calienta menos.

## 10. Memoria unificada y disco

**Qué es:** `Mem: 7.4Gi` total, `443Mi` en uso, `6.8Gi` disponible; disco NVMe de `456G` con `417G` libres (4% usado).

**Para qué sirve:** en Jetson la RAM la comparten CPU y GPU: esos 7.4G son para todo (modelo + sistema). Con 6.8G libres vas sobrado para empezar; el NVMe de 456G da espacio de sobra para datasets y modelos.

## 11. `jtop` / jetson-stats 4.3.2

**Qué es:** monitor estilo `htop` pero para Jetson (GPU, CPU, RAM, temps, power).

**Para qué sirve:** ver en vivo si la GPU trabaja al inferir. Ya instalado (`jtop 4.3.2`, `jetson-stats`, `Jetson.GPIO 2.1.9`).

## 12. Cámara: no hay ninguna conectada

**Qué es:** `ls /dev/video*` → no existe; `v4l2-ctl` solo ve `tegra-camrtc-ca` (`/dev/media0`, el controlador, sin sensor).

**Para qué sirve saberlo:** hoy no puedes capturar nada. Cuando conectes una cámara CSI o USB deberá aparecer `/dev/video0`. OpenCV `4.8.0` ya está listo para usarla.

## 13. Red: WiFi con IP dinámica

**Qué es:** interfaz `wlP1p1s0` con `192.168.1.21/24` **dinámica** (era `.15` antes).

**Para qué sirve:** si la IP baila, reserva la MAC en tu router o pon IP fija; si no, cada vez hay que redescubrirla. SSH con `jetson-orin-nano` + tu pass funciona.

## 14. Equivalencias con el tutorial de Windows

| Tutorial (Windows x86) | Tu Jetson (Linux ARM) | Estado |
|---|---|---|
| MSVC++ Redist + VS Community | `build-essential` + `g++ 11.4` | ✅ ya está |
| `nvidia-smi` versión CUDA | driver 540.5 → CUDA 12.6 | ✅ más nuevo que el 11.8 de la guía |
| CUDA Toolkit 11.8 `.exe` | Toolkit 12.6 vía JetPack (no se instala `.exe`) | ✅ + fix PATH hecho |
| cuDNN 8.9.7 p/ CUDA 11 | cuDNN 9.3.0 p/ CUDA 12 + TensorRT 10.3 | ✅ mejor |
| PyTorch CUDA 11.8/12.x | wheel NVIDIA ARM p/ JetPack 6 | ❌ pendiente |
