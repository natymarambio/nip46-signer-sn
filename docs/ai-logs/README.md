# Registros de conversación con el agente de IA

Agente utilizado: **Claude (Anthropic)**, en modo agente con acceso a terminal.

**Conversación completa (enlace público):**
https://claude.ai/share/e836bcaf-2a54-445a-b5f1-47b8bd4d966b

## Resumen de la sesión

1. Se le entregó al agente el PDF de la prueba con la instrucción "realizar prueba de conocimientos técnicos".
2. Antes de construir, el agente planteó 4 decisiones de alcance y yo elegí:
   - Lenguaje: **Python**.
   - Flujo NIP-46: **ambos, priorizando `bunker://`**.
   - Almacenamiento de la clave: **cifrada con contraseña** (NIP-49).
   - Entrega: zip para publicarlo yo en GitHub.
3. El agente leyó la especificación NIP-46 y el código fuente de Stacker News y de NDK 2.12.2 para descubrir los
   requisitos reales del cliente: NIP-04 por defecto, `connect` → `"ack"` y el evento kind 27235 con `challenge`.
4. Implementación por capas: criptografía → almacén de clave → relays → firmante → CLI.
5. Verificación: vectores oficiales NIP-44/NIP-49/NIP-19, tests de punta a punta con relay local y un cliente que
   replica a Stacker News, y prueba manual de la CLI.
6. La prueba con el sitio real stacker.news se hace en el computador del postulante: el entorno del agente no tenía
   acceso abierto a internet (solo a registros de paquetes y GitHub), así que no podía conectarse a los relays ni a SN.
7. Publicación: el agente integró el historial del repositorio, reemplazó el .zip subido inicialmente por el código
   fuente y lo publicó en GitHub.
