# Local Vulnerability AI — Backend

Backend en Python con FastAPI, SQLAlchemy asíncrono, SQLite WAL, Alembic, AI layer (Ollama & Ollama SystemOne) y Deterministic Risk Engine.

## Estructura del Backend

```text
backend/
├── src/
│   └── vuln_ai/
│       ├── core/       # Scanners, Matchers, Engine de escaneo y modelos de dominio
│       ├── ai/         # Providers (Ollama, Ollama SystemOne, Fallback) y evaluación IA
│       ├── risk/       # Deterministic Risk Engine y reglas de evaluación de riesgo
│       ├── db/         # Modelos SQLAlchemy, base de datos y repositorios asíncronos
│       ├── api/        # Routers FastAPI, schemas Pydantic y servicios de aplicación
│       └── config.py   # Configuración centralizada vía pydantic-settings
│
├── tests/              # Suite completa de tests unitarios, de integración y API
├── alembic/            # Migraciones de esquema de base de datos
├── alembic.ini         # Configuración de Alembic
├── pyproject.toml      # Dependencias y configuración de herramientas
├── .env.example        # Plantilla de variables de entorno
└── README.md
```

## Requisitos

- Python 3.12+ (soporta 3.12, 3.13, 3.14)
- Ollama (opcional, para enriquecimiento de IA local)

## Instalación

```bash
cd backend

# Crear entorno virtual si no existe
python3 -m venv .venv
source .venv/bin/activate

# Instalar en modo editable con dependencias de desarrollo
pip install -e ".[dev]"
```

## Configuración

Copiar la plantilla de configuración:

```bash
cp .env.example .env
```

Las variables de entorno siguen el prefijo `VULN_AI_` (por ejemplo, `VULN_AI_DATABASE__URL`, `VULN_AI_AI__OLLAMA__BASE_URL`).

## Base de Datos y Migraciones con Alembic

El proyecto utiliza SQLite con modo WAL y SQLAlchemy 2.0 asíncrono.

```bash
cd backend

# Aplicar todas las migraciones a la última versión
alembic upgrade head

# Revertir una migración
alembic downgrade -1

# Crear una nueva migración automáticamente
alembic revision --autogenerate -m "descripcion"
```

## Ejecución del Servidor API

```bash
cd backend

# Iniciar el servidor FastAPI con Uvicorn y recarga automática
uvicorn vuln_ai.api.main:app --reload --host 127.0.0.1 --port 8000
```

Documentación interactiva disponible en:
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`
- Health check: `http://localhost:8000/health`
- Readiness check: `http://localhost:8000/health/ready`

## Ejecución de Tests

```bash
cd backend

# Ejecutar todos los tests
pytest

# Ejecutar tests con reporte de cobertura
pytest --cov=src/vuln_ai --cov-report=term-missing
```

## Calidad de Código (Lint y Formateo)

```bash
cd backend

# Verificar linting con Ruff
ruff check .

# Formatear automáticamente con Ruff
ruff format .

# Verificar formato sin modificar
ruff format --check .
```
