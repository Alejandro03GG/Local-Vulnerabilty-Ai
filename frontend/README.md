# Local Vulnerability AI — Frontend Console

Frontend web profesional para **Local Vulnerability AI**, diseñado como un panel de **Security Operations Center (SOC)**, Software Composition Analysis (SCA) y Threat Intelligence.

---

## 1. Stack Tecnológico

- **Framework**: React 18 + TypeScript + Vite
- **Estilos**: Tailwind CSS (Dark-first SOC Design System)
- **Routing**: React Router v6
- **Server State & Caching**: TanStack Query v5
- **Iconos**: Lucide React
- **Testing**: Vitest + Testing Library + jsdom
- **Calidad de Código**: ESLint 9 + Prettier

---

## 2. Arquitectura de Directorios

```text
frontend/
├── public/
├── src/
│   ├── app/
│   │   ├── App.tsx
│   │   ├── router.tsx
│   │   └── providers.tsx
│   ├── components/
│   │   ├── badges/
│   │   │   ├── ApplicabilityBadge.tsx
│   │   │   ├── RiskBadge.tsx
│   │   │   ├── ScanStatusBadge.tsx
│   │   │   ├── SourceStatusBadge.tsx
│   │   │   └── ReviewBadge.tsx
│   │   ├── intelligence/
│   │   │   ├── AIAnalysisCard.tsx
│   │   │   ├── AuditTrace.tsx
│   │   │   ├── ConflictPanel.tsx
│   │   │   └── SystemOneCard.tsx
│   │   ├── layout/
│   │   │   ├── AppShell.tsx
│   │   │   ├── CommandMenu.tsx
│   │   │   ├── PageHeader.tsx
│   │   │   ├── Sidebar.tsx
│   │   │   └── Topbar.tsx
│   │   └── ui/
│   │       ├── DataTable.tsx
│   │       ├── EmptyState.tsx
│   │       ├── ErrorState.tsx
│   │       ├── LoadingState.tsx
│   │       ├── Metric.tsx
│   │       └── Toast.tsx
│   ├── context/
│   │   └── ToastContext.ts
│   ├── hooks/
│   │   └── useToast.ts
│   ├── lib/
│   │   └── utils.ts
│   ├── pages/
│   │   ├── ComponentsPage.tsx
│   │   ├── DashboardPage.tsx
│   │   ├── MatchDetailPage.tsx
│   │   ├── MatchesPage.tsx
│   │   ├── ProjectDetailPage.tsx
│   │   ├── ProjectsPage.tsx
│   │   ├── ScanDetailPage.tsx
│   │   ├── ScansPage.tsx
│   │   ├── SettingsPage.tsx
│   │   ├── SourcesPage.tsx
│   │   ├── VulnerabilitiesPage.tsx
│   │   └── VulnerabilityDetailPage.tsx
│   ├── services/
│   │   └── api/
│   │       ├── client.ts
│   │       ├── components.ts
│   │       ├── health.ts
│   │       ├── matches.ts
│   │       ├── projects.ts
│   │       ├── scans.ts
│   │       ├── sources.ts
│   │       └── vulnerabilities.ts
│   ├── styles/
│   │   └── globals.css
│   ├── test/
│   │   ├── apiClient.test.ts
│   │   ├── badges.test.tsx
│   │   ├── conflictAndAudit.test.tsx
│   │   ├── criticalConflict.test.tsx
│   │   ├── dataTableAndMetric.test.tsx
│   │   ├── details.test.tsx
│   │   ├── fixtures.ts
│   │   ├── routing.test.tsx
│   │   ├── setup.ts
│   │   └── uiStates.test.tsx
│   ├── types/
│   │   └── index.ts
│   ├── main.tsx
│   └── vite-env.d.ts
├── .env.example
├── index.html
├── package.json
├── tsconfig.json
├── vite.config.ts
├── vitest.config.ts
├── tailwind.config.js
├── postcss.config.js
├── eslint.config.js
└── prettier.config.js
```

---

## 3. Configuración y Desarrollo

### Variables de Entorno

Crear `.env` basándose en `.env.example`:

```bash
VITE_API_BASE_URL=http://localhost:8000
```

### Scripts de Ejecución

```bash
# Instalar dependencias
npm install

# Iniciar servidor de desarrollo (puerto 5173)
npm run dev

# Verificación de tipos TypeScript
npm run typecheck

# Linter de código
npm run lint

# Formato de código
npm run format:check
npm run format

# Ejecutar tests unitarios
npm run test
npm run test:coverage

# Compilar para producción
npm run build

# Previsualizar bundle de producción
npm run preview
```

---

## 4. Principios Clave de Diseño y Seguridad

1. **Sin `VULNERABLE`**: El frontend utiliza rigurosamente las clasificaciones deterministas del backend (`LIKELY_AFFECTED`, `LIKELY_NOT_AFFECTED`, `UNKNOWN`, `DETECTED`, `REQUIRES_REVIEW`) y nunca el término ambiguo `VULNERABLE`.
2. **Sin Mock Data en Producción**: Toda la información procede de la API local en FastAPI.
3. **Discrepancias Auditables**: Discrepancias entre fuentes de inteligencia (OSV, NVD, CISA KEV) se destacan mediante `ConflictPanel`.
4. **Separación Determinista vs IA**: El análisis de lenguaje contextual (Ollama) y el soporte de decisión rápida (SystemOne) se presentan con etiquetas claras de advertencia, dejando el veredicto final y el cálculo de riesgo al `DeterministicRiskEngine` del backend.
