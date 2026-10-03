/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        soc: {
          bg: '#090d16',
          surface: '#111827',
          elevated: '#1a2234',
          highlight: '#243046',
          border: '#1f293d',
          'border-light': '#2e3d5b',
          muted: '#64748b',
          secondary: '#94a3b8',
          primary: '#f1f5f9',
        },
        risk: {
          critical: '#ef4444',
          'critical-bg': 'rgba(239, 68, 68, 0.12)',
          'critical-border': 'rgba(239, 68, 68, 0.3)',
          high: '#f97316',
          'high-bg': 'rgba(249, 115, 22, 0.12)',
          'high-border': 'rgba(249, 115, 22, 0.3)',
          medium: '#eab308',
          'medium-bg': 'rgba(234, 179, 8, 0.12)',
          'medium-border': 'rgba(234, 179, 8, 0.3)',
          low: '#3b82f6',
          'low-bg': 'rgba(59, 130, 246, 0.12)',
          'low-border': 'rgba(59, 130, 246, 0.3)',
        },
        app: {
          affected: '#f43f5e',
          'not-affected': '#10b981',
          unknown: '#6b7280',
          detected: '#8b5cf6',
          review: '#f59e0b',
        },
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'Consolas', 'monospace'],
        sans: ['Inter', 'system-ui', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'sans-serif'],
      },
    },
  },
  plugins: [],
};
