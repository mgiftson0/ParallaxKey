/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ['./src/**/*.{html,ts,js}'],
  theme: {
    extend: {
      colors: {
        'vault': {
          50: '#f0f9ff',
          100: '#e0f2fe',
          200: '#bae6fd',
          300: '#7dd3fc',
          400: '#38bdf8',
          500: '#0ea5e9',
          600: '#0284c7',
          700: '#0369a1',
          800: '#075985',
          900: '#0c4a6e',
        },
        'severity': {
          critical: '#dc2626',
          high: '#ea580c',
          medium: '#d97706',
          low: '#2563eb',
          info: '#6b7280',
        },
      },
    },
  },
  plugins: [],
};