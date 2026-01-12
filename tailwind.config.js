module.exports = {
  darkMode: 'class',
  content: ['./src/**/*.{html,ts}'],
  theme: {
    extend: {
      colors: {
        background: {
          light: '#FDFCF5', // Premium Cream
          dark: '#121212',  // Deep Charcoal
        },
        surface: {
          light: '#FFFFFF',
          dark: '#1E1E1E',  // Slate Charcoal
        },
        primary: {
          DEFAULT: '#3B82F6', // Vibrant Blue
          hover: '#2563EB',
          dark: '#60A5FA',
        },
        secondary: {
          light: '#94A3B8', // Slate Grey
          dark: '#475569',
        },
        accent: {
          cream: '#F5F5DC',
          charcoal: '#1A1A1A',
        }
      },
      fontFamily: {
        sans: ['Inter', 'Outfit', 'system-ui', 'sans-serif'],
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'fade-in': 'fadeIn 0.5s ease-out',
        'slide-up': 'slideUp 0.4s ease-out',
      },
      keyframes: {
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        slideUp: {
          '0%': { transform: 'translateY(10px)', opacity: '0' },
          '100%': { transform: 'translateY(0)', opacity: '1' },
        }
      },
      backdropBlur: {
        xs: '2px',
      }
    }
  },
  plugins: []
};