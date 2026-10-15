/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        // Night-indigo surfaces taken from the Risk Radar logo
        ink: {
          950: '#07081A',
          900: '#0B0D24',
          850: '#0F1230',
          800: '#141838',
          700: '#1C2148',
          600: '#272D5C',
          500: '#3A4178'
        },
        fog: {
          50: '#F5F6FF',
          100: '#E6E8FA',
          200: '#C9CDEE',
          300: '#A4AAD6',
          400: '#8188BA',
          500: '#606795'
        },
        brand: {
          50: '#F5F3FF',
          100: '#EDE9FE',
          200: '#DDD6FE',
          300: '#C4B5FD',
          400: '#A78BFA',
          500: '#8B5CF6',
          600: '#7C3AED',
          700: '#6D28D9',
          800: '#5B21B6',
          900: '#4C1D95'
        },
        signal: {
          300: '#67E8F9',
          400: '#22D3EE',
          500: '#06B6D4'
        },
        risk: {
          low: '#2DD4A4',
          guarded: '#60A5FA',
          medium: '#FBBF24',
          high: '#FB8A3C',
          critical: '#F43F5E'
        }
      },
      fontFamily: {
        display: ['"Chakra Petch"', 'system-ui', 'sans-serif'],
        sans: ['"IBM Plex Sans"', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['"IBM Plex Mono"', 'ui-monospace', 'SFMono-Regular', 'monospace']
      },
      boxShadow: {
        panel: '0 1px 0 0 rgba(255,255,255,0.04) inset, 0 12px 32px -16px rgba(0,0,0,0.6)',
        glow: '0 0 0 1px rgba(167,139,250,0.35), 0 8px 30px -8px rgba(139,92,246,0.55)',
        'glow-cyan': '0 0 0 1px rgba(34,211,238,0.35), 0 8px 30px -10px rgba(34,211,238,0.45)'
      },
      keyframes: {
        'fade-in': { from: { opacity: 0, transform: 'translateY(4px)' }, to: { opacity: 1, transform: 'none' } },
        'toast-in': { from: { opacity: 0, transform: 'translateY(12px) scale(0.98)' }, to: { opacity: 1, transform: 'none' } },
        sweep: { from: { transform: 'rotate(0deg)' }, to: { transform: 'rotate(360deg)' } },
        blip: {
          '0%': { opacity: 0.95, transform: 'scale(1)' },
          '18%': { opacity: 0.6, transform: 'scale(2.6)' },
          '40%, 100%': { opacity: 0, transform: 'scale(3.2)' }
        },
        'scan-line': { '0%': { transform: 'translateX(-100%)' }, '100%': { transform: 'translateX(100%)' } }
      },
      animation: {
        'fade-in': 'fade-in 220ms ease-out both',
        'toast-in': 'toast-in 260ms cubic-bezier(.2,.8,.2,1) both',
        sweep: 'sweep 4s linear infinite',
        blip: 'blip 4s ease-out infinite',
        'scan-line': 'scan-line 1.4s ease-in-out infinite'
      }
    }
  },
  plugins: []
};
