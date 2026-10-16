/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        page: '#F7F7F2',
        'mint-section': '#EAF6F2',
        charcoal: {
          DEFAULT: '#202622',
          muted: '#5A675F',
          faint: '#87978D',
        },
        forest: {
          DEFAULT: '#315E4B',
          hover: '#264B3C',
          dark: '#1C382C',
        },
        sage: {
          50: '#F4F9F6',
          100: '#E8F3EE',
          200: '#D2E5DC',
          300: '#AECFC2',
          400: '#8FB8A1',
          500: '#549581',
          600: '#315E4B',
          700: '#264B3C',
          800: '#1C382C',
          900: '#14271F',
        },
        card: {
          green: '#DDEFCB',
          blue: '#DCECF7',
          mint: '#D7EBE2',
          surface: '#FFFFFF',
        },
        border: {
          DEFAULT: '#E1E7E2',
          subtle: '#EEF2EF',
          strong: '#CCD5CE',
        }
      },
      fontFamily: {
        sans: [
          'Inter',
          '-apple-system',
          'BlinkMacSystemFont',
          '"Segoe UI"',
          'Roboto',
          'Helvetica',
          'Arial',
          'sans-serif',
        ],
      },
      borderRadius: {
        '2xl': '1rem',
        '3xl': '1.5rem',
        '4xl': '2rem',
      }
    },
  },
  plugins: [],
}
