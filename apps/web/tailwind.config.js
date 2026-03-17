/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        // Discord-inspired palette
        brand: {
          50: '#eef2ff',
          500: '#5865f2',
          600: '#4752c4',
        },
        surface: {
          900: '#0d1117',
          800: '#161b22',
          700: '#1c2128',
          600: '#21262d',
          500: '#30363d',
          400: '#484f58',
        },
      },
    },
  },
  plugins: [],
};
