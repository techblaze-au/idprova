/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        bg: '#0d1117',
        surface: '#161b22',
        surface2: '#1c2128',
        border: '#30363d',
        text: '#e6edf3',
        'text-muted': '#8b949e',
        accent: '#58a6ff',
        success: '#3fb950',
        danger: '#f85149',
        warning: '#d29922',
      },
    },
  },
  plugins: [],
};
