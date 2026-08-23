/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // Enterprise security-operations-center palette built on Tailwind's
        // slate/zinc neutrals with indigo accents for interactive elements.
        panel: "#111827",
        "panel-edge": "#1f2937",
        accent: "#6366f1",
      },
      fontFamily: {
        mono: [
          "JetBrains Mono",
          "Fira Code",
          "Consolas",
          "monospace",
        ],
      },
    },
  },
  plugins: [],
};