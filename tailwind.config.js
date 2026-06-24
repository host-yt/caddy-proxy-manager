/** @type {import('tailwindcss').Config} */
// Scans every Go template (admin / app / install / auth) and the auto-
// generated templ files so class names used in any view get emitted in
// the final stylesheet. darkMode: 'class' matches the existing
// document.documentElement.classList.toggle('dark') bootstrap in every
// layout - we never use prefers-color-scheme as the source of truth
// once the user has flipped the toggle.

// Build a full ramp pointing at CSS vars (channels in themes.css). The
// <alpha-value> placeholder keeps opacity utilities (bg-black/50) working.
const SHADES = [50, 100, 200, 300, 400, 500, 600, 700, 800, 900, 950];
function ramp(name) {
  return Object.fromEntries(
    SHADES.map((s) => [s, `rgb(var(--c-${name}-${s}) / <alpha-value>)`])
  );
}

module.exports = {
  content: [
    './internal/view/**/*.html.tmpl',
    './internal/view/**/*_templ.go',
  ],
  darkMode: 'class',
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', 'ui-sans-serif', 'system-ui', '-apple-system', 'Segoe UI', 'Roboto', 'Helvetica Neue', 'Arial', 'sans-serif'],
      },
      // Remap named ramps to theme vars so every existing utility picks up
      // the active palette with zero template edits. white/black stay
      // literal so text-white on buttons never shifts.
      colors: {
        slate: ramp('slate'),
        zinc: ramp('zinc'),
        indigo: ramp('indigo'),
        emerald: ramp('emerald'),
        rose: ramp('rose'),
        amber: ramp('amber'),
        sky: ramp('sky'),
      },
    },
  },
  plugins: [],
};
