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
        gold: ramp('gold'),
        // Semantic token bridge - resolves to CSS vars set in themes.css.
        // Templates write bg-surface/text-muted/bg-accent with no dark: pairs.
        bg:            'rgb(var(--bg) / <alpha-value>)',
        surface:       'rgb(var(--surface) / <alpha-value>)',
        'surface-2':   'rgb(var(--surface-2) / <alpha-value>)',
        border:        'rgb(var(--border) / <alpha-value>)',
        text:          'rgb(var(--text) / <alpha-value>)',
        muted:         'rgb(var(--muted) / <alpha-value>)',
        'muted-2':     'rgb(var(--muted-2) / <alpha-value>)',
        accent:        'rgb(var(--accent) / <alpha-value>)',
        'accent-strong': 'rgb(var(--accent-strong) / <alpha-value>)',
        'accent-weak': 'rgb(var(--accent-weak) / <alpha-value>)',
        'accent-on':   'rgb(var(--accent-on) / <alpha-value>)',
        success:       'rgb(var(--success) / <alpha-value>)',
        'success-weak':'rgb(var(--success-weak) / <alpha-value>)',
        warning:       'rgb(var(--warning) / <alpha-value>)',
        'warning-weak':'rgb(var(--warning-weak) / <alpha-value>)',
        danger:        'rgb(var(--danger) / <alpha-value>)',
        'danger-weak': 'rgb(var(--danger-weak) / <alpha-value>)',
        info:          'rgb(var(--info) / <alpha-value>)',
        'info-weak':   'rgb(var(--info-weak) / <alpha-value>)',
      },
    },
  },
  plugins: [],
};
