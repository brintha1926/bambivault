module.exports = {
  content: ['./templates/**/*.html'],
  theme: {
    extend: {
      colors: {
        'bg-card': '#FFFFFF', 'bg-subtle': '#F8FAFC', 'border-subtle': '#E2E8F0',
        'text-primary': '#0F172A', 'text-secondary': '#475569', 'text-muted': '#94A3B8',
        'accent': '#0D9488', 'accent-hover': '#0F766E', 'accent-bg': '#F0FDFA',
        'success': '#10B981', 'warning': '#F59E0B', 'danger': '#EF4444', 'critical': '#8B5CF6'
      },
      fontFamily: { sans: ['Inter', 'sans-serif'], mono: ['JetBrains Mono', 'monospace'] },
      boxShadow: {
        card: '0 1px 3px 0 rgba(0,0,0,0.05), 0 1px 2px 0 rgba(0,0,0,0.03)',
        'card-hover': '0 10px 15px -3px rgba(0,0,0,0.05), 0 4px 6px -2px rgba(0,0,0,0.03)'
      }
    }
  },
  plugins: []
};
