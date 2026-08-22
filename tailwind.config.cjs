/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./apps/web/public/index.html"],
  safelist: [
    "text-emerald-600",
    "text-blue-600",
    "border-emerald-400",
    "border-blue-400",
    "bg-emerald-100",
    "bg-blue-100",
    "bg-emerald-50/50",
    "bg-blue-50/50"
  ],
  theme: {
    extend: {}
  },
  plugins: []
};
