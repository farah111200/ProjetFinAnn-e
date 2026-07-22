(function () {
  const stored = localStorage.getItem("theme");
  const theme = stored || "dark";
  document.documentElement.setAttribute("data-theme", theme);

  window.toggleTheme = function () {
    const current = document.documentElement.getAttribute("data-theme");
    const next = current === "light" ? "dark" : "light";
    document.documentElement.setAttribute("data-theme", next);
    localStorage.setItem("theme", next);
    document.querySelectorAll("[data-theme-icon]").forEach((el) => {
      el.innerHTML = next === "light" ? ICONS.sun : ICONS.moon;
    });
  };

  const ICONS = {
    sun: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>',
    moon: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>',
  };
  window.THEME_ICONS = ICONS;

  document.addEventListener("DOMContentLoaded", () => {
    document.querySelectorAll("[data-theme-icon]").forEach((el) => {
      el.innerHTML = theme === "light" ? ICONS.sun : ICONS.moon;
    });
  });
})();
