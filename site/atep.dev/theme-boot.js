// Runs in <head> before first paint: apply a stored theme choice. Without one, CSS defaults to dark.
try { var t = localStorage.getItem("theme"); if (t === "light" || t === "dark") document.documentElement.setAttribute("data-theme", t); } catch (e) {}
