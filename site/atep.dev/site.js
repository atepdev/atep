// Theme toggle. Dark is the default; a stored choice (theme-boot.js applies it before paint) wins.
(function () {
  var btn = document.getElementById("theme");
  if (!btn) return;
  var root = document.documentElement;
  function current() { return root.getAttribute("data-theme") === "light" ? "light" : "dark"; }
  function label() {
    var light = current() === "light";
    btn.textContent = light ? "Use dark theme" : "Use light theme";
    btn.setAttribute("aria-pressed", light ? "true" : "false");
  }
  label();
  btn.addEventListener("click", function () {
    var next = current() === "dark" ? "light" : "dark";
    root.setAttribute("data-theme", next);
    try { localStorage.setItem("theme", next); } catch (e) {}
    label();
  });
})();
