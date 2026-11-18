import { createContext, useContext, useEffect, useMemo, useState } from "react";

const ThemeContext = createContext(null);
export const useTheme = () => useContext(ThemeContext);

function initialTheme() {
  const saved = localStorage.getItem("cpt_theme");
  if (saved === "light" || saved === "dark") return saved;
  return document.documentElement.dataset.theme === "dark" ? "dark" : "light";
}

export function ThemeProvider({ children }) {
  const [theme, setTheme] = useState(initialTheme);
  useEffect(() => { document.documentElement.dataset.theme = theme; }, [theme]);
  const value = useMemo(() => ({
    theme,
    toggleTheme: () => setTheme((current) => {
      const next = current === "dark" ? "light" : "dark";
      localStorage.setItem("cpt_theme", next);
      return next;
    }),
  }), [theme]);
  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}
