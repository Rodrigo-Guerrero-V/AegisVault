import { useEffect, useState } from "react";

export type ThemePreference = "light" | "dark" | null;

const STORAGE_KEY = "aegisvault.theme";
const DARK_QUERY = "(prefers-color-scheme: dark)";

function readStoredPreference(): ThemePreference {
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (raw === "light" || raw === "dark") {
      return raw;
    }
  } catch {
    // En caso de restricciones de almacenamiento, seguir preferencia del sistema.
  }
  return null;
}

function applyThemeAttribute(preference: ThemePreference): void {
  if (typeof document === "undefined") return;
  const root = document.documentElement;
  if (preference === "light" || preference === "dark") {
    root.dataset.theme = preference;
  } else {
    delete root.dataset.theme;
  }
}

export function initTheme(): void {
  applyThemeAttribute(readStoredPreference());
}

export function useTheme() {
  const [preference, setPreference] = useState<ThemePreference>(() =>
    readStoredPreference()
  );
  const [systemDark, setSystemDark] = useState<boolean>(() =>
    typeof window !== "undefined" && typeof window.matchMedia === "function"
      ? window.matchMedia(DARK_QUERY).matches
      : false
  );

  useEffect(() => {
    if (typeof window === "undefined" || typeof window.matchMedia !== "function") {
      return;
    }
    const mql = window.matchMedia(DARK_QUERY);
    const onChange = (ev: MediaQueryListEvent) => {
      setSystemDark(ev.matches);
    };
    setSystemDark(mql.matches);
    mql.addEventListener("change", onChange);
    return () => mql.removeEventListener("change", onChange);
  }, []);

  useEffect(() => {
    applyThemeAttribute(preference);
  }, [preference]);

  const isDark = preference !== null ? preference === "dark" : systemDark;

  const setDarkMode = (enabled: boolean) => {
    const next: ThemePreference = enabled ? "dark" : "light";
    try {
      window.localStorage.setItem(STORAGE_KEY, next);
    } catch {
      // Ignorar si localStorage no está disponible.
    }
    applyThemeAttribute(next);
    setPreference(next);
  };

  const resetToSystem = () => {
    try {
      window.localStorage.removeItem(STORAGE_KEY);
    } catch {
      // Ignorar si localStorage no está disponible.
    }
    applyThemeAttribute(null);
    setPreference(null);
  };

  return {
    isDark,
    preference,
    systemDark,
    setDarkMode,
    resetToSystem,
  };
}
