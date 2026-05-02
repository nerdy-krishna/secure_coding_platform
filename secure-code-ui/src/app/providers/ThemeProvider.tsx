// secure-code-ui/src/app/providers/ThemeProvider.tsx
//
// Manages the SCCAP theme mode + color-variation attributes on
// document.documentElement. Persists theme + variant + optional accent
// override to localStorage and writes matching `data-theme` /
// `data-variant` attributes so the token CSS picks them up. The user
// edits these from the Appearance settings page.

import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from "react";

export type SccapTheme = "light" | "dark";
export type SccapVariant = "A" | "B";

interface ThemeContextValue {
  theme: SccapTheme;
  variant: SccapVariant;
  accent: string;
  setTheme: (theme: SccapTheme) => void;
  setVariant: (variant: SccapVariant) => void;
  setAccent: (accent: string) => void;
  toggleTheme: () => void;
}

const STORAGE_KEYS = {
  theme: "sccap-theme",
  variant: "sccap-variant",
  accent: "sccap-accent",
  role: "sccap-role",
} as const;

const ThemeContext = createContext<ThemeContextValue | null>(null);

function readStored<T extends string>(key: string, fallback: T, valid: readonly T[]): T {
  if (typeof window === "undefined") return fallback;
  const raw = window.localStorage.getItem(key);
  return valid.includes(raw as T) ? (raw as T) : fallback;
}

// Allow-list regex for CSS color values accepted as accent overrides.
// Permits #hex (3–8 hex digits), rgb(), rgba(), hsl(), hsla(), oklch(), color().
// Rejects strings containing ; or { } to prevent CSS injection.
const ACCENT_RE =
  /^#[0-9a-fA-F]{3,8}$|^(rgb|rgba|hsl|hsla|oklch|color)\([^;{}]{0,80}\)$/i;

function safeAccent(raw: string): string {
  const trimmed = raw.slice(0, 128);
  return ACCENT_RE.test(trimmed) && !/[;{}]/.test(trimmed) ? trimmed : "";
}

function readAccent(): string {
  if (typeof window === "undefined") return "";
  const raw = window.localStorage.getItem(STORAGE_KEYS.accent) || "";
  return safeAccent(raw);
}

export const ThemeProvider: React.FC<{ children: React.ReactNode }> = ({
  children,
}) => {
  const [theme, setThemeState] = useState<SccapTheme>(() =>
    readStored<SccapTheme>(STORAGE_KEYS.theme, "light", ["light", "dark"]),
  );
  const [variant, setVariantState] = useState<SccapVariant>(() =>
    readStored<SccapVariant>(STORAGE_KEYS.variant, "A", ["A", "B"]),
  );
  const [accent, setAccentState] = useState<string>(() => readAccent());

  // Drop the legacy `sccap-role` localStorage entry from the cosmetic
  // role-preview era — role is now derived solely from user.is_superuser.
  useEffect(() => {
    if (typeof window !== "undefined") {
      window.localStorage.removeItem(STORAGE_KEYS.role);
    }
  }, []);

  // Write attributes + persist on every change.
  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    document.documentElement.setAttribute("data-variant", variant);
    window.localStorage.setItem(STORAGE_KEYS.theme, theme);
    window.localStorage.setItem(STORAGE_KEYS.variant, variant);
  }, [theme, variant]);

  // Accent override — sets --primary + --primary-strong to the same hue
  // (the prototype does this naively; a proper OKLCH derivation can come
  // later if the palette needs nuance).
  useEffect(() => {
    const validated = safeAccent(accent);
    window.localStorage.setItem(STORAGE_KEYS.accent, validated);
    if (validated) {
      document.documentElement.style.setProperty("--primary", validated);
      document.documentElement.style.setProperty("--primary-strong", validated);
    } else {
      document.documentElement.style.removeProperty("--primary");
      document.documentElement.style.removeProperty("--primary-strong");
    }
  }, [accent]);

  const toggleTheme = useCallback(() => {
    setThemeState((t) => (t === "light" ? "dark" : "light"));
  }, []);

  const value = useMemo<ThemeContextValue>(
    () => ({
      theme,
      variant,
      accent,
      setTheme: setThemeState,
      setVariant: setVariantState,
      setAccent: setAccentState,
      toggleTheme,
    }),
    [theme, variant, accent, toggleTheme],
  );

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
};

export function useTheme(): ThemeContextValue {
  const ctx = useContext(ThemeContext);
  if (!ctx) {
    throw new Error("useTheme must be used inside a ThemeProvider.");
  }
  return ctx;
}
