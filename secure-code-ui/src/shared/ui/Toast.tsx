// secure-code-ui/src/shared/ui/Toast.tsx
//
// Lightweight toast/message primitive replacing `message.*` from antd
// across the SCCAP admin pages. Stacked at top-right. Auto-dismisses.
// Uses the same tokens as the rest of the design.

import React, {
  createContext,
  useCallback,
  useContext,
  useRef,
  useState,
} from "react";

type ToastTone = "success" | "error" | "info" | "warn";

interface ToastItem {
  id: number;
  text: string;
  tone: ToastTone;
}

interface ToastAPI {
  show: (text: string, tone?: ToastTone) => void;
  success: (text: string) => void;
  error: (text: string) => void;
  info: (text: string) => void;
  warn: (text: string) => void;
}

const ToastContext = createContext<ToastAPI | null>(null);

export const ToastProvider: React.FC<{ children: React.ReactNode }> = ({
  children,
}) => {
  const [items, setItems] = useState<ToastItem[]>([]);
  const counter = useRef(0);

  const show = useCallback((text: string, tone: ToastTone = "info") => {
    const id = ++counter.current;
    setItems((prev) => [...prev, { id, text, tone }]);
    setTimeout(() => {
      setItems((prev) => prev.filter((t) => t.id !== id));
    }, 4500);
  }, []);

  const api: ToastAPI = {
    show,
    success: (t) => show(t, "success"),
    error: (t) => show(t, "error"),
    info: (t) => show(t, "info"),
    warn: (t) => show(t, "warn"),
  };

  return (
    <ToastContext.Provider value={api}>
      {children}
      <div
        aria-live="polite"
        style={{
          position: "fixed",
          top: 18,
          right: 18,
          display: "grid",
          gap: 8,
          zIndex: 2000,
          pointerEvents: "none",
        }}
      >
        {items.map((t) => (
          <ToastCard key={t.id} item={t} />
        ))}
      </div>
    </ToastContext.Provider>
  );
};

const toneMap: Record<
  ToastTone,
  { bg: string; fg: string; border: string; label: string }
> = {
  success: {
    bg: "var(--success-weak)",
    fg: "var(--success)",
    border: "var(--success)",
    label: "Success",
  },
  error: {
    bg: "var(--critical-weak)",
    fg: "var(--critical)",
    border: "var(--critical)",
    label: "Error",
  },
  info: {
    bg: "var(--info-weak)",
    fg: "var(--info)",
    border: "var(--info)",
    label: "Info",
  },
  warn: {
    bg: "var(--medium-weak)",
    fg: "var(--medium)",
    border: "var(--medium)",
    label: "Warning",
  },
};

const ToastCard: React.FC<{ item: ToastItem }> = ({ item }) => {
  const s = toneMap[item.tone];
  return (
    <div
      role="status"
      style={{
        background: s.bg,
        color: s.fg,
        border: `1px solid ${s.border}`,
        borderRadius: "var(--r-md)",
        padding: "10px 14px",
        fontSize: 13,
        minWidth: 220,
        maxWidth: 360,
        boxShadow: "var(--shadow-sm, 0 2px 8px rgba(0,0,0,.08))",
        pointerEvents: "auto",
      }}
    >
      <div
        style={{
          fontSize: 10,
          fontWeight: 600,
          textTransform: "uppercase",
          letterSpacing: ".08em",
          marginBottom: 2,
        }}
      >
        {s.label}
      </div>
      {item.text}
    </div>
  );
};

export function useToast(): ToastAPI {
  const ctx = useContext(ToastContext);
  if (!ctx) {
    // Graceful fallback for tests / stories that don't mount the provider.
    return {
      show: (t) => console.info("[toast]", t),
      success: (t) => console.info("[toast:success]", t),
      error: (t) => console.error("[toast:error]", t),
      info: (t) => console.info("[toast:info]", t),
      warn: (t) => console.warn("[toast:warn]", t),
    };
  }
  return ctx;
}

export { ToastContext };
