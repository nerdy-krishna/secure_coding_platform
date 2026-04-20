// secure-code-ui/src/shared/ui/Modal.tsx
//
// Minimal modal primitive used by the SCCAP admin/settings pages in
// place of antd's Modal. Focus-trap is deliberately skipped — these
// modals are always invoked by the user and their content is small.
// If keyboard trap requirements come up later, wrap with a
// focus-trap-react or hand-roll a small implementation.

import React, { useEffect } from "react";
import { Icon } from "./Icon";

export interface ModalProps {
  open: boolean;
  onClose: () => void;
  title?: React.ReactNode;
  children?: React.ReactNode;
  footer?: React.ReactNode;
  width?: number | string;
}

export const Modal: React.FC<ModalProps> = ({
  open,
  onClose,
  title,
  children,
  footer,
  width = 520,
}) => {
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div
      role="dialog"
      aria-modal="true"
      onClick={onClose}
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(0, 0, 0, 0.45)",
        display: "grid",
        placeItems: "center",
        zIndex: 1000,
        padding: 20,
        animation: "sccap-fade-in .15s var(--ease)",
      }}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        className="surface"
        style={{
          width,
          maxWidth: "100%",
          maxHeight: "90vh",
          overflow: "auto",
          boxShadow: "var(--shadow-lg, 0 20px 40px rgba(0,0,0,.25))",
        }}
      >
        {title !== undefined && (
          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              gap: 12,
              padding: "16px 20px",
              borderBottom: "1px solid var(--border)",
            }}
          >
            <div style={{ fontWeight: 600, color: "var(--fg)", fontSize: 15 }}>
              {title}
            </div>
            <button
              aria-label="Close"
              className="sccap-btn sccap-btn-ghost sccap-btn-icon"
              onClick={onClose}
            >
              <Icon.X size={14} />
            </button>
          </div>
        )}
        <div style={{ padding: 20 }}>{children}</div>
        {footer && (
          <div
            style={{
              borderTop: "1px solid var(--border)",
              padding: "12px 20px",
              display: "flex",
              justifyContent: "flex-end",
              gap: 8,
            }}
          >
            {footer}
          </div>
        )}
      </div>
    </div>
  );
};

export default Modal;
