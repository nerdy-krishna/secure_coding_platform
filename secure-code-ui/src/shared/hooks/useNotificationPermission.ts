// secure-code-ui/src/shared/hooks/useNotificationPermission.ts
//
// Browser desktop-notification permission state + opt-in / opt-out
// helpers for the open-tab notification flow (features.md §6).
//
// Per the close-features-4-6 threat model:
// - N2: `request()` MUST only be called from a user-gesture click
//   handler. Browsers reject permission requests that originate from
//   a `useEffect`/page-load context, and silently train users to
//   click "Block" if we ask without warning. The hook does not call
//   `request()` itself; callers (e.g. the TopNav opt-in button) do.
// - Once the user clicks "no thanks" (`dismiss()`) or the browser
//   reports `"denied"`, we persist `notifications_dismissed=true` in
//   localStorage and never re-prompt. The user can re-enable by
//   clearing the key (DevTools) or via a future Settings toggle.

import { useCallback, useEffect, useState } from "react";

const DISMISSED_KEY = "notifications_dismissed";

function readDismissed(): boolean {
  try {
    return localStorage.getItem(DISMISSED_KEY) === "true";
  } catch {
    // Private/incognito tabs may throw on localStorage access; treat
    // as not-dismissed so the user can opt in (the API itself is the
    // source of truth for permission state regardless).
    return false;
  }
}

function writeDismissed(value: boolean): void {
  try {
    if (value) localStorage.setItem(DISMISSED_KEY, "true");
    else localStorage.removeItem(DISMISSED_KEY);
  } catch {
    // ignore
  }
}

export interface NotificationPermissionState {
  /** True when the browser exposes the Notification API. */
  supported: boolean;
  /** Browser's current permission ("default" / "granted" / "denied"). */
  permission: NotificationPermission;
  /** True when the user explicitly clicked "no thanks" or browser denied. */
  dismissed: boolean;
  /**
   * Request the browser permission prompt. MUST be invoked from a
   * user-gesture click handler. On `"denied"`, also persists the
   * dismissed flag so we don't re-prompt.
   */
  request: () => Promise<NotificationPermission>;
  /** Persist a "no thanks" so the opt-in button stops showing. */
  dismiss: () => void;
}

export function useNotificationPermission(): NotificationPermissionState {
  const supported = typeof window !== "undefined" && "Notification" in window;

  const [permission, setPermission] = useState<NotificationPermission>(() =>
    supported ? Notification.permission : "denied",
  );
  const [dismissed, setDismissed] = useState<boolean>(() => readDismissed());

  // Re-sync on mount in case another tab changed permission or the
  // user cleared the localStorage key from DevTools.
  useEffect(() => {
    if (!supported) return;
    setPermission(Notification.permission);
    setDismissed(readDismissed());
  }, [supported]);

  const request = useCallback(async (): Promise<NotificationPermission> => {
    if (!supported) return "denied";
    const result = await Notification.requestPermission();
    setPermission(result);
    if (result === "denied") {
      writeDismissed(true);
      setDismissed(true);
    }
    return result;
  }, [supported]);

  const dismiss = useCallback(() => {
    writeDismissed(true);
    setDismissed(true);
  }, []);

  return { supported, permission, dismissed, request, dismiss };
}
