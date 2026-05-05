// In-app notification store backed by localStorage.
// Each notification is immutable once created; only `read` is mutable.

export interface AppNotification {
  id: string;
  type: "success" | "error" | "warning" | "info";
  title: string;
  body?: string;
  href?: string;
  timestamp: number;
  read: boolean;
}

const STORAGE_KEY = "sccap_notifications";
const MAX_STORED = 50;

function load(): AppNotification[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    return JSON.parse(raw) as AppNotification[];
  } catch {
    return [];
  }
}

function save(items: AppNotification[]): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(items.slice(0, MAX_STORED)));
  } catch {
    // quota exceeded — silently ignore
  }
}

// Push a new notification and dispatch a storage event so all tabs/hooks refresh.
export function pushNotification(
  n: Omit<AppNotification, "id" | "timestamp" | "read">,
): void {
  const items = load();
  const next: AppNotification = {
    ...n,
    id: `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
    timestamp: Date.now(),
    read: false,
  };
  save([next, ...items]);
  // Trigger useNotifications listeners in the same tab via a CustomEvent
  // (StorageEvent only fires in other tabs).
  window.dispatchEvent(new CustomEvent("sccap_notifications_changed"));
}

import { useCallback, useEffect, useState } from "react";

export function useNotifications() {
  const [items, setItems] = useState<AppNotification[]>(load);

  const refresh = useCallback(() => setItems(load()), []);

  useEffect(() => {
    window.addEventListener("sccap_notifications_changed", refresh);
    window.addEventListener("storage", refresh);
    return () => {
      window.removeEventListener("sccap_notifications_changed", refresh);
      window.removeEventListener("storage", refresh);
    };
  }, [refresh]);

  const markAllRead = useCallback(() => {
    const next = load().map((n) => ({ ...n, read: true }));
    save(next);
    setItems(next);
    window.dispatchEvent(new CustomEvent("sccap_notifications_changed"));
  }, []);

  const clearAll = useCallback(() => {
    save([]);
    setItems([]);
    window.dispatchEvent(new CustomEvent("sccap_notifications_changed"));
  }, []);

  const markRead = useCallback((id: string) => {
    const next = load().map((n) => (n.id === id ? { ...n, read: true } : n));
    save(next);
    setItems(next);
    window.dispatchEvent(new CustomEvent("sccap_notifications_changed"));
  }, []);

  const unreadCount = items.filter((n) => !n.read).length;

  return { notifications: items, unreadCount, markAllRead, clearAll, markRead };
}
