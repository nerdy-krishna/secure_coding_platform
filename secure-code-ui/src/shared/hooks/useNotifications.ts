// secure-code-ui/src/shared/hooks/useNotifications.ts
import { useEffect, useState } from 'react';

type NotificationPermission = 'default' | 'granted' | 'denied';

export const useNotifications = () => {
  const [permission, setPermission] = useState<NotificationPermission>('default');

  useEffect(() => {
    if ('Notification' in window) {
      setPermission(Notification.permission);
    }
  }, []);

  const requestPermission = async () => {
    if (!('Notification' in window)) {
      return;
    }
    const newPermission = await Notification.requestPermission();
    setPermission(newPermission);
  };

  const showNotification = (title: string, body: string, icon?: string) => {
    if (!('Notification' in window)) {
      console.error('This browser does not support desktop notification.');
      return;
    }

    // Check the LIVE permission status directly from the browser API.
    // This avoids any issues with React's state updates.
    if (Notification.permission === 'granted') {
      new Notification(title, { body, icon });
    } else {
      // The request to show a notification was made, but permission is not granted.
      // We can silently ignore this or add a console warning for debugging.
      console.warn(`Notification permission is "${Notification.permission}". Notification not shown.`);
    }
  };

  return {
    permission,
    requestPermission,
    showNotification,
  };
};