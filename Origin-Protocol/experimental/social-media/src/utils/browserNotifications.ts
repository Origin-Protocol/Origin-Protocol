export function supportsBrowserNotifications(): boolean {
  return typeof window !== 'undefined' && 'Notification' in window;
}

export function getNotificationPermission(): NotificationPermission {
  if (!supportsBrowserNotifications()) return 'denied';
  return Notification.permission;
}

export async function requestBrowserNotificationPermission(): Promise<NotificationPermission> {
  if (!supportsBrowserNotifications()) return 'denied';
  return Notification.requestPermission();
}

function toAbsoluteUrl(href: string): string {
  if (/^https?:\/\//i.test(href)) return href;
  if (href.startsWith('/')) return `${window.location.origin}${href}`;
  return `${window.location.origin}/${href.replace(/^\/+/, '')}`;
}

export function notifyWithExternalOpen(params: {
  title: string;
  body: string;
  href: string;
  tag?: string;
}): boolean {
  if (!supportsBrowserNotifications() || Notification.permission !== 'granted') {
    return false;
  }

  const targetUrl = toAbsoluteUrl(params.href);
  const notification = new Notification(params.title, {
    body: params.body,
    tag: params.tag,
  });

  notification.onclick = () => {
    window.open(targetUrl, '_blank', 'noopener,noreferrer');
    notification.close();
  };

  return true;
}
