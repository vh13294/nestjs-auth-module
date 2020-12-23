export function generateCookie(
  key: string,
  value: string,
  maxAgeInSecond: number,
  secureHttps: boolean,
): string {
  // must be enable for https, can skip if use cloudflare
  const secureHeader = secureHttps ? 'Secure; ' : '';
  return (
    `${key}=${value}; ` +
    secureHeader +
    'HttpOnly; ' +
    'SameSite=Strict; ' +
    'Path=/; ' +
    `Max-Age=${maxAgeInSecond}`
  );
}

export function dayToSecond(day: number): number {
  return day * 86400;
}

export function minuteToSecond(minute: number): number {
  return minute * 60;
}
