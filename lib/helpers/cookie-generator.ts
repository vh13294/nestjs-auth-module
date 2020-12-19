export function generateCookie(
  key: string,
  value: string,
  maxAgeInSecond: number,
): string {
  return (
    `${key}=${value}; ` +
    'Secure; ' + // must be enable for https, can skip if use cloudflare
    'HttpOnly; ' +
    'SameSite=Strict; ' +
    'Path=/; ' +
    `Max-Age=${maxAgeInSecond}`
  );
}

export function dayToSecond(day: number) {
  return day * 86400;
}

export function minuteToSecond(minute: number) {
  return minute * 60;
}
