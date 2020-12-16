export function generateCookie(
  key: string,
  value: string,
  maxAgeInSecond: number,
): string {
  return (
    `${key}=${value}; ` +
    'HttpOnly; ' +
    'SameSite=Strict; ' +
    'Path=/; ' +
    `Max-Age=${maxAgeInSecond}`
  );
}

export function dayToSecond(day: string | undefined) {
  if (day) {
    return Number(day) * 86400;
  }
  return 0;
}

export function minuteToSecond(minute: string | undefined) {
  if (minute) {
    return Number(minute) * 60;
  }
  return 0;
}
