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
