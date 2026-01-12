export function isValidJSON(str: string): boolean {
  try { JSON.parse(str); return true; } catch { return false; }
}

export function isValidJWT(str: string): boolean {
  const parts = str.split('.');
  if (parts.length !== 3) return false;
  try {
    const decode = (s: string) => JSON.parse(atob(s.replace(/-/g, '+').replace(/_/g, '/')));
    return typeof decode(parts[0]) === 'object' && typeof decode(parts[1]) === 'object';
  } catch { return false; }
}

export function isValidEmail(str: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(str);
}

export function looksLikeAPIKey(str: string): boolean {
  if (str.length < 16 || str.length > 256) return false;
  if (!/^[a-zA-Z0-9_-]+$/.test(str)) return false;
  return new Set(str).size >= 8;
}

export function looksLikePhoneNumber(str: string): boolean {
  return /^[+]?[(]?[0-9]{1,4}[)]?[-\s./0-9]{7,}$/.test(str.replace(/\s/g, ''));
}

export function looksLikeCreditCard(str: string): boolean {
  const cleaned = str.replace(/[\s-]/g, '');
  if (!/^[0-9]{13,19}$/.test(cleaned)) return false;
  let sum = 0, isEven = false;
  for (let i = cleaned.length - 1; i >= 0; i--) {
    let digit = parseInt(cleaned[i], 10);
    if (isEven) { digit *= 2; if (digit > 9) digit -= 9; }
    sum += digit;
    isEven = !isEven;
  }
  return sum % 10 === 0;
}

export function looksLikeSSN(str: string): boolean {
  return /^(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}$/.test(str);
}