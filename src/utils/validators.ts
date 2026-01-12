export function isEmail(str: string): boolean {
  return /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(str);
}

export function isPhoneNumber(str: string): boolean {
  return /^[+]?[0-9]{10,15}$/.test(str.replace(/[\s\-().]/g, ''));
}

export function isCreditCard(str: string): boolean {
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

export function isSSN(str: string): boolean {
  return /^\d{3}-?\d{2}-?\d{4}$/.test(str);
}

export function containsPII(str: string): { hasPII: boolean; types: string[] } {
  const types: string[] = [];
  if (isEmail(str)) types.push('email');
  if (isPhoneNumber(str)) types.push('phone');
  if (isCreditCard(str)) types.push('credit_card');
  if (isSSN(str)) types.push('ssn');
  return { hasPII: types.length > 0, types };
}