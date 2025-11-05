export const patterns = {
  name: /^[A-Za-z ,.'-]{2,80}$/,
  idNumber: /^[0-9]{6,18}$/,
  accountNumber: /^[0-9]{6,20}$/,
  email: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
  swift: /^[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?$/,
  currency: /^[A-Z]{3}$/,
  provider: /^[A-Za-z0-9 _.\-]{2,40}$/
};

export const isPasswordStrong = (pw) =>
  /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{12,}$/.test(pw || "");

export function sanitizeString(s) {
  s = (s ?? "").toString().trim();
  return s.replace(/[^a-zA-Z0-9 @._,'\/\-]/g, "");
}

