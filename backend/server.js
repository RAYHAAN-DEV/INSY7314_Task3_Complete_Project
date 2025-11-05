import express from 'express';
import https from 'https';
import fs from 'fs';
import dotenv from 'dotenv';
import helmet from 'helmet';
import hpp from 'hpp';
import rateLimit from 'express-rate-limit';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import csrf from 'csurf';
import argon2 from 'argon2';
import jwt from 'jsonwebtoken';
import morgan from 'morgan';

import db from './db.js';
import { patterns, isPasswordStrong, sanitizeString } from './validation.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 8443;

const ORIGINS = [
  process.env.CORS_ORIGIN || 'https://localhost:5173',
  'https://localhost:5174'
];

app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: true,
    directives: {
      "default-src": ["'self'"],
      "script-src": ["'self'"],
      "style-src": ["'self'", "'unsafe-inline'"],
      "object-src": ["'none'"],
      "frame-ancestors": ["'none'"],
      "img-src": ["'self'","data:"],
      "connect-src": ["'self'", ...ORIGINS]
    }
  },
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
  referrerPolicy: { policy: "no-referrer" }
}));
app.disable('x-powered-by');
app.use(hpp());
app.use(morgan('combined'));

app.use(cors({
  origin(origin, cb) { if (!origin) return cb(null, true); return cb(null, ORIGINS.includes(origin)); },
  credentials: true, methods: ['GET','POST','OPTIONS'], allowedHeaders: ['Content-Type','X-CSRF-Token']
}));
app.use(express.json({ limit: '50kb' }));
app.use(cookieParser(process.env.COOKIE_SECRET || 'cookie-secret'));

const authLimiter = rateLimit({ windowMs: 15*60*1000, max: 20, standardHeaders: true, legacyHeaders: false });
const paymentLimiter = rateLimit({ windowMs: 15*60*1000, max: 60, standardHeaders: true, legacyHeaders: false });

const csrfProtection = csrf({ cookie: { httpOnly:true, sameSite:'strict', secure:true }, value: req => req.headers['x-csrf-token'] });

const signToken = (payload) => jwt.sign(payload, process.env.JWT_SECRET || 'dev', { expiresIn: '30m' });

function authRequired(req,res,next){
  try{ const t=req.signedCookies['auth']; if(!t) return res.status(401).json({error:'Not authenticated'});
    req.user = jwt.verify(t, process.env.JWT_SECRET || 'dev'); next();
  }catch{ return res.status(401).json({error:'Invalid token'}); }
}
function employeeRequired(req,res,next){
  try{ const t=req.signedCookies['employee_auth']; if(!t) return res.status(401).json({error:'Not authenticated'});
    const d=jwt.verify(t, process.env.JWT_SECRET || 'dev'); if(d.role!=='EMPLOYEE') return res.status(403).json({error:'Forbidden'}); req.employee=d; next();
  }catch{ return res.status(401).json({error:'Invalid token'}); }
}

app.get('/api/csrf-token', csrfProtection, (req,res)=> res.json({ csrfToken: req.csrfToken() }));

app.post('/api/auth/register', authLimiter, csrfProtection, async (req,res)=>{
  const { fullName,email,idNumber,accountNumber,password } = req.body||{};
  const safe = { fullName: sanitizeString(fullName), email:(email||'').toLowerCase().trim(), idNumber:(idNumber||'').trim(), accountNumber:(accountNumber||'').trim() };
  if(!patterns.name.test(safe.fullName)) return res.status(400).json({error:'Invalid name'});
  if(!patterns.email.test(safe.email)) return res.status(400).json({error:'Invalid email'});
  if(!patterns.idNumber.test(safe.idNumber)) return res.status(400).json({error:'Invalid ID number'});
  if(!patterns.accountNumber.test(safe.accountNumber)) return res.status(400).json({error:'Invalid account number'});
  if(!isPasswordStrong(password||'')) return res.status(400).json({error:'Weak password'});

  try{
    const hash = await argon2.hash(password,{ type:argon2.argon2id, timeCost:3, memoryCost:65536, parallelism:2 });
    db.prepare('INSERT INTO users (full_name,email,id_number,account_number,password_hash,created_at,role) VALUES (?,?,?,?,?,?,?)')
      .run(safe.fullName, safe.email, safe.idNumber, safe.accountNumber, hash, Date.now(), 'CUSTOMER');
    res.status(201).json({message:'Registered'});
  }catch(e){ if(String(e).includes('UNIQUE')) return res.status(409).json({error:'Email already exists'}); console.error(e); res.status(500).json({error:'Server error'}); }
});

app.post('/api/auth/login', authLimiter, csrfProtection, async (req,res)=>{
  const { email,password } = req.body||{};
  const row = db.prepare('SELECT * FROM users WHERE email=?').get((email||'').toLowerCase().trim());
  if(!row) return res.status(401).json({error:'Invalid credentials'});

  const now = Date.now();
  if(row.locked_until && now < row.locked_until) return res.status(423).json({error:'Account temporarily locked. Try later.'});

  const ok = await argon2.verify(row.password_hash, password||'');
  if(!ok){ const attempts=(row.failed_attempts||0)+1; let lock=row.locked_until; if(attempts>=5) lock=now+15*60*1000;
    db.prepare('UPDATE users SET failed_attempts=?, locked_until=? WHERE id=?').run(attempts, lock, row.id);
    return res.status(401).json({error:'Invalid credentials'});
  }
  db.prepare('UPDATE users SET failed_attempts=0, locked_until=NULL WHERE id=?').run(row.id);

  const token = signToken({ id:row.id, email:row.email, role: row.role || 'CUSTOMER' });
  res.cookie('auth', token, { httpOnly:true, secure:true, sameSite:'strict', signed:true, maxAge:30*60*1000 });
  res.json({message:'Logged in'});
});

app.post('/api/auth/logout', authRequired, csrfProtection, (req,res)=>{ res.clearCookie('auth'); res.json({message:'Logged out'}); });

app.post('/api/payments/create', authRequired, paymentLimiter, csrfProtection, (req,res)=>{
  const { amount,currency,provider,payeeAccount,swiftCode } = req.body||{};
  const amt=Number(amount); if(!Number.isFinite(amt)||amt<=0) return res.status(400).json({error:'Invalid amount'});
  const cur=(currency||'').toUpperCase().trim(), prov=(provider||'').trim(), payee=(payeeAccount||'').trim(), swift=(swiftCode||'').toUpperCase().trim();
  if(!patterns.currency.test(cur)) return res.status(400).json({error:'Invalid currency'});
  if(!patterns.provider.test(prov)) return res.status(400).json({error:'Invalid provider'});
  if(!patterns.accountNumber.test(payee)) return res.status(400).json({error:'Invalid payee account'});
  if(!patterns.swift.test(swift)) return res.status(400).json({error:'Invalid SWIFT code'});
  db.prepare('INSERT INTO payments (user_id,amount,currency,provider,payee_account,swift_code,created_at) VALUES (?,?,?,?,?,?,?)')
    .run(req.user.id, amt, cur, prov, payee, swift, Date.now());
  res.status(201).json({message:'Payment captured. Pending employee verification.'});
});

app.post('/api/employee/login', authLimiter, csrfProtection, async (req,res)=>{
  const { email,password } = req.body||{};
  const row = db.prepare("SELECT * FROM users WHERE email=? AND role='EMPLOYEE'").get((email||'').toLowerCase().trim());
  if(!row) return res.status(401).json({error:'Invalid credentials'});

  const now=Date.now();
  if(row.locked_until && now<row.locked_until) return res.status(423).json({error:'Account temporarily locked. Try later.'});

  const ok = await argon2.verify(row.password_hash, password||'');
  if(!ok){ const attempts=(row.failed_attempts||0)+1; let lock=row.locked_until; if(attempts>=5) lock=now+15*60*1000;
    db.prepare('UPDATE users SET failed_attempts=?, locked_until=? WHERE id=?').run(attempts, lock, row.id);
    return res.status(401).json({error:'Invalid credentials'});
  }
  db.prepare('UPDATE users SET failed_attempts=0, locked_until=NULL WHERE id=?').run(row.id);

  const token = signToken({ id:row.id, email:row.email, role:'EMPLOYEE' });
  res.cookie('employee_auth', token, { httpOnly:true, secure:true, sameSite:'strict', signed:true, maxAge:30*60*1000 });
  res.json({message:'Employee logged in'});
});

app.get('/api/employee/payments/pending', employeeRequired, csrfProtection, (_req,res)=>{
  const rows = db.prepare(`
    SELECT p.id, u.full_name AS customer, p.amount, p.currency, p.provider,
           p.payee_account, p.swift_code, p.created_at
    FROM payments p JOIN users u ON u.id = p.user_id
    ORDER BY p.created_at DESC
  `).all();
  res.json(rows);
});

app.post('/api/employee/payments/:id/verify', employeeRequired, paymentLimiter, csrfProtection, (req,res)=>{
  const id=Number(req.params.id); if(!Number.isInteger(id)) return res.status(400).json({error:'Invalid id'});
  res.json({message:'Payment verified and forwarded to SWIFT (simulated).'});
});

app.get('/api/health', (_req,res)=> res.json({ ok:true }));

const useHttps = String(process.env.USE_HTTPS || 'true').toLowerCase() === 'true';
if(useHttps){
  const key = fs.readFileSync(process.env.SSL_KEY_PATH || './certs/key.pem');
  const cert= fs.readFileSync(process.env.SSL_CERT_PATH || './certs/cert.pem');
  https.createServer({key,cert}, app).listen(PORT, ()=> console.log(`HTTPS API listening on https://localhost:${PORT}`));
}else{
  app.listen(PORT, ()=> console.log(`HTTP API listening on http://localhost:${PORT}`));
}

