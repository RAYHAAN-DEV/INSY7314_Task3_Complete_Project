import db from "./db.js";
try{ db.prepare("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'CUSTOMER'").run(); console.log("Added role column."); }
catch(e){ if(String(e).includes("duplicate column")) console.log("Role column already exists."); else console.error(e); }
try{ db.prepare("CREATE INDEX idx_users_email ON users(email)").run(); }catch(e){}
console.log("Migration complete.");

