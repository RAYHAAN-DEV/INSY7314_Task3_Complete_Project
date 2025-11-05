import argon2 from "argon2";
import db from "./db.js";

(async ()=>{
  const employees=[
    { full_name:"Employee Admin", email:"admin@bank.local", password:"AdminSecure2025!", role:"EMPLOYEE" },
    { full_name:"Verifier One",  email:"verifier@bank.local", password:"VerifyStrong2025!", role:"EMPLOYEE" }
  ];
  for(const u of employees){
    const ex=db.prepare("SELECT id FROM users WHERE email=?").get(u.email);
    if(ex) { console.log("Exists:", u.email); continue; }
    const hash=await argon2.hash(u.password,{type:argon2.argon2id,timeCost:3,memoryCost:65536,parallelism:2});
    db.prepare("INSERT INTO users(full_name,email,id_number,account_number,password_hash,created_at,role) VALUES(?,?,?,?,?,?,?)")
      .run(u.full_name,u.email,"0000000000000","000000",hash,Date.now(),u.role);
    console.log("Seeded:",u.email);
  }
  console.log("✅ Employee accounts seeded");
  process.exit(0);
})();

