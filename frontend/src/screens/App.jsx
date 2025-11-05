import React,{useEffect,useState} from "react";
const API="https://localhost:8443";

async function getCsrf(){const r=await fetch(`${API}/api/csrf-token`,{credentials:"include"}); return (await r.json()).csrfToken;}
function useForm(i){const [v,s]=useState(i); return {values:v,set:s,bind:n=>({value:v[n]||"",onChange:e=>s(x=>({...x,[n]:e.target.value}))})};}
function PasswordHint({value}){const strong=/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{12,}$/.test(value||""); return <div style={{fontSize:"0.9em"}}>Password must be 12+ chars with upper, lower & digit — {strong?"Looks strong ✅":"Not strong ❌"}</div>;}

export default function App(){
  const [csrf,setCsrf]=useState(""); const [msg,setMsg]=useState("");
  const reg=useForm({fullName:"",email:"",idNumber:"",accountNumber:"",password:""});
  const login=useForm({email:"",password:""});
  const pay=useForm({amount:"",currency:"ZAR",provider:"SWIFT",payeeAccount:"",swiftCode:""});

  useEffect(()=>{getCsrf().then(setCsrf).catch(()=>setMsg("API not reachable. Start backend first."));},[]);
  async function post(url,body){const r=await fetch(`${API}${url}`,{method:"POST",headers:{"Content-Type":"application/json","X-CSRF-Token":csrf},credentials:"include",body:JSON.stringify(body)}); const d=await r.json().catch(()=>({})); if(!r.ok) throw new Error(d.error||"Request failed"); return d;}

  return <div style={{maxWidth:900,margin:"40px auto",fontFamily:"system-ui, Segoe UI, Roboto"}}>
    <h1>Customer International Payments Portal</h1>
    <p>HTTPS, CSRF, Argon2id hashing, regex whitelists, and rate limits are enforced.</p>

    <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:24}}>
      <section style={{border:"1px solid #ddd",borderRadius:12,padding:16}}>
        <h2>Register</h2>
        <input placeholder="Full Name" {...reg.bind("fullName")} pattern="[A-Za-z ,.'-]{2,80}"/>
        <input placeholder="Email" type="email" {...reg.bind("email")}/>
        <input placeholder="ID Number" {...reg.bind("idNumber")} pattern="[0-9]{6,18}"/>
        <input placeholder="Account Number" {...reg.bind("accountNumber")} pattern="[0-9]{6,20}"/>
        <input placeholder="Password" type="password" {...reg.bind("password")}/>
        <PasswordHint value={reg.values.password}/>
        <button onClick={async()=>{try{await post("/api/auth/register",reg.values); setMsg("Registered! Now login.")}catch(e){setMsg(e.message)}}}>Create account</button>
      </section>

      <section style={{border:"1px solid #ddd",borderRadius:12,padding:16}}>
        <h2>Login</h2>
        <input placeholder="Email" type="email" {...login.bind("email")}/>
        <input placeholder="Password" type="password" {...login.bind("password")}/>
        <button onClick={async()=>{try{await post("/api/auth/login",login.values); setMsg("Logged in!")}catch(e){setMsg(e.message)}}}>Login</button>
      </section>
    </div>

    <section style={{marginTop:32,border:"1px solid #ddd",borderRadius:12,padding:16}}>
      <h2>Create International Payment</h2>
      <div style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:12}}>
        <input placeholder="Amount" {...pay.bind("amount")}/>
        <input placeholder="Currency (e.g., ZAR, USD)" {...pay.bind("currency")} pattern="[A-Z]{3}"/>
        <input placeholder="Provider" {...pay.bind("provider")}/>
        <input placeholder="Payee Account" {...pay.bind("payeeAccount")} pattern="[0-9]{6,20}"/>
        <input placeholder="SWIFT Code" {...pay.bind("swiftCode")} pattern="[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?"/>
      </div>
      <button style={{marginTop:12}} onClick={async()=>{try{await post("/api/payments/create",pay.values); setMsg("Payment captured. Pending employee verification.")}catch(e){setMsg(e.message)}}}>Submit Payment</button>
    </section>

    <p style={{marginTop:20,color:msg.includes("!")?"green":"#d33"}}>{msg}</p>
  </div>;
}

