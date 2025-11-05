import React,{useEffect,useState} from "react";
const API="https://localhost:8443";
async function csrf(){const r=await fetch(`${API}/api/csrf-token`,{credentials:"include"});return (await r.json()).csrfToken;}
function useForm(i){const [v,s]=useState(i);return {values:v,set:s,bind:n=>({value:v[n]||"",onChange:e=>s(x=>({...x,[n]:e.target.value}))})};}
export default function App(){
  const [t,setT]=useState(""),[msg,setMsg]=useState(""),[rows,setRows]=useState([]);
  const login=useForm({email:"",password:""});
  useEffect(()=>{csrf().then(setT).catch(()=>setMsg("API not reachable"));},[]);
  async function post(u,b){const r=await fetch(`${API}${u}`,{method:"POST",headers:{"Content-Type":"application/json","X-CSRF-Token":t},credentials:"include",body:JSON.stringify(b)});const d=await r.json().catch(()=>({}));if(!r.ok)throw new Error(d.error||"Request failed");return d;}
  async function get(u){const r=await fetch(`${API}${u}`,{headers:{"X-CSRF-Token":t},credentials:"include"});const d=await r.json().catch(()=>({}));if(!r.ok)throw new Error(d.error||"Request failed");return d;}
  const doLogin=async()=>{try{await post("/api/employee/login",login.values);setMsg("Employee logged in.");setRows(await get("/api/employee/payments/pending"));}catch(e){setMsg(e.message)}};
  const verify=async(id)=>{try{await post(`/api/employee/payments/${id}/verify`,{});setMsg(`Payment ${id} verified.`);}catch(e){setMsg(e.message)}};
  return <div style={{maxWidth:1000,margin:"40px auto",fontFamily:"system-ui,Segoe UI,Roboto"}}>
    <h1>Employee International Payments Portal</h1>
    <section style={{border:"1px solid #ddd",borderRadius:12,padding:16,marginBottom:24}}>
      <h2>Employee Login</h2>
      <input placeholder="Email" type="email" {...login.bind("email")}/>
      <input placeholder="Password" type="password" {...login.bind("password")}/>
      <button onClick={doLogin}>Login</button>
    </section>
    <section style={{border:"1px solid #ddd",borderRadius:12,padding:16}}>
      <h2>Pending Payments</h2>
      <table style={{width:"100%",borderCollapse:"collapse"}}>
        <thead><tr><th>ID</th><th>Customer</th><th>Amount</th><th>Currency</th><th>Provider</th><th>Payee</th><th>SWIFT</th><th>Action</th></tr></thead>
        <tbody>
          {rows.map(p=>(
            <tr key={p.id}>
              <td>{p.id}</td><td>{p.customer}</td><td>{p.amount}</td>
              <td>{p.currency}</td><td>{p.provider}</td>
              <td>{p.payee_account}</td><td>{p.swift_code}</td>
              <td><button onClick={()=>verify(p.id)}>Verify</button></td>
            </tr>
          ))}
          {!rows.length && <tr><td colSpan="8" style={{textAlign:"center"}}>Login to load payments</td></tr>}
        </tbody>
      </table>
    </section>
    <p style={{marginTop:20,color:msg.includes("!")?"green":"#d33"}}>{msg}</p>
  </div>;
}

