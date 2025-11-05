import { defineConfig } from "vite"; import fs from "fs"; import path from "path";
export default defineConfig({ server:{ https:{ key:fs.readFileSync(path.resolve(__dirname,"../backend/certs/key.pem")), cert:fs.readFileSync(path.resolve(__dirname,"../backend/certs/cert.pem")) }, port:5173 }});

