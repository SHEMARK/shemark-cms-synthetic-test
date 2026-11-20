import fs from 'node:fs';

let content = fs.readFileSync('index.js', 'utf-8');
const id = process.env.GITHUB_CLIENT_ID || '';
const secret = process.env.GITHUB_CLIENT_SECRET || '';

if (id) {
  content = content.replaceAll('__CLIENT_ID__', id);
}
if (secret) {
  content = content.replaceAll('__CLIENT_SECRET__', secret);
}
fs.writeFileSync('index.js', content, 'utf-8');
console.log('Injected OAuth environment variables successfully (id present: ' + Boolean(id) + ', secret present: ' + Boolean(secret) + ')');
