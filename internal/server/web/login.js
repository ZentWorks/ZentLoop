const form=document.getElementById('loginForm');
const button=document.getElementById('loginButton');
const statusNode=document.getElementById('loginStatus');
const username=document.getElementById('username');
const password=document.getElementById('password');
function destination(){const raw=new URLSearchParams(location.search).get('next')||'/';return raw.startsWith('/')&&!raw.startsWith('//')&&!raw.includes('\\')?raw:'/';}
form.addEventListener('submit',async ev=>{ev.preventDefault();statusNode.textContent='';button.disabled=true;button.textContent='Signing in…';try{const r=await fetch('/api/auth/login',{method:'POST',cache:'no-store',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:username.value,password:password.value})});if(!r.ok){let message='Sign-in failed.';try{const x=await r.json();if(x&&x.error)message=x.error;}catch(e){}throw new Error(message);}location.replace(destination());}catch(err){statusNode.textContent=err.message||'Sign-in failed.';password.select();button.disabled=false;button.textContent='Sign in';}});
username.focus();
