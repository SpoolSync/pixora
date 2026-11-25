/* Pixora kit: what every newer Pixora app shares.
   - One Pixora account and ONE Pixora passcode for all of these apps. The passcode unwraps a master secret
     kept in the account at apps/pixora/users/<uid> (stored only wrapped). Each app derives its own key from
     it, so the apps can't read each other's data, and the server, the project owner and any AI see only
     scrambled bytes.
   - The passcode is typed once per phone per app; after that the app opens straight away.
   - The app's whole state is one encrypted document at apps/<app>/users/<uid>, newest copy wins.
     It also stays on the phone, so the app works offline and catches up later.
   - Optional: a summary for Pixora Today (pixora-summary.js) and anonymous usage counts (pixora-usage.js).
   Shared file: the same copy lives in every app that uses it. Change it in one, copy it to all. */
(function(root){
"use strict";
var ITER=600000,enc=new TextEncoder(),dec=new TextDecoder();
var K={cfg:null,fdb:null,user:null,key:null,state:null,status:"",pushT:null,pushing:false,again:false,unsub:null,local:false};
function $(s){return document.querySelector(s);}
function esc(s){return String(s==null?"":s).replace(/[&<>"']/g,function(c){return {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c];});}
function rnd(n){return crypto.getRandomValues(new Uint8Array(n));}
function b64(u){var s="",i;for(i=0;i<u.length;i+=0x8000)s+=String.fromCharCode.apply(null,u.subarray(i,i+0x8000));return btoa(s);}
function unb64(s){var b=atob(s),o=new Uint8Array(b.length),i;for(i=0;i<b.length;i++)o[i]=b.charCodeAt(i);return o;}
function T(f){try{if(root.PixoraUsage)PixoraUsage.track(f);}catch(e){}}

/* ---- this phone's storage ---- */
var dbp=null;
function idb(mode,fn){
  if(!dbp)dbp=new Promise(function(res,rej){var r=indexedDB.open("pixora-"+K.cfg.app,1);r.onupgradeneeded=function(){r.result.createObjectStore("kv");};r.onsuccess=function(){res(r.result);};r.onerror=function(){rej(r.error);};});
  return dbp.then(function(db){return new Promise(function(res,rej){var tx=db.transaction("kv",mode),rq=fn(tx.objectStore("kv"));tx.oncomplete=function(){res(rq?rq.result:undefined);};tx.onerror=tx.onabort=function(){rej(tx.error);};});});
}
function get(k){return idb("readonly",function(s){return s.get(k);});}
function put(k,v){return idb("readwrite",function(s){return s.put(v,k);});}
function del(k){return idb("readwrite",function(s){return s.delete(k);});}
function who(){return K.local?"local":K.user.uid;}

/* ---- keys ---- */
async function kek(pass,salt,iter){
  var base=await crypto.subtle.importKey("raw",enc.encode(pass),"PBKDF2",false,["deriveKey"]);
  return crypto.subtle.deriveKey({name:"PBKDF2",salt:salt,iterations:iter,hash:"SHA-256"},base,{name:"AES-GCM",length:256},false,["encrypt","decrypt"]);
}
async function appKey(masterRaw){
  var base=await crypto.subtle.importKey("raw",masterRaw,"HKDF",false,["deriveKey"]);
  return crypto.subtle.deriveKey({name:"HKDF",hash:"SHA-256",salt:enc.encode("pixora"),info:enc.encode("pixora-app:"+K.cfg.app)},base,{name:"AES-GCM",length:256},false,["encrypt","decrypt"]);
}
function masterDoc(){return K.fdb.doc("apps/pixora/users/"+K.user.uid);}
function stateDoc(){return K.fdb.doc("apps/"+K.cfg.app+"/users/"+K.user.uid);}
async function seal(key,obj){var iv=rnd(12);return {iv:b64(iv),ct:b64(new Uint8Array(await crypto.subtle.encrypt({name:"AES-GCM",iv:iv},key,enc.encode(JSON.stringify(obj)))))};}
async function open(key,box){return JSON.parse(dec.decode(await crypto.subtle.decrypt({name:"AES-GCM",iv:unb64(box.iv)},key,unb64(box.ct))));}
async function setPass(pass){
  var m=rnd(32),salt=rnd(16),w=await seal(await kek(pass,salt,ITER),{m:b64(m)}),mid=b64(rnd(9)).replace(/[+/=]/g,"");
  await masterDoc().set({mk:{v:1,id:mid,salt:b64(salt),iter:ITER,iv:w.iv,ct:w.ct}},{merge:true});
  K.key=await appKey(m);m.fill(0);await put("key:"+K.user.uid,{key:K.key,mid:mid});
}
async function enterPass(pass,mk){
  var o=await open(await kek(pass,unb64(mk.salt),Math.min(Math.max(+mk.iter||ITER,100000),2000000)),mk);
  var m=unb64(o.m);K.key=await appKey(m);m.fill(0);await put("key:"+K.user.uid,{key:K.key,mid:mk.id});
}

/* ---- state ---- */
function clean(s){
  s=s&&typeof s==="object"?s:{};var out;try{out=K.cfg.clean(s);}catch(e){out=K.cfg.clean({});}
  /* The Pixora country travels inside each app's encrypted data, whatever the app's own clean() keeps. */
  var PC=root.PixoraCountry;if(PC&&PC.ok(s.country)){out.country=s.country;out.countryAt=+s.countryAt||0;}
  return out;
}
/* Agree on one country: whichever was chosen most recently, on this phone or in synced data. */
function syncCountry(s){
  var PC=root.PixoraCountry;if(!PC||!s)return false;
  if(PC.ok(s.country)&&(s.countryAt||0)>PC.stamp()){PC.set(s.country,s.countryAt,true);return false;}
  if(PC.chosen()&&(s.country!==PC.get()||(s.countryAt||0)<PC.stamp())){s.country=PC.get();s.countryAt=PC.stamp();return true;}
  return false;
}
async function loadLocal(){var s=await get("state:"+who()).catch(function(){return null;});return s?clean(s):null;}
/* Save: on the phone right away, to the cloud a moment later. */
function save(s){
  s=s||K.state;s.ts=Date.now();K.state=s;
  put("state:"+who(),s).catch(function(){});
  if(!K.local){clearTimeout(K.pushT);K.pushT=setTimeout(push,800);}
  summary();
}
async function push(){
  if(K.local||!K.user||!K.key)return;
  if(K.pushing){K.again=true;return;}
  K.pushing=true;setStatus(navigator.onLine===false?"offline":"syncing");
  try{var s=K.state,box=await seal(K.key,s);await stateDoc().set({v:1,ts:s.ts,iv:box.iv,ct:box.ct});setStatus("synced");}
  catch(e){setStatus(navigator.onLine===false?"offline":"error");}
  finally{K.pushing=false;if(K.again){K.again=false;push();}}
}
function setStatus(s){K.status=s;try{if(K.cfg.onStatus)K.cfg.onStatus(statusText());}catch(e){}}
function statusText(){return K.local?"On this phone only":K.status==="synced"?"Synced":K.status==="syncing"?"Syncing…":K.status==="offline"?"Offline · will sync later":K.status==="error"?"Sync paused":"Connecting…";}
function listen(){
  if(K.unsub)K.unsub();
  K.unsub=stateDoc().onSnapshot(async function(snap){
    if(snap.metadata.hasPendingWrites||!snap.exists)return;
    var d=snap.data();if(!d.ct||(d.ts||0)<=(K.state.ts||0))return;
    try{var s=clean(await open(K.key,d));s.ts=d.ts;K.state=s;syncCountry(s);put("state:"+who(),s).catch(function(){});setStatus("synced");K.cfg.onRemote(s);summary();}catch(e){}
  },function(){setStatus("offline");});
}
async function openApp(){
  var local=await loadLocal(),cloud=null,unreadable=false;
  if(K.pendingLocal&&!K.local){local=K.pendingLocal;local.ts=Date.now();K.pendingLocal=null;}
  if(!K.local){
    try{
      var snap=await Promise.race([stateDoc().get(),new Promise(function(_,r){setTimeout(function(){r("slow");},8000);})]);
      if(snap.exists&&snap.data().ct){try{cloud=clean(await open(K.key,snap.data()));cloud.ts=snap.data().ts;}catch(e){unreadable=true;}}
      setStatus("synced");
    }catch(e){setStatus("offline");}
  }
  var s=cloud&&(!local||(cloud.ts||0)>(local.ts||0))?cloud:local||clean({});
  K.state=s;if(syncCountry(s))s.ts=Date.now();put("state:"+who(),s).catch(function(){});
  if(!K.local&&(unreadable||!cloud||(local&&(local.ts||0)>(cloud.ts||0))))if(s.ts)push();
  if(!K.local)listen();
  hideGate();K.cfg.onOpen(s,{unreadable:unreadable});summary();T("open_app");
  if(!K.local&&K.cfg.app!=="legacy")setTimeout(legacyCheck,1500);
}
/* If a trusted person has asked to open this person's Legacy file, say so in every Pixora app,
   so the waiting period actually gets noticed. Reads only the request's status, nothing else. */
async function legacyCheck(){
  try{
    var q=await K.fdb.collection("legacyGrants").where("owner","==",K.user.uid).where("status","==","requested").limit(5).get();
    if(q.empty||$("#pk-legacy"))return;
    var st=document.createElement("style");st.textContent="#pk-legacy{position:sticky;top:0;z-index:50;display:block;background:#b42318;color:#fff;padding:calc(10px + env(safe-area-inset-top)) 16px 10px;font:600 14px/1.35 system-ui,sans-serif;text-decoration:none}";
    var a=document.createElement("a");a.id="pk-legacy";a.href="/legacy/";
    a.textContent=(q.size===1?"Someone you trust has":q.size+" people you trust have")+" asked to open your Legacy file. If that's not expected, open Legacy and deny it. Tap to open.";
    document.head.append(st);document.body.prepend(a);T("legacy_alert_seen");
  }catch(e){}
}
function summary(){
  if(K.local||!K.user||!K.cfg.summary||!root.PixoraSummary)return;
  PixoraSummary.schedule(K.cfg.app,function(){return {fdb:K.fdb,uid:K.user.uid,build:function(){return K.cfg.summary(K.state);}};});
}

/* ---- screens ---- */
var STYLE=".pk-gate{min-height:100vh;min-height:100dvh;display:flex;align-items:center;justify-content:center;padding:calc(24px + env(safe-area-inset-top)) 16px calc(24px + env(safe-area-inset-bottom))}"+
 ".pk-card{width:100%;max-width:420px;background:var(--card);border:2px solid var(--ink);border-radius:14px;padding:22px 18px;display:flex;flex-direction:column;gap:14px}"+
 ".pk-card h1{margin:0;font-size:26px;line-height:1.1}.pk-card p{margin:0}.pk-eb{font-family:ui-monospace,Menlo,monospace;font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted)}"+
 ".pk-f{display:flex;flex-direction:column;gap:5px;font-size:13px;font-weight:600}.pk-f input{width:100%;border:1px solid var(--line);background:var(--paper);color:inherit;border-radius:8px;padding:10px;min-height:44px;font-size:16px;font-weight:400}"+
 ".pk-row{display:flex;gap:10px;flex-wrap:wrap}.pk-link{all:unset;cursor:pointer;font-weight:600;text-decoration:underline;color:var(--ink)}.pk-b{border:1px solid var(--ink);background:transparent;color:inherit;border-radius:8px;padding:10px 14px;font:inherit;font-weight:600;cursor:pointer;min-height:44px}"+
 ".pk-b.p{background:var(--ink);color:var(--paper)}.pk-b.q{border-color:var(--line);font-weight:500}.pk-err{color:var(--bad);font-size:14px;font-weight:600;min-height:1px}.pk-mut{color:var(--muted);font-size:14px}";
function gate(html){
  var g=$("#pk-gate");
  if(!g){var st=document.createElement("style");st.textContent=STYLE;document.head.append(st);g=document.createElement("section");g.id="pk-gate";g.className="pk-gate";document.body.prepend(g);}
  g.hidden=false;g.innerHTML='<div class="pk-card"><p class="pk-eb">'+esc(K.cfg.title)+' · Pixora</p>'+html+'</div>';
  if(K.cfg.onGate)K.cfg.onGate(true);
  return g;
}
function hideGate(){var g=$("#pk-gate");if(g){g.hidden=true;g.innerHTML="";}if(K.cfg.onGate)K.cfg.onGate(false);}
var AUTH={"auth/invalid-credential":"That email and password don't match a Pixora account.","auth/wrong-password":"That email and password don't match a Pixora account.","auth/user-not-found":"That email and password don't match a Pixora account.","auth/invalid-login-credentials":"That email and password don't match a Pixora account.","auth/email-already-in-use":"There's already a Pixora account with that email. Tap Sign in.","auth/weak-password":"Use at least 6 characters for the password.","auth/invalid-email":"That doesn't look like an email address.","auth/network-request-failed":"No connection. Connect and try again.","auth/too-many-requests":"Too many tries. Wait a few minutes."};
/* First visit on this phone (the flag is shared by every Pixora app on this site): lead with Create account. */
function showSignIn(mode){
  if(!mode){try{mode=localStorage.getItem("pixora-has-account")?"signin":"create";}catch(e){mode="signin";}}
  var c=mode==="create";
  var g=gate((c?'<h1>Create your Pixora account</h1><p class="pk-mut">'+esc(K.cfg.blurb||"")+' One Pixora account and one passcode work in every Pixora app. Everything is encrypted on your phone first, so nobody else can read it, not even Pixora.</p>'
      :'<h1>Sign in</h1><p class="pk-mut">'+esc(K.cfg.blurb||"")+' Use your Pixora account, the same one as your other Pixora apps. Everything is encrypted on your phone first, so nobody else can read it, not even Pixora.</p>')+
    '<label class="pk-f">Email<input id="pk-em" type="email" autocomplete="username" autocapitalize="off" inputmode="email"></label>'+
    '<label class="pk-f">'+(c?"Choose a password":"Password")+'<input id="pk-pw" type="password" autocomplete="'+(c?"new-password":"current-password")+'"></label><p class="pk-err" id="pk-err"></p>'+
    '<div class="pk-row">'+(c?'<button class="pk-b p" data-m="create">Create account</button>':'<button class="pk-b p" data-m="signin">Sign in</button><button class="pk-b q" data-m="reset">Forgot password</button>')+'</div>'+
    '<p class="pk-mut" style="font-size:14px">'+(c?'Already have a Pixora account? <button class="pk-link" data-m="tosignin">Sign in</button>':'New to Pixora? <button class="pk-link" data-m="tocreate">Create an account</button>')+'</p>'+
    '<button class="pk-b q" data-m="local" style="align-self:flex-start">Use on this phone only, without an account</button>');
  g.onclick=async function(e){
    var b=e.target.closest("[data-m]");if(!b)return;var m=b.dataset.m,err=$("#pk-err");err.textContent="";err.style.color="";
    if(m==="local"){K.local=true;T("local_only");return openApp();}
    if(m==="tosignin"||m==="tocreate")return showSignIn(m==="tosignin"?"signin":"create");
    var em=$("#pk-em").value.trim(),pw=$("#pk-pw").value;
    try{
      if(!/^\S+@\S+\.\S+$/.test(em))throw {code:"auth/invalid-email"};
      if(m==="reset"){await firebase.auth().sendPasswordResetEmail(em);err.style.color="var(--muted)";err.textContent="If that's a Pixora account, a reset link is on its way.";return;}
      if(!pw)throw {message:"Type your password."};
      if(m==="create"&&pw.length<6)throw {code:"auth/weak-password"};
      try{localStorage.setItem("pixora-has-account","1");}catch(e){}
      b.disabled=true;
      if(m==="create")await firebase.auth().createUserWithEmailAndPassword(em,pw);else await firebase.auth().signInWithEmailAndPassword(em,pw);
      T(m==="create"?"account_create":"signin");
    }catch(x){b.disabled=false;err.textContent=AUTH[x&&x.code]||(x&&x.message)||"Something went wrong. Try again.";}
  };
}
async function afterSignIn(){
  var saved=await get("key:"+K.user.uid).catch(function(){return null;}),mk=null,snap=null;
  try{snap=await masterDoc().get();mk=snap.exists?snap.data().mk:null;}
  catch(e){if(saved&&saved.key){K.key=saved.key;return openApp();}return showOffline();}
  if(saved&&saved.key&&mk&&saved.mid===mk.id){K.key=saved.key;return openApp();}
  showPass(mk,saved&&mk&&saved.mid!==mk.id);
}
function showOffline(){
  var g=gate('<h1>Connect once</h1><p class="pk-mut">This phone needs the internet once to set up your encryption key.</p><div class="pk-row"><button class="pk-b p" data-m="retry">Try again</button><button class="pk-b q" data-m="out">Use a different account</button></div>');
  g.onclick=function(e){var b=e.target.closest("[data-m]");if(!b)return;if(b.dataset.m==="retry")afterSignIn();else signOut();};
}
function showPass(mk,changed,arm){
  var set=!mk;
  var g=gate('<h1>'+(set?"Set your Pixora passcode":"Enter your Pixora passcode")+'</h1><p class="pk-mut">'+(set
      ?"One passcode for every Pixora app that uses it. It protects the key that encrypts your data before it leaves the phone. You type it once per phone per app. It can't be recovered, so pick one you'll remember."
      :changed?"Your Pixora passcode was changed or reset on another phone. Enter the current one.":"The same one you use in your other Pixora apps. You type it once on this phone.")+'</p>'+
    '<form id="pk-form" style="display:flex;flex-direction:column;gap:12px"><label class="pk-f">Pixora passcode<input id="pk-p1" type="password" autocomplete="'+(set?"new-password":"current-password")+'"></label>'+
    (set?'<label class="pk-f">Repeat it<input id="pk-p2" type="password" autocomplete="new-password"></label>':"")+
    '<p class="pk-err" id="pk-err"></p><button class="pk-b p" id="pk-go">'+(set?"Set passcode":"Unlock")+'</button></form>'+
    (set?"":'<button class="pk-b q" data-m="forgot" style="align-self:flex-start;color:var(--bad);border-color:var(--bad)">'+(arm?"Tap again: new passcode for all Pixora apps. Cloud copies they can't open are replaced by what's on each phone.":"Forgot it? Start over")+'</button>')+
    '<button class="pk-b q" data-m="out" style="align-self:flex-start">Use a different account</button>');
  try{$("#pk-p1").focus();}catch(e){}
  g.onclick=function(e){var b=e.target.closest("[data-m]");if(!b)return;if(b.dataset.m==="out")return signOut();if(b.dataset.m==="forgot"){if(!arm)return showPass(mk,changed,true);showPass(null);}};
  $("#pk-form").onsubmit=async function(e){
    e.preventDefault();var p1=$("#pk-p1").value,p2=set?$("#pk-p2").value:"",err=$("#pk-err"),go=$("#pk-go");
    if(set&&p1.length<4){err.textContent="Use at least 4 characters.";return;}
    if(set&&p1!==p2){err.textContent="The two passcodes don't match.";return;}
    go.disabled=true;go.textContent=set?"Setting up…":"Unlocking…";
    try{if(set)await setPass(p1);else await enterPass(p1,mk);T(set?"passcode_set":"passcode_enter");}
    catch(x){go.disabled=false;go.textContent=set?"Set passcode":"Unlock";err.textContent=set?"Couldn't save. Check the connection and try again.":"That isn't your Pixora passcode.";return;}
    openApp();
  };
}
async function signOut(){
  if(K.unsub){K.unsub();K.unsub=null;}
  if(K.user)await del("key:"+K.user.uid).catch(function(){});
  K.key=null;K.state=null;K.local=false;
  try{await firebase.auth().signOut();}catch(e){}
  showSignIn();
}
/* Start the app. cfg: {app, title, blurb, version, clean(s), onOpen(state), onRemote(state), summary(state)?, onStatus(text)?, onGate(shown)?} */
async function boot(cfg){
  K.cfg=cfg;
  /* Picking a country in any app's Settings: keep it in this app's data and redraw. */
  addEventListener("pixora-country",function(e){
    if(!K.state)return;K.state.country=e.detail.c;K.state.countryAt=e.detail.at;save(K.state);T("country_"+e.detail.c);
    try{(K.cfg.onCountry||K.cfg.onRemote)(K.state);}catch(x){}
  });
  if(!root.isSecureContext||!root.crypto||!crypto.subtle||!root.indexedDB){gate("<h1>Can't open here</h1><p>Open the app from its https address in a current browser.</p>");return;}
  if(!root.firebase||!root.PIXORA_CLOUD){K.local=true;return openApp();}
  firebase.initializeApp(root.PIXORA_CLOUD);
  K.fdb=firebase.firestore();
  if(root.PIXORA_EMULATOR){K.fdb.useEmulator("127.0.0.1",root.PIXORA_EMULATOR.db);firebase.auth().useEmulator("http://127.0.0.1:"+root.PIXORA_EMULATOR.auth,{disableWarnings:true});}
  K.fdb.enablePersistence({synchronizeTabs:true}).catch(function(){});
  if(root.PixoraUsage)PixoraUsage.init(cfg.app,cfg.version,function(){return K.user&&!K.local?K.fdb:null;});
  addEventListener("online",function(){if(K.user&&K.key&&K.status!=="synced")push();});
  addEventListener("offline",function(){if(K.user)setStatus("offline");});
  var first=true;
  firebase.auth().onAuthStateChanged(async function(u){
    var was=K.user&&K.user.uid;K.user=u||null;
    if(!first&&(u&&u.uid)===was)return;first=false;
    if(K.local&&!u)return;
    if(!u){if(await get("state:local").catch(function(){return null;})){K.local=true;return openApp();}return showSignIn();}
    K.local=false;afterSignIn();
  });
  if("serviceWorker" in navigator)navigator.serviceWorker.register("sw.js").catch(function(){});
}
/* An offline-only person can move to an account later: their phone copy comes along. */
async function joinAccount(){
  var s=K.state;await del("state:local").catch(function(){});K.local=false;
  if(s)K.pendingLocal=s;
  showSignIn();
}
/* Delete this app's data only: the cloud copy, this app's dashboard summary and the copy on this phone.
   The Pixora login and other apps are untouched; deleting the login itself goes through Pixora by email. */
async function deleteAppData(){
  if(K.unsub){K.unsub();K.unsub=null;}clearTimeout(K.pushT);
  if(!K.local&&K.user){
    await stateDoc().delete();
    await K.fdb.doc("apps/dashboard/users/"+K.user.uid+"/inbox/"+K.cfg.app).delete().catch(function(){});
  }
  await del("state:"+who()).catch(function(){});
  K.state=clean({});T("delete_app_data");
  if(!K.local)listen();
  K.cfg.onOpen(K.state,{fresh:true});
}
/* A readable copy of this app's data, as a file the person keeps. It is NOT encrypted, so the app says so.
   cfg.exportable(state) can leave out things that must stay secret (Legacy leaves out its keys). */
function exportCopy(){
  var st=K.cfg.exportable?K.cfg.exportable(K.state):K.state,d=new Date(),z=function(n){return String(n).padStart(2,"0");};
  var day=d.getFullYear()+"-"+z(d.getMonth()+1)+"-"+z(d.getDate());
  var blob=new Blob([JSON.stringify({pixora:K.cfg.app,v:1,saved:d.toISOString(),state:st},null,1)],{type:"application/json"});
  var a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download=K.cfg.app+"-copy-"+day+".json";document.body.append(a);a.click();
  setTimeout(function(){URL.revokeObjectURL(a.href);a.remove();},2000);T("export_copy");
}
/* Bring back a copy made by exportCopy. Replaces what's here; cfg.restore(current, fromFile) can keep parts (Legacy keeps its keys). */
function restoreCopy(text){
  var o;try{o=JSON.parse(text);}catch(e){throw {code:"notjson"};}
  if(!o||o.pixora!==K.cfg.app||!o.state)throw {code:"wrongapp",app:o&&o.pixora};
  var s=K.cfg.clean(o.state);if(K.cfg.restore)s=K.cfg.restore(K.state,s);
  s.ts=Date.now();K.state=s;save(s);K.cfg.onOpen(s,{restored:true});T("restore_copy");return s;
}
root.PixoraKit={boot:boot,save:save,track:T,status:statusText,signOut:signOut,deleteAppData:deleteAppData,
  get state(){return K.state;},get email(){return K.user&&K.user.email;},get local(){return K.local;},
  get db(){return K.local?null:K.fdb;},get uid(){return K.user&&!K.local?K.user.uid:null;},
  joinAccount:joinAccount,esc:esc,exportCopy:exportCopy,restoreCopy:restoreCopy};
})(typeof self!=="undefined"?self:this);
