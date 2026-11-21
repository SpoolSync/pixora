"use strict";
/* Pixora Today: one glance at every Pixora app.
   Each app encrypts a short summary to this dashboard's public key and drops it in your own corner of the
   Pixora account (apps/dashboard/users/<uid>/inbox/<app>). Only this dashboard holds the private key, wrapped
   by the dashboard passcode, so nobody else can read the summaries: not the server, not the project owner,
   not an AI. Nothing here is sent anywhere else. */
var APPS={
  spendlog:{name:"Spend Log",cls:"spend",url:"/spend-log/",blurb:"Bills, purchases and returns"},
  splitlog:{name:"Split Log",cls:"split",url:"/split-log/",blurb:"Splits and settling up with friends"},
  contour:{name:"Contour",cls:"fit",url:"/Contour/",blurb:"Food, workouts and body"}
};
var ORDER=["spendlog","splitlog","contour"];
var ITER=600000;
var fdb=null,cuser=null,PRIV=null,KID=null,inbox={},unsub=null,screen="home",state="connecting",keepOn=true,hiddenAt=0;

/* ---------- small helpers ---------- */
function $(id){return document.getElementById(id);}
function T(f){try{if(window.PixoraUsage)PixoraUsage.track(f);}catch(e){}}
function h(tag,attrs){
  var el=document.createElement(tag),k,v;
  if(attrs)for(k in attrs){v=attrs[k];if(v==null||v===false)continue;
    if(k==="class")el.className=v;else if(k==="text")el.textContent=v;
    else if(k.slice(0,2)==="on")el.addEventListener(k.slice(2),v);
    else el.setAttribute(k,v===true?"":v);}
  for(var i=2;i<arguments.length;i++)add(el,arguments[i]);
  return el;
}
function add(el,c){if(c==null||c===false)return;if(Array.isArray(c)){c.forEach(function(x){add(el,x);});return;}el.append(c.nodeType?c:document.createTextNode(String(c)));}
function z(n){return String(n).padStart(2,"0");}
function iso(d){return d.getFullYear()+"-"+z(d.getMonth()+1)+"-"+z(d.getDate());}
function today(){return iso(new Date());}
function fromIso(s){var p=String(s).split("-");return new Date(+p[0],+p[1]-1,+p[2]);}
function daysFrom(s){return Math.round((fromIso(s)-fromIso(today()))/86400000);}
function dayWord(s){var n=daysFrom(s);return n===0?"today":n===1?"tomorrow":n===-1?"yesterday":n<0?(-n)+" days ago":n<7?fromIso(s).toLocaleDateString("en-CA",{weekday:"long"}):fromIso(s).toLocaleDateString("en-CA",{month:"short",day:"numeric"});}
var fmts={};
function money(n,cur){cur=cur||"CAD";if(!fmts[cur])fmts[cur]=new Intl.NumberFormat("en-CA",{style:"currency",currency:cur});return fmts[cur].format(n||0).replace(/^CA/,"");}
function num(n,d){return (+n||0).toLocaleString("en-CA",{maximumFractionDigits:d==null?0:d});}
function ago(ms){var s=Math.round((Date.now()-ms)/1000);if(s<90)return "just now";var m=Math.round(s/60);if(m<60)return m+" min ago";var hr=Math.round(m/60);if(hr<24)return hr+" h ago";var d=Math.round(hr/24);return d+(d===1?" day ago":" days ago");}
function rnd(n){return crypto.getRandomValues(new Uint8Array(n));}
function b64(u){var s="",i;for(i=0;i<u.length;i+=0x8000)s+=String.fromCharCode.apply(null,u.subarray(i,i+0x8000));return btoa(s);}
function unb64(s){var b=atob(s),o=new Uint8Array(b.length),i;for(i=0;i<b.length;i++)o[i]=b.charCodeAt(i);return o;}
var toastT=null;
function toast(m){var t=$("toast");t.textContent=m;t.hidden=false;clearTimeout(toastT);toastT=setTimeout(function(){t.hidden=true;},4000);}
function armed(btn,label,fn){var on=false;btn.addEventListener("click",function(){if(!on){on=true;btn.textContent=label;return;}fn();});return btn;}

/* ---------- this phone's storage ---------- */
var dbp=null;
function idb(mode,fn){
  if(!dbp)dbp=new Promise(function(res,rej){var r=indexedDB.open("pixoratoday",1);r.onupgradeneeded=function(){r.result.createObjectStore("kv");};r.onsuccess=function(){res(r.result);};r.onerror=function(){rej(r.error);};});
  return dbp.then(function(db){return new Promise(function(res,rej){var tx=db.transaction("kv",mode),rq=fn(tx.objectStore("kv"));tx.oncomplete=function(){res(rq?rq.result:undefined);};tx.onerror=tx.onabort=function(){rej(tx.error);};});});
}
function kvGet(k){return idb("readonly",function(s){return s.get(k);});}
function kvSet(k,v){return idb("readwrite",function(s){return s.put(v,k);});}

/* ---------- keys ---------- */
async function kek(pass,salt,iter){
  var base=await crypto.subtle.importKey("raw",new TextEncoder().encode(pass),"PBKDF2",false,["deriveKey"]);
  return crypto.subtle.deriveKey({name:"PBKDF2",salt:salt,iterations:iter,hash:"SHA-256"},base,{name:"AES-GCM",length:256},false,["encrypt","decrypt"]);
}
function dashDoc(){return fdb.doc("apps/dashboard/users/"+cuser.uid);}
function inboxCol(){return dashDoc().collection("inbox");}
/* First dashboard for this account: make the key pair, keep the private half wrapped by the passcode. */
async function createKeys(pass){
  var pair=await crypto.subtle.generateKey({name:"ECDH",namedCurve:"P-256"},true,["deriveKey"]);
  var pub=await crypto.subtle.exportKey("jwk",pair.publicKey),pk8=new Uint8Array(await crypto.subtle.exportKey("pkcs8",pair.privateKey));
  var salt=rnd(16),iv=rnd(12),ct=new Uint8Array(await crypto.subtle.encrypt({name:"AES-GCM",iv:iv},await kek(pass,salt,ITER),pk8));
  pk8.fill(0);
  var kid=b64(rnd(9)).replace(/[+/=]/g,"");
  await dashDoc().set({v:1,kid:kid,pub:{x:pub.x,y:pub.y},iter:ITER,salt:b64(salt),wiv:b64(iv),wct:b64(ct),at:firebase.firestore.FieldValue.serverTimestamp()});
  return openKeys(pass,{kid:kid,iter:ITER,salt:b64(salt),wiv:b64(iv),wct:b64(ct)});
}
async function openKeys(pass,d){
  var pk8=new Uint8Array(await crypto.subtle.decrypt({name:"AES-GCM",iv:unb64(d.wiv)},await kek(pass,unb64(d.salt),Math.min(Math.max(+d.iter||ITER,100000),2000000)),unb64(d.wct)));
  var priv=await crypto.subtle.importKey("pkcs8",pk8,{name:"ECDH",namedCurve:"P-256"},false,["deriveKey"]);
  pk8.fill(0);
  PRIV=priv;KID=d.kid;
  await remember();
}
async function remember(){try{keepOn=(await kvGet("keep"))!==false;await kvSet("key",keepOn&&PRIV?{uid:cuser.uid,kid:KID,priv:PRIV}:null);}catch(e){}}
async function openBox(d){
  var epk=await crypto.subtle.importKey("jwk",{kty:"EC",crv:"P-256",x:d.ex,y:d.ey,ext:true},{name:"ECDH",namedCurve:"P-256"},false,[]);
  var aes=await crypto.subtle.deriveKey({name:"ECDH",public:epk},PRIV,{name:"AES-GCM",length:256},false,["decrypt"]);
  return JSON.parse(new TextDecoder().decode(await crypto.subtle.decrypt({name:"AES-GCM",iv:unb64(d.iv)},aes,unb64(d.ct))));
}

/* ---------- live summaries ---------- */
function listen(){
  if(unsub)unsub();
  state="connecting";
  /* If the dashboard was started over on another phone, this phone's key no longer fits: ask for the new passcode. */
  var keyWatch=dashDoc().onSnapshot(function(d){
    if(d.metadata.fromCache)return;
    if(!d.exists||d.data().kid!==KID){toast("The dashboard was reset on another phone. Enter its new passcode.");lockNow();}
  },function(){});
  var inboxUnsub=inboxCol().onSnapshot({includeMetadataChanges:true},async function(snap){
    var next={};
    for(var i=0;i<snap.docs.length;i++){
      var doc=snap.docs[i],d=doc.data();
      if(!APPS[doc.id]||d.kid!==KID)continue;
      try{var o=await openBox(d);if(o&&o.app===doc.id&&o.data&&typeof o.data==="object")next[doc.id]={at:+o.at||d.ts||0,data:o.data};}catch(e){}
    }
    inbox=next;state=snap.metadata.fromCache?(navigator.onLine===false?"offline":"connecting"):"live";
    kvSet("last:"+cuser.uid,{kid:KID,inbox:inbox}).catch(function(){});
    if(screen==="home")render();else paintStatus();
  },function(){state=navigator.onLine===false?"offline":"error";paintStatus();});
  unsub=function(){keyWatch();inboxUnsub();};
}
addEventListener("online",function(){if(PRIV&&cuser&&state!=="live")listen();});
addEventListener("offline",function(){state="offline";paintStatus();});

/* ---------- screens ---------- */
function show(which){$("gate").hidden=which!=="gate";$("app").hidden=which!=="app";}
function render(){
  var app=$("app");app.textContent="";show("app");
  if(screen==="settings")return drawSettings(app);
  var d=new Date();
  app.append(h("header",{class:"top"},
    h("div",null,h("p",{class:"eyebrow",text:d.toLocaleDateString("en-CA",{weekday:"long",month:"long",day:"numeric"})}),h("h1",{text:greet(d)})),
    h("button",{type:"button",class:"btn quiet mini",text:"Settings",onclick:function(){T("settings");screen="settings";render();}})),
    statusChip());
  var items=attention();
  if(items.length){
    var box=h("section",{class:"attn","aria-label":"Needs attention"},h("p",{class:"eyebrow",text:"Needs attention"}));
    items.forEach(function(it){
      box.append(h("a",{class:"row",href:APPS[it.app].url,onclick:function(){T("attention_tap_"+it.app);}},h("span",{class:"dot",style:"background:var(--"+APPS[it.app].cls+")"}),h("span",{class:"what",text:it.text}),h("span",{class:"when",text:it.when||""})));
    });
    app.append(box);
  }else if(Object.keys(inbox).length){
    app.append(h("section",{class:"attn"},h("p",{class:"eyebrow",text:"Needs attention"}),h("p",{class:"small muted",text:"Nothing due in the next few days. You're clear."})));
  }
  var grid=h("section",{class:"grid"});
  ORDER.forEach(function(k){grid.append(card(k));});
  app.append(grid);
  app.append(h("p",{class:"small muted",text:"Summaries are encrypted by each app and opened only here. They update whenever you use an app while signed in to your Pixora account."}));
}
function greet(d){var hr=d.getHours();return hr<5?"Good night":hr<12?"Good morning":hr<17?"Good afternoon":"Good evening";}
function statusText(){return state==="live"?"Up to date":state==="offline"?"Offline · showing the last copy":state==="error"?"Couldn't reach your account":"Connecting…";}
function statusChip(){return h("button",{type:"button",id:"st",class:"status"+(state==="error"?" warn":""),text:statusText(),onclick:function(){if(state!=="live")listen();}});}
function paintStatus(){var s=$("st");if(s){s.textContent=statusText();s.className="status"+(state==="error"?" warn":"");}}

/* What deserves a look today, pulled from every app. Soonest first. */
function attention(){
  var out=[],t=today(),s=inbox.spendlog&&inbox.spendlog.data,x=inbox.splitlog&&inbox.splitlog.data,c=inbox.contour&&inbox.contour.data;
  if(s){
    (s.bills||[]).forEach(function(b){if(!b.paid&&b.due&&daysFrom(b.due)<=3&&daysFrom(b.due)>=-3)out.push({app:"spendlog",k:b.due,text:(daysFrom(b.due)<0?"Overdue: ":"Bill: ")+b.n+" "+money(b.amt,s.cur),when:dayWord(b.due)});});
    (s.returns||[]).forEach(function(r){if(daysFrom(r.by)>=0&&daysFrom(r.by)<=5)out.push({app:"spendlog",k:r.by,text:"Last day to return "+r.w,when:dayWord(r.by)});});
    if(s.inbox>0)out.push({app:"spendlog",k:"9",text:s.inbox+(s.inbox===1?" bank row needs":" bank rows need")+" details"});
    if(s.d===t&&!s.todayDone&&new Date().getHours()>=18)out.push({app:"spendlog",k:"9",text:"Nothing logged in Spend Log today"});
  }
  if(x&&x.totals)Object.keys(x.totals).forEach(function(cur){var v=x.totals[cur];if(v.owe>0)out.push({app:"splitlog",k:"8",text:"You owe "+money(v.owe/100,cur)+" in Split Log"});});
  if(c&&c.d===t&&!c.loggedToday&&new Date().getHours()>=14)out.push({app:"contour",k:"9",text:"No food logged in Contour yet today"});
  if(c&&c.workout&&c.workout.today&&!c.workout.doneToday)out.push({app:"contour",k:"9",text:"Today's session: "+c.workout.today});
  out.sort(function(a,b){return String(a.k).localeCompare(String(b.k));});
  return out.slice(0,8);
}

function cardShell(k,body){
  var a=APPS[k],got=inbox[k],stale=got&&got.data.d&&got.data.d!==today();
  return h("article",{class:"card "+a.cls+(k==="spendlog"?" wide":"")},
    h("div",{class:"chead"},h("h2",{text:a.name}),got?h("span",{class:"age"+(stale?" stale":""),text:"Updated "+ago(got.at)}):null),
    body,
    h("div",{class:"btnrow"},h("a",{class:"btn quiet mini",href:a.url,text:"Open "+a.name,onclick:function(){T("open_"+k);}})));
}
function card(k){
  var got=inbox[k];
  if(!got)return cardShell(k,h("div",{class:"empty"},h("p",{text:APPS[k].blurb+". Open "+APPS[k].name+" while signed in to your Pixora account, and its summary shows up here."})));
  try{return cardShell(k,(k==="spendlog"?spendCard:k==="splitlog"?splitCard:fitCard)(got.data));}
  catch(e){return cardShell(k,h("p",{class:"small muted",text:"This summary is from a newer or older version of the app. Open "+APPS[k].name+" once to refresh it."}));}
}
function ln(k,v,cls){return h("div",{class:"ln"},h("span",{class:"k",text:k}),h("span",{class:"lead"}),h("span",{class:"v"+(cls?" "+cls:""),text:v}));}

function spendCard(s){
  var cur=s.cur||"CAD",box=h("div",{style:"display:flex;flex-direction:column;gap:10px"}),sameMonth=s.month===today().slice(0,7);
  box.append(h("p",{class:"sub",text:sameMonth?"Spent this month":"Spent in "+fromIso(s.month+"-01").toLocaleDateString("en-CA",{month:"long"})}),h("p",{class:"big",text:money(s.spent,cur)}));
  if(sameMonth&&s.lastMonthSoFar>0){
    var diff=s.spent-s.lastMonthSoFar;
    box.append(h("p",{class:"small "+(diff>0?"neg":"pos"),text:(diff>0?money(diff,cur)+" more":money(-diff,cur)+" less")+" than this point last month"}));
  }
  if(s.d===today())box.append(ln("Today",s.todayDone?(s.todaySpent?money(s.todaySpent,cur):"No spending"):"Not logged yet",s.todayDone?"":"neg"));
  (s.top||[]).forEach(function(t){box.append(ln(t[0],money(t[1],cur)));});
  if(s.billsTotal){
    box.append(h("p",{class:"sub",style:"margin-top:4px",text:"Bills this month: "+money(s.billsTotal-s.billsLeft,cur)+" paid of "+money(s.billsTotal,cur)}));
    var pct=Math.min(100,Math.round(100*(s.billsTotal-s.billsLeft)/s.billsTotal));
    box.append(h("div",{class:"bar"},h("i",{style:"width:"+pct+"%"})));
    (s.bills||[]).filter(function(b){return !b.paid;}).slice(0,3).forEach(function(b){box.append(ln(b.n+" · "+dayWord(b.due),money(b.amt,cur)));});
  }
  if(s.streak>1)box.append(h("p",{class:"small muted mono",text:s.streak+" days in a row accounted for"}));
  return box;
}
function splitCard(x){
  var box=h("div",{style:"display:flex;flex-direction:column;gap:10px"}),curs=Object.keys(x.totals||{});
  if(!curs.length){box.append(h("p",{class:"sub",text:x.count?"Mark which person is you in each group to see your totals.":"No groups yet."}));return box;}
  curs.forEach(function(cur){
    var v=x.totals[cur],net=v.owed-v.owe;
    box.append(h("p",{class:"sub",text:net>0?"Overall, you're owed":net<0?"Overall, you owe":"All settled"}),h("p",{class:"big "+(net>0?"pos":net<0?"neg":""),text:money(Math.abs(net)/100,cur)}));
  });
  (x.groups||[]).forEach(function(g){box.append(ln(g.n,g.net?(g.net>0?"owed ":"owe ")+money(Math.abs(g.net)/100,g.cur):"settled",g.net>0?"pos":g.net<0?"neg":""));});
  box.append(h("p",{class:"small muted",text:x.count+(x.count===1?" group":" groups")}));
  return box;
}
function fitCard(c){
  var box=h("div",{style:"display:flex;flex-direction:column;gap:10px"}),isToday=c.d===today();
  if(isToday&&c.target){
    var pct=Math.round(100*c.kcal/c.target);
    box.append(h("p",{class:"sub",text:"Calories today"}),h("p",{class:"big",text:num(c.kcal)+" / "+num(c.target)}),
      h("div",{class:"bar"+(pct>105?" over":"")},h("i",{style:"width:"+Math.min(100,pct)+"%"})),
      h("p",{class:"small muted",text:c.kcal<c.target?num(c.target-c.kcal)+" kcal left":num(c.kcal-c.target)+" kcal over"}));
    if(c.pTarget)box.append(ln("Protein",num(c.p)+" / "+num(c.pTarget)+" g"));
  }else box.append(h("p",{class:"sub",text:"Nothing from today yet. Last update: "+dayWord(c.d)+"."}));
  if(c.workout){
    var wk=h("div",{class:"week","aria-label":c.workout.done+" of "+c.workout.of+" sessions done this week"});
    for(var i=0;i<(c.workout.of||6);i++)wk.append(h("span",{class:i<c.workout.done?"on":""}));
    box.append(ln("Workouts this week",c.workout.done+" of "+c.workout.of),wk);
  }
  if(c.weight){
    var w=c.weight,u=w.u==="lb"?"lb":"kg",f=u==="lb"?2.20462:1;
    box.append(ln("Weight",num(w.kg*f,1)+" "+u+(w.ch30!=null?" ("+(w.ch30>0?"+":"")+num(w.ch30*f,1)+" in 30 days)":"")));
  }
  if(c.streak>1)box.append(h("p",{class:"small muted mono",text:c.streak+" days of food logged in a row"}));
  return box;
}

function drawSettings(app){
  app.append(h("button",{type:"button",class:"back",text:"← Today",onclick:function(){screen="home";render();}}),h("h1",{text:"Settings"}));
  app.append(h("div",{class:"panel"},h("h3",{text:"Pixora account"}),h("p",{class:"small",text:"Signed in as "+(cuser.email||"your Pixora account")+"."}),
    h("div",{class:"btnrow"},h("button",{type:"button",class:"btn quiet",text:"Sign out",onclick:async function(){await signOutAll();}}))));
  var every=h("input",{type:"checkbox"});every.checked=!keepOn;
  every.addEventListener("change",function(){keepOn=!every.checked;kvSet("keep",keepOn).then(remember).catch(function(){});});
  app.append(h("div",{class:"panel"},h("h3",{text:"Unlocking"}),
    h("p",{class:"small muted",text:"After the dashboard passcode is entered once, this phone stays unlocked and your phone's own lock protects it."}),
    h("label",{style:"display:flex;gap:10px;align-items:center;min-height:44px"},every,h("span",{text:"Ask for the dashboard passcode every time"})),
    h("div",{class:"btnrow"},h("button",{type:"button",class:"btn quiet",text:"Lock now",onclick:lockNow}))));
  app.append(h("div",{class:"panel"},h("h3",{text:"Who can see what"}),
    h("p",{class:"small",text:"Each app turns its numbers into a short summary, encrypts it with this dashboard's public key, and stores it in your own account. Only a dashboard unlocked with your passcode can open it."}),
    h("p",{class:"small muted",text:"The Pixora servers see that a summary exists and when it changed, never what's in it. No summary is shown to an AI or to anyone else. Other people can't reach your account's summaries at all."})));
  var reset=armed(h("button",{type:"button",class:"btn danger",text:"Forgot the passcode? Start the dashboard over"}),"Tap again: makes new keys and clears the summaries",async function(){
    await startOver();toast("Dashboard reset. Open each app once to fill it again.");
  });
  app.append(h("div",{class:"panel"},h("h3",{text:"Start over"}),h("p",{class:"small muted",text:"Makes a new dashboard key and passcode for your account. Old summaries can't be opened any more, so they're cleared, and each app sends a fresh one the next time you open it. Your data inside the apps isn't touched."}),reset));
}

/* ---------- gate: account and passcode ---------- */
var AUTH_MSG={"auth/invalid-credential":"That email and password don't match a Pixora account.","auth/wrong-password":"That email and password don't match a Pixora account.","auth/user-not-found":"That email and password don't match a Pixora account.","auth/invalid-login-credentials":"That email and password don't match a Pixora account.","auth/email-already-in-use":"There is already a Pixora account with that email. Tap Sign in instead.","auth/weak-password":"Use at least 6 characters for the password.","auth/invalid-email":"That doesn't look like an email address.","auth/network-request-failed":"No connection. Connect to the internet and try again.","auth/too-many-requests":"Too many tries. Wait a few minutes and try again."};
function gate(nodes){var g=$("gateBody");g.textContent="";add(g,[h("p",{class:"eyebrow",text:"Pixora Today"})].concat(nodes));show("gate");}
function showSignIn(problem){
  var msg=h("p",{class:"err",role:"alert",hidden:!problem,text:problem||""});
  var em=h("input",{type:"email",id:"g-email",autocomplete:"username",autocapitalize:"off",spellcheck:"false",inputmode:"email"}),pw=h("input",{type:"password",id:"g-pw",autocomplete:"current-password"});
  function go(mode){return async function(){
    msg.hidden=true;msg.style.color="";var btns=$("gateBody").querySelectorAll("button");btns.forEach(function(b){b.disabled=true;});
    try{
      var e=em.value.trim();if(!/^\S+@\S+\.\S+$/.test(e))throw {code:"auth/invalid-email"};
      if(mode==="reset"){await firebase.auth().sendPasswordResetEmail(e);msg.style.color="var(--muted)";msg.textContent="If a Pixora account uses that email, a reset link is on its way.";msg.hidden=false;}
      else{if(!pw.value)throw {message:"Type your password."};cuser=(mode==="create"?await firebase.auth().createUserWithEmailAndPassword(e,pw.value):await firebase.auth().signInWithEmailAndPassword(e,pw.value)).user;pw.value="";await afterSignIn();return;}
    }catch(x){msg.textContent=AUTH_MSG[x&&x.code]||(x&&x.message)||"Something went wrong. Try again.";msg.hidden=false;}
    btns.forEach(function(b){b.disabled=false;});
  };}
  gate([h("h1",{text:"Sign in"}),h("p",{class:"muted",text:"Use the same Pixora account as your apps. The dashboard shows a summary from each one, and only you can read it."}),
    h("div",{class:"field"},h("label",{for:"g-email",text:"Email"}),em),h("div",{class:"field"},h("label",{for:"g-pw",text:"Password"}),pw),msg,
    h("div",{class:"btnrow"},h("button",{type:"button",class:"btn primary",text:"Sign in",onclick:go("signin")}),h("button",{type:"button",class:"btn",text:"Create account",onclick:go("create")}),h("button",{type:"button",class:"btn quiet",text:"Forgot password",onclick:go("reset")}))]);
}
async function afterSignIn(){
  var snap;
  try{snap=await dashDoc().get();}catch(e){showSignIn("Couldn't reach your Pixora account. Check the connection and try again.");return;}
  var d=snap.exists?snap.data():null;
  showPass(d&&d.wct?d:null);
}
function showPass(existing,problem){
  var msg=h("p",{class:"err",role:"alert",hidden:!problem,text:problem||""});
  var p1=h("input",{type:"password",id:"g-p1",autocomplete:existing?"current-password":"new-password"}),p2=h("input",{type:"password",id:"g-p2",autocomplete:"new-password"});
  var go=h("button",{type:"submit",class:"btn primary",text:existing?"Unlock":"Set passcode"});
  var form=h("form",{novalidate:true,style:"display:flex;flex-direction:column;gap:14px",onsubmit:async function(ev){
    ev.preventDefault();msg.hidden=true;
    if(!existing){
      if(p1.value.length<4){msg.textContent="Use at least 4 characters.";msg.hidden=false;return;}
      if(p1.value!==p2.value){msg.textContent="The two passcodes don't match.";msg.hidden=false;return;}
    }
    go.disabled=true;go.textContent=existing?"Unlocking…":"Setting up…";
    try{
      if(existing)await openKeys(p1.value,existing);else await createKeys(p1.value);
      p1.value=p2.value="";await enter();
    }catch(e){
      go.disabled=false;go.textContent=existing?"Unlock":"Set passcode";
      msg.textContent=existing?"Wrong dashboard passcode.":(e&&e.code==="unavailable"?"You're offline. Connect once to set up the dashboard.":"Couldn't set up the dashboard. Try again.");msg.hidden=false;
    }
  }},
    h("div",{class:"field"},h("label",{for:"g-p1",text:"Dashboard passcode"}),p1),
    existing?null:h("div",{class:"field"},h("label",{for:"g-p2",text:"Repeat passcode"}),p2),msg,go);
  gate([h("h1",{text:existing?"Enter your dashboard passcode":"Set a dashboard passcode"}),
    h("p",{class:"muted",text:existing?"The one you set the first time you used Pixora Today. You type it once per phone.":"It locks the key that opens your apps' summaries. You type it once per phone, then it stays unlocked. It can't be recovered, but you can start the dashboard over without losing anything in your apps."}),
    form,
    existing?armed(h("button",{type:"button",class:"btn quiet danger",text:"Forgot it? Start the dashboard over"}),"Tap again: new keys, summaries cleared",async function(){await startOver(true);}):null,
    h("button",{type:"button",class:"btn quiet",text:"Use a different account",onclick:signOutAll})]);
  try{p1.focus();}catch(e){}
}
async function enter(){
  screen="home";
  var last=await kvGet("last:"+cuser.uid).catch(function(){return null;});
  if(last&&last.kid===KID)inbox=last.inbox||{};
  render();listen();T("view_today");
  try{if(navigator.storage&&navigator.storage.persist)navigator.storage.persist();}catch(e){}
}
async function lockNow(){
  if(unsub){unsub();unsub=null;}
  await kvSet("key",null).catch(function(){});
  PRIV=null;inbox={};
  var snap=await dashDoc().get().catch(function(){return null;});
  showPass(snap&&snap.exists?snap.data():null);
}
async function signOutAll(){
  if(unsub){unsub();unsub=null;}
  await kvSet("key",null).catch(function(){});
  PRIV=null;KID=null;inbox={};
  try{await firebase.auth().signOut();}catch(e){}
  cuser=null;showSignIn();
}
async function startOver(fromGate){
  if(unsub){unsub();unsub=null;}
  var docs=await inboxCol().get().catch(function(){return null;});
  if(docs){var b=fdb.batch();docs.forEach(function(d){b.delete(d.ref);});await b.commit().catch(function(){});}
  await dashDoc().delete().catch(function(){});
  await kvSet("key",null).catch(function(){});await kvSet("last:"+cuser.uid,null).catch(function(){});
  PRIV=null;KID=null;inbox={};
  showPass(null,fromGate?null:null);
}
document.addEventListener("visibilitychange",function(){
  if(document.hidden){hiddenAt=Date.now();return;}
  if(PRIV&&!keepOn&&hiddenAt&&Date.now()-hiddenAt>180000){lockNow();return;}
  if(PRIV&&screen==="home"){render();T("view_today");}
});

/* ---------- start ---------- */
(async function start(){
  if(!window.isSecureContext||!window.crypto||!crypto.subtle||!window.indexedDB){gate([h("h1",{text:"Can't open here"}),h("p",{text:"Pixora Today needs its https address and a current browser."})]);return;}
  if(!window.firebase||!window.PIXORA_CLOUD){gate([h("h1",{text:"Can't open here"}),h("p",{text:"The Pixora account service didn't load."})]);return;}
  firebase.initializeApp(window.PIXORA_CLOUD);
  fdb=firebase.firestore();
  if(window.PIXORA_EMULATOR){fdb.useEmulator("127.0.0.1",window.PIXORA_EMULATOR.db);firebase.auth().useEmulator("http://127.0.0.1:"+window.PIXORA_EMULATOR.auth,{disableWarnings:true});}
  fdb.enablePersistence({synchronizeTabs:true}).catch(function(){});
  if(window.PixoraUsage)PixoraUsage.init("dashboard","pixoratoday-v2",function(){return fdb&&cuser?fdb:null;});
  try{keepOn=(await kvGet("keep"))!==false;}catch(e){}
  var first=true;
  firebase.auth().onAuthStateChanged(async function(u){
    if(!first&&(u&&u.uid)===(cuser&&cuser.uid))return;
    first=false;cuser=u||null;
    if(!u){showSignIn();return;}
    var saved=null;try{saved=await kvGet("key");}catch(e){}
    if(saved&&saved.uid===u.uid&&saved.priv){PRIV=saved.priv;KID=saved.kid;await enter();return;}
    await afterSignIn();
  });
  if("serviceWorker" in navigator)navigator.serviceWorker.register("sw.js").catch(function(){});
})();
