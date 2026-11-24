"use strict";
/* Pixora Admin: how each app is used, so it can be improved. Reads only the anonymous counters and error
   reports under stats/. It has no access to anyone's data: the database rules give the admin nothing else,
   and the data is encrypted anyway. Only the verified admin email can read the counters. */
var ADMIN="pixora3dstudios@gmail.com";
var APPS=[["spendlog","Tally"],["splitlog","Split Log"],["contour","Contour"],["meals","Meals"],["invest","Investments"],["legacy","Legacy"],["dashboard","Pixora Today"]];
var CONSOLE="https://console.firebase.google.com/project/pixora-bca1f";
var fdb=null,user=null,range=30,data={},errors={},loading=false,feedback=[];
function $(id){return document.getElementById(id);}
function h(tag,a){var el=document.createElement(tag),k;if(a)for(k in a){var v=a[k];if(v==null||v===false)continue;if(k==="class")el.className=v;else if(k==="text")el.textContent=v;else if(k.slice(0,2)==="on")el.addEventListener(k.slice(2),v);else el.setAttribute(k,v===true?"":v);}
  for(var i=2;i<arguments.length;i++)add(el,arguments[i]);return el;}
function add(el,c){if(c==null||c===false)return;if(Array.isArray(c)){c.forEach(function(x){add(el,x);});return;}el.append(c.nodeType?c:document.createTextNode(String(c)));}
function z(n){return String(n).padStart(2,"0");}
function iso(d){return d.getFullYear()+"-"+z(d.getMonth()+1)+"-"+z(d.getDate());}
function days(n){var out=[],d=new Date();for(var i=n-1;i>=0;i--){var x=new Date(d);x.setDate(d.getDate()-i);out.push(iso(x));}return out;}
function n(v){return (v||0).toLocaleString("en-CA");}
/* Feature ids are code words; make them readable. */
function label(f){
  var map={open:"App opened",active_device:"Active device (once a day)",signin:"Signed in",
    tab_:"Viewed tab: ",act_:"Tapped: ",form_:"Submitted: ",store_:"Saved: "};
  if(map[f])return map[f];
  for(var p in map)if(p.slice(-1)==="_"&&f.indexOf(p)===0)return map[p]+f.slice(p.length).replace(/_/g," ");
  return f.replace(/_/g," ");
}

async function load(){
  if(loading)return;loading=true;render();
  var from=days(range)[0];
  for(var i=0;i<APPS.length;i++){
    var app=APPS[i][0];
    try{
      var snap=await fdb.collection("stats/"+app+"/f").where("d",">=",from).get();
      var m={};snap.forEach(function(doc){var x=doc.data();(m[x.d]=m[x.d]||{})[x.f]=x.n||0;});data[app]=m;
      var es=await fdb.collection("stats/"+app+"/errors").where("d",">=",from).limit(200).get();
      errors[app]=es.docs.map(function(d){var x=d.data();return {id:d.id,ref:d.ref,m:x.m,v:x.v,p:x.p,d:x.d};});
    }catch(e){data[app]=null;errors[app]=[];data._err=e&&e.code;}
  }
  try{var fb=await fdb.collection("feedback").orderBy("at","desc").limit(100).get();
    feedback=fb.docs.map(function(d){var x=d.data();return {ref:d.ref,app:x.app,kind:x.kind,m:x.m,d:x.d,e:x.e||""};});}catch(e){feedback=[];}
  loading=false;render();
}
function sum(app,feat,ds){var m=data[app]||{},t=0;ds.forEach(function(d){t+=(m[d]&&m[d][feat])||0;});return t;}
function feats(app){var m=data[app]||{},s={};Object.keys(m).forEach(function(d){Object.keys(m[d]).forEach(function(f){s[f]=1;});});return Object.keys(s);}

function render(){
  var root=$("root");root.textContent="";
  if(!user)return signIn(root);
  if(!user.emailVerified)return verify(root);
  var w=h("div",{class:"wrap"});root.append(w);
  w.append(h("header",{class:"top"},h("div",null,h("p",{class:"eyebrow",text:"Pixora Admin"}),h("h1",{text:"How the apps are used"})),
    h("div",{class:"btnrow"},seg(),h("button",{class:"btn quiet",text:loading?"Loading…":"Refresh",onclick:load}),
      h("button",{class:"btn quiet",text:"Sign out",onclick:function(){firebase.auth().signOut();}}))));
  if(data._err==="permission-denied"){
    w.append(h("div",{class:"card"},h("p",{class:"err",text:"This account isn't the Pixora admin."}),
      h("p",{class:"small muted",text:"Only "+("pixora3dstudios@gmail.com")+" can read usage, and only once that email is verified. The admin email is set in the database rules (isPixoraAdmin)."})));
    return;
  }
  var fbc=h("section",{class:"card"},h("h2",{text:"Feedback"+(feedback.length?" ("+feedback.length+")":"")}));
  if(!feedback.length)fbc.append(h("p",{class:"small muted",text:"Nothing yet. People can send it from Settings in each app and from the welcome screen."}));
  var NAMES={};APPS.forEach(function(a){NAMES[a[0]]=a[1];});var KIND={idea:"Idea",bug:"Broken",other:"Other"};
  feedback.forEach(function(f){
    var row=h("div",{class:"fb"},h("p",{class:"small muted",text:f.d+" · "+(NAMES[f.app]||f.app)+" · "+(KIND[f.kind]||f.kind)+(f.e?" · ":"")},f.e?h("a",{href:"mailto:"+f.e+"?subject="+encodeURIComponent("Re: your Pixora feedback"),text:f.e}):null),
      h("p",{class:"fbm",text:f.m}),
      h("div",{class:"btnrow"},h("button",{class:"btn quiet",text:"Done, remove",onclick:async function(){try{await f.ref.delete();feedback=feedback.filter(function(x){return x!==f;});render();}catch(e){}}})));
    fbc.append(row);
  });
  w.append(fbc);
  var all=days(range),today=all.slice(-1),week=all.slice(-7);
  var tiles=h("section",{class:"tiles"});
  APPS.forEach(function(a){
    tiles.append(h("div",{class:"tile",style:"--c:var(--"+a[0]+")"},h("p",{class:"eyebrow",text:a[1]}),
      h("p",{class:"n",text:n(sum(a[0],"active_device",today))}),h("p",{class:"small muted",text:"active devices today · "+n(sum(a[0],"active_device",week))+" device-days this week"})));
  });
  w.append(tiles);
  var g=h("section",{class:"grid2"});
  APPS.forEach(function(a){g.append(appCard(a[0],a[1],all,today,week));});
  w.append(g);
  w.append(h("section",{class:"card"},h("h2",{text:"Also in the Firebase console"}),
    h("p",{class:"small muted",text:"Accounts (emails, sign-up date, last sign-in, disabling or deleting an account) and database limits live in the console. Neither shows anyone's app data: it's encrypted."}),
    h("div",{class:"btnrow"},
      h("a",{class:"btn quiet",href:CONSOLE+"/authentication/users",target:"_blank",rel:"noopener",text:"Accounts"}),
      h("a",{class:"btn quiet",href:CONSOLE+"/firestore/databases/-default-/usage",target:"_blank",rel:"noopener",text:"Database usage and limits"}),
      h("a",{class:"btn quiet",href:CONSOLE+"/usage",target:"_blank",rel:"noopener",text:"Free plan usage"}))));
  w.append(h("p",{class:"small muted",text:"Counts are anonymous: each app adds to a feature counter while someone is signed in. There are no account ids, amounts, names or anything typed. A device that uses an app on several days counts once per day."}));
}
function seg(){
  var s=h("div",{class:"seg",role:"group","aria-label":"Range"});
  [[7,"7 days"],[30,"30 days"],[90,"90 days"]].forEach(function(r){s.append(h("button",{"aria-pressed":String(range===r[0]),text:r[1],onclick:function(){range=r[0];load();}}));});
  return s;
}
function appCard(app,name,all,today,week){
  var c=h("article",{class:"card",style:"--c:var(--"+app+")"},h("h2",{text:name}));
  if(data[app]===null){c.append(h("p",{class:"small muted",text:"Couldn't load."}));return c;}
  var m=data[app]||{},max=1;all.forEach(function(d){max=Math.max(max,(m[d]&&m[d].open)||0);});
  var ch=h("div",{class:"chart",role:"img","aria-label":"App opens per day, last "+all.length+" days"});
  all.forEach(function(d){var o=(m[d]&&m[d].open)||0,a=(m[d]&&m[d].active_device)||0;
    ch.append(h("i",{style:"height:"+Math.round(100*o/max)+"%",title:d+": "+o+" opens, "+a+" active devices"}));});
  c.append(h("p",{class:"small muted",text:"App opens per day · "+n(sum(app,"open",all))+" in "+all.length+" days"}),ch);
  var fs=feats(app).filter(function(f){return f!=="open"&&f!=="active_device";}).map(function(f){return {f:f,t:sum(app,f,today),w:sum(app,f,week),a:sum(app,f,all)};})
    .sort(function(x,y){return y.a-x.a;});
  if(!fs.length)c.append(h("p",{class:"small muted",text:"No feature use recorded yet in this range."}));
  else{
    var top=fs[0].a||1,t=h("table",null,h("thead",null,h("tr",null,h("th",{text:"Feature"}),h("th",{class:"n",text:"Today"}),h("th",{class:"n",text:"7 days"}),h("th",{class:"n",text:all.length+" days"}))));
    var tb=h("tbody");fs.forEach(function(x){tb.append(h("tr",null,h("td",null,h("span",{class:"bar",style:"width:"+Math.max(2,Math.round(60*x.a/top))+"px"}),label(x.f)),h("td",{class:"n",text:n(x.t)}),h("td",{class:"n",text:n(x.w)}),h("td",{class:"n",text:n(x.a)})));});
    t.append(tb);c.append(t);
  }
  var es=errors[app]||[];
  if(es.length){
    var et=h("table",null,h("thead",null,h("tr",null,h("th",{text:"Error ("+es.length+")"}),h("th",{text:"Version"}),h("th",{text:"Device"}),h("th",{text:"Day"}))));
    var eb=h("tbody");es.slice().sort(function(a,b){return b.d.localeCompare(a.d);}).slice(0,15).forEach(function(e){eb.append(h("tr",null,h("td",{class:"mono small",text:e.m}),h("td",{class:"small",text:e.v}),h("td",{class:"small",text:e.p}),h("td",{class:"small",text:e.d})));});
    et.append(eb);c.append(et,h("div",{class:"btnrow"},h("button",{class:"btn quiet",text:"Clear these errors",onclick:async function(){
      for(var i=0;i<es.length;i++)try{await es[i].ref.delete();}catch(x){}load();}})));
  }else c.append(h("p",{class:"small muted",text:"No errors reported in this range."}));
  return c;
}
function signIn(root){
  var em=h("input",{type:"email",autocomplete:"username"}),pw=h("input",{type:"password",autocomplete:"current-password"}),msg=h("p",{class:"err",hidden:true});
  root.append(h("div",{class:"gate"},h("p",{class:"eyebrow",text:"Pixora Admin"}),h("h1",{text:"Sign in"}),
    h("p",{class:"small muted",text:"Usage counts for every Pixora app. Only the Pixora admin account ("+ADMIN+") can see them, and they never include anyone's data. First time? Enter that email and a new password, then tap Create admin account."}),
    h("label",null,"Email",em),h("label",null,"Password",pw),msg,
    h("div",{class:"btnrow"},h("button",{class:"btn",text:"Sign in",onclick:async function(){
      msg.hidden=true;try{await firebase.auth().signInWithEmailAndPassword(em.value.trim(),pw.value);}catch(e){msg.textContent="That email and password don't match a Pixora account.";msg.hidden=false;}
    }}),h("button",{class:"btn quiet",text:"Create admin account",onclick:async function(){
      msg.hidden=true;var e=em.value.trim().toLowerCase();
      if(e!==ADMIN){msg.textContent="Only "+ADMIN+" can be the Pixora admin.";msg.hidden=false;return;}
      if(pw.value.length<8){msg.textContent="Use a password of at least 8 characters.";msg.hidden=false;return;}
      try{await firebase.auth().createUserWithEmailAndPassword(e,pw.value);}
      catch(x){msg.textContent=x&&x.code==="auth/email-already-in-use"?"That email already has a Pixora account. Tap Sign in, or Forgot password if you don't know it.":"Couldn't create it. Try again.";msg.hidden=false;}
    }}),h("button",{class:"btn quiet",text:"Forgot password",onclick:async function(){
      try{await firebase.auth().sendPasswordResetEmail(em.value.trim());}catch(e){}msg.textContent="If that's a Pixora account, a reset link is on its way.";msg.hidden=false;
    }}))));
}
function verify(root){
  var msg=h("p",{class:"small muted"});
  root.append(h("div",{class:"gate"},h("p",{class:"eyebrow",text:"Pixora Admin"}),h("h1",{text:"Confirm your email"}),
    h("p",{class:"small",text:"Usage is only shown to a verified admin email. Send the confirmation link, open it, then come back and tap I've confirmed it."}),msg,
    h("div",{class:"btnrow"},
      h("button",{class:"btn",text:"Send the link",onclick:async function(){try{await user.sendEmailVerification();msg.textContent="Sent to "+user.email+".";}catch(e){msg.textContent="Couldn't send. Try again in a minute.";}}}),
      h("button",{class:"btn quiet",text:"I've confirmed it",onclick:async function(){
        try{var cu=firebase.auth().currentUser;await cu.reload();await cu.getIdToken(true);}catch(e){msg.textContent="Couldn't check. Try again.";return;}
        if(!firebase.auth().currentUser.emailVerified){msg.textContent="Not confirmed yet. Open the link in the email first.";return;}
        onUser(firebase.auth().currentUser);
      }}),
      h("button",{class:"btn quiet",text:"Sign out",onclick:function(){firebase.auth().signOut();}}))));
}
var shown=null;
function onUser(u){
  user=u||null;var k=u?u.uid+":"+u.emailVerified:"";if(k===shown)return;shown=k;
  data={};errors={};render();if(u&&u.emailVerified)load();
}
(function start(){
  firebase.initializeApp(window.PIXORA_CLOUD);
  fdb=firebase.firestore();
  if(window.PIXORA_EMULATOR){fdb.useEmulator("127.0.0.1",window.PIXORA_EMULATOR.db);firebase.auth().useEmulator("http://127.0.0.1:"+window.PIXORA_EMULATOR.auth,{disableWarnings:true});}
  /* Fires on sign-in, sign-out and token refresh, so confirming the email shows the numbers straight away. */
  firebase.auth().onIdTokenChanged(onUser);
})();
