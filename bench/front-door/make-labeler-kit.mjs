#!/usr/bin/env node
// E20-R2 audit: turns validation-sheet.json into what the labeler and the agent get.
// Usage: make-labeler-kit.mjs <validation-sheet.json> <out dir> [--expect 300]
// Writes label-sheet.csv and labeler.html, and shows the sheet's hash, which `bind` asks for. Refuses a sheet that holds anything that could
// unblind it. The page is one file, makes no request, and writes page text only as text.
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const [sheetFile, out] = process.argv.slice(2);
const expectAt = process.argv.indexOf("--expect");
const expected = expectAt > 0 ? Number(process.argv[expectAt + 1]) : null;
if (!sheetFile || !out) { console.error("Usage: make-labeler-kit.mjs <validation-sheet.json> <out dir> [--expect 300]"); process.exit(2); }

const bytes = readFileSync(sheetFile);
const sheet = JSON.parse(bytes.toString("utf8"));
const sheetSha256 = createHash("sha256").update(bytes).digest("hex");
const ROW = new Set(["id", "status", "headerNames", "values", "cookieNames", "excerpt", "pageExcerpt"]);
const PAGE = new Set(["title", "text", "noscript", "chars", "scripts", "forms", "links", "metaRefresh"]);
const refuse = (why) => { console.error(`Refused: ${why}`); process.exit(3); };
if (!Array.isArray(sheet) || !sheet.length) refuse("the sheet is empty.");
if (expected && sheet.length !== expected) refuse(`the sheet has ${sheet.length} rows, expected ${expected}.`);
for (const r of sheet) {
  const extra = Object.keys(r).filter((k) => !ROW.has(k));
  if (extra.length) refuse(`row ${r.id} has unexpected fields: ${extra.join(", ")}.`);
  const inner = Object.keys(r.pageExcerpt ?? {}).filter((k) => !PAGE.has(k));
  if (inner.length) refuse(`row ${r.id} has unexpected page fields: ${inner.join(", ")}.`);
}
if (new Set(sheet.map((r) => r.id)).size !== sheet.length) refuse("two rows share an id.");

const cell = (v) => `"${String(v ?? "").replace(/"/g, '""')}"`;
const edge = (r) => Object.entries(r.values ?? {}).map(([k, v]) => `${k}: ${v}`).join("; ");
const csv = ["id,http_status,headers,cookies,title,visible_text,noscript,error_excerpt,scripts,forms,links,your_label", ...sheet.map((r) => {
  const p = r.pageExcerpt ?? {};
  return [r.id, r.status, cell(edge(r)), cell((r.cookieNames ?? []).join(" ")), cell(p.title), cell(p.text), cell(p.noscript), cell(r.excerpt), p.scripts ?? "", p.forms ?? "", p.links ?? "", ""].join(",");
})].join("\n") + "\n";

// Escaped so no page text can close the script block.
const data = JSON.stringify(sheet).replace(/</g, "\\u003c").replace(/\u2028|\u2029/g, " ");
const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>E20-R2 audit</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'">
<style>
:root{--bg:#fff;--fg:#14171a;--mute:#5b6570;--line:#dfe3e7;--acc:#1f5fbf}
@media (prefers-color-scheme:dark){:root{--bg:#14171a;--fg:#e8ebee;--mute:#9aa4ae;--line:#2c3238;--acc:#6ea4ee}}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,sans-serif}
main{max-width:860px;margin:0 auto;padding:16px}
h1{font-size:20px;margin:0 0 4px}h2{font-size:17px;margin:16px 0 4px}
.m{color:var(--mute);font-size:14px;margin:4px 0}
pre{white-space:pre-wrap;overflow-wrap:anywhere;border:1px solid var(--line);border-radius:6px;padding:10px;font:13px/1.45 ui-monospace,monospace;max-height:320px;overflow:auto;margin:4px 0}
.row{display:flex;flex-wrap:wrap;gap:8px;margin:12px 0}
button{font:inherit;padding:8px 12px;border:1px solid var(--line);border-radius:6px;background:transparent;color:inherit;cursor:pointer}
button.on{background:var(--acc);border-color:var(--acc);color:var(--bg)}
</style></head><body><main>
<h1>E20-R2 audit</h1>
<p class="m">Label what the response is from this evidence alone. Don't visit any site. Keys: 1 to 5 pick a label, arrows move. Your work saves in this browser.</p>
<p class="m">Sheet ${sheetSha256}. Send this hash back with your labels.</p>
<p class="m" id="pos"></p>
<div class="row" id="choices"></div>
<div id="card"></div>
<div class="row"><button id="prev">Back</button><button id="next">Next</button><button id="todo">Next unlabeled</button><button id="save">Download labels.csv</button></div>
<p class="m" id="note"></p>
</main><script>
const S=${data};
const K="e20r2-audit-"+S.length;
const C=[["page","A real page"],["challenge","Bot check that can be passed (JS, CAPTCHA, wait)"],["block","Refused by a bot or firewall rule"],["error","Site or server error, not about bots"],["unsure","Can't tell"]];
let L={},i=0;
try{L=JSON.parse(localStorage.getItem(K)||"{}");i=Math.min(+localStorage.getItem(K+"-i")||0,S.length-1)}catch(e){}
const $=(id)=>document.getElementById(id);
const el=(t,x,p)=>{const e=document.createElement(t);if(x!=null)e.textContent=x;if(p)p.appendChild(e);return e};
const store=()=>{try{localStorage.setItem(K,JSON.stringify(L));localStorage.setItem(K+"-i",i)}catch(e){}};
const block=(title,text,c)=>{if(!text)return;el("h2",title,c);el("pre",text,c)};
function draw(){
  const s=S[i],c=$("card"),p=s.pageExcerpt||{};
  c.textContent="";
  $("pos").textContent="Row "+(i+1)+" of "+S.length+", "+Object.keys(L).length+" labeled";
  el("h2","HTTP "+s.status,c);
  el("p",(p.chars||0)+" characters, "+(p.scripts||0)+" scripts, "+(p.forms||0)+" forms, "+(p.links||0)+" links"+(p.metaRefresh?", meta refresh":""),c).className="m";
  block("Title",p.title,c);block("Visible text",p.text,c);block("Noscript",p.noscript,c);block("Error body",s.excerpt,c);
  block("Selected headers",Object.entries(s.values||{}).map(function(e){return e[0]+": "+e[1]}).join("\\n"),c);
  block("Header names",(s.headerNames||[]).join(" "),c);block("Cookie names",(s.cookieNames||[]).join(" "),c);
  if(!p.title&&!p.text&&!p.noscript&&!s.excerpt)el("p","No text is stored for this response.",c).className="m";
  const b=$("choices");b.textContent="";
  C.forEach(function(o,k){const x=el("button",(k+1)+" "+o[1],b);if(L[s.id]===o[0])x.className="on";x.onclick=function(){pick(o[0])}});
  $("note").textContent="";
}
function pick(v){L[S[i].id]=v;if(i<S.length-1)i++;store();draw()}
function move(d){i=Math.max(0,Math.min(S.length-1,i+d));store();draw()}
$("prev").onclick=function(){move(-1)};
$("next").onclick=function(){move(1)};
$("todo").onclick=function(){const k=S.findIndex(function(s){return !L[s.id]});if(k>=0){i=k;store();draw()}};
$("save").onclick=function(){
  const left=S.filter(function(s){return !L[s.id]}).length;
  const blob=new Blob(["id,label\\n"+S.filter(function(s){return L[s.id]}).map(function(s){return s.id+","+L[s.id]}).join("\\n")+"\\n"],{type:"text/csv"});
  const a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download="labels.csv";a.click();
  $("note").textContent=left?left+" rows still have no label. The score refuses an incomplete file.":"All rows labeled. Send labels.csv back.";
};
document.addEventListener("keydown",function(e){
  if(e.key>="1"&&e.key<="5")pick(C[+e.key-1][0]);
  if(e.key==="ArrowRight")move(1);
  if(e.key==="ArrowLeft")move(-1);
});
draw();
</script></body></html>
`;
mkdirSync(out, { recursive: true, mode: 0o700 });
writeFileSync(join(out, "label-sheet.csv"), csv, { mode: 0o600 });
writeFileSync(join(out, "labeler.html"), html, { mode: 0o600 });
console.log(JSON.stringify({ rows: sheet.length, sheetSha256, withText: sheet.filter((r) => r.excerpt || r.pageExcerpt?.text || r.pageExcerpt?.title).length, out }));
