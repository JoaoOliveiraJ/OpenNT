//! O CSS e os scripts do site, num lugar só. Cada página leva o CSS inline
//! (as páginas abrem sozinhas, direto do disco, sem nenhum recurso externo)
//! e só os scripts de que precisa. Sem JavaScript, nada some: os filtros
//! ficam escondidos e todas as linhas aparecem.

/// O sistema de design: fontes do sistema, escala de tipos e de espaços,
/// cores em variáveis (tema claro e escuro por `prefers-color-scheme`), e
/// os componentes (cabeçalho, trilha, números, barras, selos de estado,
/// listas, tabelas e filtros).
pub const CSS: &str = r#"
:root{--sans:system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
--mono:ui-monospace,SFMono-Regular,"Cascadia Mono",Consolas,"Liberation Mono",monospace;
--fs-xs:12px;--fs-sm:14px;--fs-md:18px;--fs-lg:21px;--fs-xl:25px;--fs-2xl:clamp(30px,4.6vw,40px);
--sp-1:4px;--sp-2:8px;--sp-3:12px;--sp-4:16px;--sp-5:24px;--sp-6:32px;--sp-7:56px;
--r-sm:6px;--r:10px;--r-lg:14px;--head-h:57px;
color-scheme:light;--bg:#f6f7f9;--surface:#fff;--surface-2:#f0f2f5;--hover:#f6f8fb;--border:#dde1e7;--border-strong:#c4cad3;
--text:#16181d;--text-2:#434a56;--muted:#5b6371;--accent:#1d5fc2;--accent-soft:#e8f0fc;--focus:#1d5fc2;
--brand:linear-gradient(135deg,#1c5cab,#6250d6);--ok:#0ca30c;--ok-text:#106b21;--ok-soft:#e5f4e8;--warn:#f2a50c;
--warn-text:#87570a;--warn-soft:#fdf3d8;--neutral:#7d8592;--neutral-soft:#edf0f3;--bad-text:#b42318;--bad-soft:#fdecea;
--bar:#2a78d6;--track:#e3e7ec}
@media (prefers-color-scheme:dark){:root{color-scheme:dark;--bg:#0e1015;--surface:#161a21;--surface-2:#1e232c;
--hover:#1b2029;--border:#2b313c;--border-strong:#3c4451;--text:#eceef2;--text-2:#c3c8d1;--muted:#9aa2af;--accent:#7db2ff;
--accent-soft:#18263b;--focus:#7db2ff;--brand:linear-gradient(135deg,#2a6fd0,#7a6cf0);--ok:#2fbf4a;--ok-text:#6bd685;
--ok-soft:#14281b;--warn:#f5b52e;--warn-text:#f2c766;--warn-soft:#2c2412;--neutral:#7a8392;--neutral-soft:#232933;
--bad-text:#ff8f85;--bad-soft:#3a1d1b;--bar:#3d8bea;--track:#29303b}}
*,*::before,*::after{box-sizing:border-box}
[hidden]{display:none!important}
html{-webkit-text-size-adjust:100%;scroll-padding-top:12px}
html:not(.js) .js-only{display:none!important}
html.js .no-js{display:none!important}
body{margin:0;background:var(--bg);color:var(--text);font:16px/1.55 var(--sans)}
a{color:var(--accent);text-decoration-thickness:1px;text-underline-offset:2px}
a:hover{text-decoration-thickness:2px}
:focus-visible{outline:2px solid var(--focus);outline-offset:2px;border-radius:4px}
main:focus{outline:none}
.sr-only{position:absolute!important;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}
.skip{position:absolute;left:8px;top:-60px;z-index:30;background:var(--surface);color:var(--text);padding:8px 14px;
border:2px solid var(--focus);border-radius:var(--r)}
.skip:focus{top:8px}
.wrap{max-width:1120px;margin:0 auto;padding:0 16px}
header.site{background:var(--surface);border-bottom:1px solid var(--border)}
header.site .bar{display:flex;flex-wrap:wrap;align-items:center;gap:6px 24px;padding-top:10px;padding-bottom:10px}
.brand{display:inline-flex;align-items:center;gap:10px;color:var(--text);text-decoration:none;font-weight:700;font-size:17px}
.brand .tag{font-weight:500;font-size:12px;color:var(--muted);border:1px solid var(--border);border-radius:999px;padding:0 8px}
.logo{width:26px;height:26px;border-radius:7px;background:var(--brand);display:grid;place-items:center;flex:none}
.logo svg{width:15px;height:15px}
.nav ul{list-style:none;margin:0;padding:0;display:flex;flex-wrap:wrap;gap:2px}
.nav a{display:block;padding:6px 10px;border-radius:var(--r-sm);color:var(--text-2);text-decoration:none;font-size:15px}
.nav a:hover{background:var(--surface-2);color:var(--text)}
.nav a[aria-current]{background:var(--accent-soft);color:var(--text);font-weight:650}
.nav .long{display:none}
@media (min-width:720px){html{scroll-padding-top:calc(var(--head-h) + 12px)}.wrap{padding:0 24px}
header.site{position:sticky;top:0;z-index:20}header.site .bar{height:56px;padding-top:0;padding-bottom:0;flex-wrap:nowrap}
.nav{margin-left:auto}}
@media (min-width:1080px){.nav .long{display:inline}}
main{padding-bottom:var(--sp-7)}
.crumbs{margin:var(--sp-5) 0 0;font-size:var(--fs-sm);color:var(--muted)}
.crumbs ol{list-style:none;margin:0;padding:0;display:flex;flex-wrap:wrap;gap:2px 6px}
.crumbs li+li::before{content:"/";margin-right:6px;color:var(--border-strong)}
.crumbs a{color:var(--muted)}
.crumbs [aria-current]{color:var(--text-2)}
.page-head{padding:var(--sp-3) 0 0}
.page-head h1{font-size:var(--fs-2xl);line-height:1.12;letter-spacing:-.02em;margin:var(--sp-2) 0 var(--sp-3)}
.page-head h1 .muted{font-weight:500}
.lead{font-size:var(--fs-md);line-height:1.45;color:var(--text);max-width:62ch;margin:0 0 var(--sp-3)}
.page-head .sub{color:var(--text-2);max-width:76ch}
.home-head{padding-top:var(--sp-6)}
.home-head h1{font-size:clamp(36px,6vw,52px);margin-top:0}
.home-head .lead{font-size:23px;font-weight:550;letter-spacing:-.01em}
.pills{display:flex;flex-wrap:wrap;gap:6px;margin:0 0 var(--sp-3);padding:0;list-style:none}
.pills li{font-size:var(--fs-xs);font-weight:600;color:var(--text-2);background:var(--surface);border:1px solid var(--border);
border-radius:999px;padding:2px 10px}
h2{font-size:var(--fs-xl);line-height:1.25;letter-spacing:-.01em;margin:0 0 var(--sp-2)}
h3{font-size:var(--fs-md);line-height:1.3;margin:var(--sp-5) 0 var(--sp-2)}
h4{font-size:16px;line-height:1.35;margin:0}
p{margin:0 0 var(--sp-3);max-width:76ch}
.block{margin-top:var(--sp-7)}
.intro{color:var(--text-2);max-width:72ch}
.muted{color:var(--muted)}
.small{font-size:var(--fs-sm)}
.count-badge{font-size:var(--fs-sm);font-weight:600;color:var(--muted);margin-left:6px}
code{font-family:var(--mono);font-size:.86em;background:var(--surface-2);padding:1px 5px;border-radius:5px;overflow-wrap:anywhere}
pre{font:13px/1.5 var(--mono);background:var(--surface-2);border:1px solid var(--border);border-radius:var(--r);padding:10px 12px;
overflow-x:auto;margin:0 0 var(--sp-3);white-space:pre}
pre code{background:none;padding:0;font-size:inherit;overflow-wrap:normal}
.path{overflow-wrap:normal}
.grid{display:grid;gap:var(--sp-3);grid-template-columns:repeat(auto-fit,minmax(min(300px,100%),1fr));margin:var(--sp-4) 0}
.grid.two{grid-template-columns:repeat(auto-fit,minmax(min(420px,100%),1fr))}
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--r-lg);padding:var(--sp-4) 18px;min-width:0}
.card>:last-child{margin-bottom:0}
.card h3{margin-top:0}
.callout{background:var(--surface-2);border-radius:var(--r-lg);padding:var(--sp-4) 18px}
.callout>:last-child{margin-bottom:0}
.callout h3{margin-top:0}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(230px,100%),1fr));gap:var(--sp-3);margin:var(--sp-5) 0 0}
.stat{background:var(--surface);border:1px solid var(--border);border-radius:var(--r-lg);padding:var(--sp-4);display:flex;
flex-direction:column;gap:6px;min-width:0;color:inherit;text-decoration:none}
a.stat:hover{border-color:var(--border-strong);background:var(--hover)}
a.stat:hover .stat-label{color:var(--accent);text-decoration:underline}
.stat-label{margin:0;font-size:var(--fs-sm);font-weight:600;color:var(--text-2)}
.stat-value{margin:0;font-size:30px;font-weight:700;line-height:1.1;letter-spacing:-.02em}
.stat-value .of{font-size:17px;font-weight:500;color:var(--muted);letter-spacing:0}
.stat-note{margin:0;font-size:13px;line-height:1.4;color:var(--muted)}
.meter{display:flex;gap:2px;height:8px;border-radius:999px;background:var(--track);overflow:hidden;min-width:48px}
.meter>span{display:block;height:100%;min-width:3px;border-radius:999px;background:var(--bar)}
.meter>.ok{background:var(--ok)}.meter>.part{background:var(--warn)}.meter>.phase-now{background:var(--warn)}
.meter.sm{height:6px}
.meter.steps{gap:3px;background:none}.meter.steps>span{flex:1;min-width:0;background:var(--track)}
.meter.steps>.ok{background:var(--ok)}.meter.steps>.part{background:var(--warn)}
.ic{width:15px;height:15px;flex:none;display:block}
.f-good{fill:var(--ok)}.f-warning{fill:var(--warn)}
.k-white{fill:none;stroke:#fff;stroke-width:1.9;stroke-linecap:round;stroke-linejoin:round}
.k-warning{fill:none;stroke:var(--warn);stroke-width:1.6}
.k-neutral{fill:none;stroke:var(--neutral);stroke-width:1.6}
.dash{stroke-dasharray:2.2 2.2}
.chip{display:inline-flex;align-items:center;gap:6px;font-size:13px;font-weight:600;line-height:1.3;white-space:nowrap;
padding:2px 10px 2px 6px;border-radius:999px;background:var(--neutral-soft);color:var(--text)}
.chip.ok{background:var(--ok-soft)}.chip.part{background:var(--warn-soft)}
.chip.bad{background:var(--bad-soft);color:var(--bad-text)}
.chip.next{background:var(--accent-soft)}
.ico{width:20px;height:20px;fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}
.ico-tile{width:36px;height:36px;border-radius:var(--r);flex:none;display:grid;place-items:center;color:var(--accent);
background:var(--accent-soft)}
.ico-tile.good{color:var(--ok-text);background:var(--ok-soft)}
.ico-tile.dim{color:var(--muted);background:var(--neutral-soft)}
.ico-tile.sm{width:30px;height:30px;border-radius:8px}.ico-tile.sm .ico{width:17px;height:17px}
.legend{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(240px,100%),1fr));gap:var(--sp-3) var(--sp-5);margin:var(--sp-3) 0}
.legend>div{font-size:var(--fs-sm);color:var(--text-2)}
.legend .chip,.legend .ms{margin-bottom:4px}
.legend p{margin:0}
.steps-list{margin:var(--sp-2) 0 var(--sp-3);padding-left:22px}
.steps-list li{margin:4px 0}
.levels{list-style:none;margin:var(--sp-3) 0 0;padding:0;display:grid;gap:var(--sp-3);
grid-template-columns:repeat(auto-fit,minmax(min(240px,100%),1fr));counter-reset:lvl}
.levels li{position:relative;padding:var(--sp-3) var(--sp-4) var(--sp-3) 46px;background:var(--surface);border:1px solid var(--border);
border-radius:var(--r);font-size:var(--fs-sm);color:var(--text-2);counter-increment:lvl}
.levels li::before{content:counter(lvl);position:absolute;left:14px;top:12px;width:22px;height:22px;border-radius:50%;
background:var(--accent-soft);color:var(--accent);font-weight:700;font-size:13px;display:grid;place-items:center}
.levels strong{display:block;color:var(--text);font-size:15px}
.items{background:var(--surface);border:1px solid var(--border);border-radius:var(--r-lg);overflow:hidden;margin:var(--sp-3) 0 0}
.item{display:grid;grid-template-columns:36px minmax(0,1fr);column-gap:14px;padding:var(--sp-4) 18px;border-top:1px solid var(--border);
margin-top:-1px}
.item>.ico-tile{grid-row:1 / span 6}
.item>:not(.ico-tile){grid-column:2}
.item-head{display:flex;flex-wrap:wrap;align-items:center;gap:4px 10px}
.item-head h3,.item-head h4{margin:0;font-size:16.5px;line-height:1.35}
.item-desc{margin:4px 0 0;color:var(--text-2);max-width:80ch}
.meta{display:grid;grid-template-columns:max-content minmax(0,1fr);gap:4px 14px;margin:10px 0 0;font-size:var(--fs-sm)}
.meta dt{color:var(--muted)}
.meta dd{margin:0;min-width:0}
.meta dd code{display:inline-block;margin:0 4px 3px 0}
.meta pre{margin:0;font-size:12.5px}
.verified{color:var(--ok-text);font-weight:600}
.unverified{color:var(--muted)}
.warn{color:var(--bad-text);font-size:13px}
.notes{margin:10px 0 0;font-size:var(--fs-sm);color:var(--text-2);max-width:88ch}
details.notes>summary{cursor:pointer;list-style:none}
details.notes>summary::-webkit-details-marker{display:none}
details.notes>summary:hover .toggle{text-decoration:underline}
details.notes p{margin:6px 0 0;max-width:88ch}
.toggle{color:var(--accent);font-weight:600;white-space:nowrap}
.toggle .less,details[open]>summary .toggle .more,details[open]>summary .ell{display:none}
details[open]>summary .toggle .less{display:inline}
.refs{list-style:none;margin:0;padding:0;display:flex;flex-wrap:wrap;gap:4px 6px}
.refs a{display:inline-flex;align-items:center;gap:5px;font-size:13px;padding:1px 9px 1px 5px;border-radius:999px;
background:var(--surface-2);text-decoration:none;color:var(--text)}
.refs a:hover{background:var(--accent-soft)}
.refs .ic{width:13px;height:13px}
.table-wrap{overflow-x:auto;background:var(--surface);border:1px solid var(--border);border-radius:var(--r-lg);margin:var(--sp-3) 0}
table{border-collapse:separate;border-spacing:0;width:100%;font-size:var(--fs-sm)}
caption{text-align:left}
th,td{padding:9px 12px;text-align:left;vertical-align:top;border-bottom:1px solid var(--border)}
thead th{font-size:var(--fs-xs);font-weight:650;color:var(--muted);background:var(--surface-2);white-space:nowrap}
thead th:first-child{border-top-left-radius:var(--r-lg)}thead th:last-child{border-top-right-radius:var(--r-lg)}
tbody tr:last-child>*{border-bottom:0}
tbody tr:hover>*{background:var(--hover)}
tbody th{font-weight:600}
tfoot th,tfoot td{border-top:1px solid var(--border-strong);border-bottom:0;font-weight:650}
td.num,th.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
td.bar{width:22%;min-width:100px;vertical-align:middle}
td.wrap-code code{overflow-wrap:break-word}
.rowgroup th{background:var(--surface-2);font-size:13px;color:var(--text-2)}
@media (min-width:720px){.table-wrap.sticky{overflow:visible}
.table-wrap.sticky thead th{position:sticky;top:var(--head-h);z-index:2}}
.yes{color:var(--ok-text);font-weight:600}
.no{color:var(--muted)}
.mark{display:inline-flex;align-items:center;gap:6px;white-space:nowrap}
.mark::before{content:"";width:9px;height:9px;border-radius:50%;flex:none;box-sizing:border-box}
.mark.yes::before{background:var(--ok)}.mark.no::before{border:1.5px solid var(--neutral)}
.ms{display:inline-flex;align-items:center;gap:6px;font-size:13px;font-weight:600;white-space:nowrap}
.ms::before{content:"";width:11px;height:11px;border-radius:50%;flex:none;box-sizing:border-box}
.ms.codigo::before{background:var(--bar)}
.ms.parcial::before{border:1.6px solid var(--warn);background:linear-gradient(90deg,transparent 50%,var(--warn) 50%)}
.ms.pendente::before{border:1.6px solid var(--neutral)}
.ms.fora::before{border:1.6px dashed var(--neutral)}
.note{display:block;font-size:13px;color:var(--muted);margin-top:2px}
.filters{display:flex;flex-wrap:wrap;align-items:center;gap:10px 14px;margin:var(--sp-4) 0 var(--sp-3)}
.search{position:relative;flex:1 1 260px;max-width:440px}
.search .ico{position:absolute;left:11px;top:50%;transform:translateY(-50%);width:18px;height:18px;color:var(--muted);pointer-events:none}
.search input{width:100%;font:inherit;font-size:15px;color:var(--text);background:var(--surface);border:1px solid var(--border-strong);
border-radius:var(--r);padding:8px 12px 8px 38px}
.search input:focus{outline:2px solid var(--focus);outline-offset:1px}
.toggles{display:inline-flex;flex-wrap:wrap;gap:3px;padding:3px;background:var(--surface-2);border:1px solid var(--border);border-radius:var(--r)}
.toggles button{font:inherit;font-size:var(--fs-sm);display:inline-flex;align-items:center;gap:6px;border:0;background:none;
color:var(--text-2);padding:5px 10px;border-radius:7px;cursor:pointer}
.toggles button:hover{color:var(--text)}
.toggles button[aria-pressed="true"]{background:var(--surface);color:var(--text);font-weight:600;box-shadow:0 0 0 1px var(--border-strong)}
.toggles .n{font-size:var(--fs-xs);color:var(--muted);font-variant-numeric:tabular-nums}
.count{margin:0 0 0 auto;font-size:var(--fs-sm);color:var(--muted)}
.empty{padding:var(--sp-4);border:1px dashed var(--border-strong);border-radius:var(--r-lg);color:var(--muted)}
.linkish{font:inherit;color:var(--accent);background:none;border:0;padding:0;text-decoration:underline;cursor:pointer}
.category{margin-top:var(--sp-6)}
.category-head{display:flex;flex-wrap:wrap;align-items:center;gap:4px 12px}
.searchbox .hint{margin:10px 0 0}
.category-head h3{margin:0;font-size:var(--fs-lg)}
.category-head .counts{font-size:var(--fs-sm);color:var(--muted);margin:0}
.category>.intro{margin:6px 0 0;font-size:15px}
.jump{display:flex;flex-wrap:wrap;gap:6px;margin:var(--sp-3) 0 0;padding:0;list-style:none}
.jump a{display:inline-flex;gap:6px;align-items:baseline;font-size:var(--fs-sm);padding:4px 11px;border-radius:999px;
background:var(--surface);border:1px solid var(--border);text-decoration:none;color:var(--text)}
.jump a:hover{border-color:var(--border-strong);background:var(--hover)}
.jump a[aria-current]{background:var(--accent-soft);border-color:transparent;font-weight:650}
.jump .n{font-size:var(--fs-xs);color:var(--muted);font-variant-numeric:tabular-nums}
.milestone{display:grid;gap:10px;margin:var(--sp-5) 0 0;padding:var(--sp-4) 18px;background:var(--surface);border:1px solid var(--border);
border-left:4px solid var(--warn);border-radius:var(--r-lg)}
.now-row{display:flex;flex-wrap:wrap;align-items:baseline;gap:4px 10px}
.now-label{flex:none;min-width:5.5em;font-size:var(--fs-xs);font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
.now-row ul{list-style:none;margin:0;padding:0;display:flex;flex-wrap:wrap;gap:4px 18px}
.phases{list-style:none;margin:var(--sp-4) 0 0;padding:0}
.phase{position:relative;display:grid;grid-template-columns:32px minmax(0,1fr);column-gap:14px;padding-bottom:var(--sp-4)}
.phase:not(:last-child)::before{content:"";position:absolute;left:15px;top:34px;bottom:2px;width:2px;border-radius:1px;background:var(--border)}
.phase.done:not(:last-child)::before{background:var(--ok)}
.phase-dot{width:32px;height:32px;border-radius:50%;display:grid;place-items:center;font-weight:700;font-size:14px;
background:var(--surface);border:2px solid var(--border-strong);color:var(--muted)}
.phase-dot svg{width:16px;height:16px;fill:none;stroke:#fff;stroke-width:2.6;stroke-linecap:round;stroke-linejoin:round}
.phase.done .phase-dot{background:var(--ok);border-color:var(--ok)}
.phase.now .phase-dot{border-color:var(--warn);color:var(--text);box-shadow:0 0 0 4px var(--warn-soft)}
.phase-body{min-width:0;padding-top:4px}
.phase.now .phase-body{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);padding:var(--sp-3) var(--sp-4);margin-top:-6px}
.phase-head{display:flex;flex-wrap:wrap;align-items:center;gap:4px 10px}
.phase-num{font-size:var(--fs-xs);font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
.phase-name{font-weight:650}
.phase-scope{margin:4px 0 0;font-size:15px;color:var(--text-2)}
.phase-comp{margin:4px 0 0;font-size:13px;color:var(--muted)}
.minis{display:grid;gap:var(--sp-3);grid-template-columns:repeat(auto-fill,minmax(min(320px,100%),1fr));margin:var(--sp-3) 0 0}
.mini{display:flex;gap:var(--sp-3);align-items:flex-start;background:var(--surface);border:1px solid var(--border);
border-radius:var(--r-lg);padding:14px var(--sp-4);min-width:0}
.mini h4 a{color:var(--text);text-decoration:none}
.mini h4 a:hover{color:var(--accent);text-decoration:underline}
.mini p{margin:2px 0 0;font-size:var(--fs-sm);color:var(--text-2)}
.mini .by{margin-top:6px;font-size:13px;color:var(--muted)}
.mini>div{min-width:0}
.links{display:grid;gap:var(--sp-3);grid-template-columns:repeat(auto-fit,minmax(min(250px,100%),1fr));margin:var(--sp-4) 0}
.links a{display:flex;flex-direction:column;gap:6px;padding:var(--sp-4);background:var(--surface);border:1px solid var(--border);
border-radius:var(--r-lg);text-decoration:none;color:var(--text)}
.links a:hover{border-color:var(--border-strong);background:var(--hover)}
.links .t{display:flex;align-items:center;gap:10px;font-weight:650;font-size:17px}
.links a:hover .t span:last-child{color:var(--accent);text-decoration:underline}
.links .big{font-size:22px;font-weight:700;letter-spacing:-.01em}
.links .big small{font-size:14px;font-weight:500;color:var(--muted)}
.links p{margin:0;font-size:var(--fs-sm);color:var(--text-2)}
.glossary{display:grid;gap:var(--sp-3);grid-template-columns:repeat(auto-fit,minmax(min(300px,100%),1fr));margin:var(--sp-4) 0}
.glossary>div{background:var(--surface);border:1px solid var(--border);border-radius:var(--r-lg);padding:14px var(--sp-4)}
.glossary dt{font-weight:650;display:flex;gap:10px;align-items:center}
.glossary dd{margin:6px 0 0;font-size:15px;color:var(--text-2)}
.badges{display:flex;flex-wrap:wrap;gap:8px;margin:var(--sp-3) 0}
.badges svg{display:block;max-width:100%;height:auto}
details.sub{background:var(--surface);border:1px solid var(--border);border-radius:var(--r-lg);margin:var(--sp-2) 0}
details.sub>summary{list-style:none;cursor:pointer;display:grid;grid-template-columns:30px minmax(0,1fr) minmax(90px,180px) 9em 14px;
gap:6px 14px;align-items:center;padding:12px var(--sp-4);border-radius:var(--r-lg)}
details.sub>summary::-webkit-details-marker{display:none}
details.sub>summary:hover{background:var(--hover)}
details.sub[open]>summary{border-bottom:1px solid var(--border);border-radius:var(--r-lg) var(--r-lg) 0 0}
.sname{font-weight:650;line-height:1.3}
.sname code{font-weight:400;font-size:12px;margin-left:6px}
.sdesc{font-size:13px;color:var(--muted);line-height:1.35}
.snums{font-size:var(--fs-sm);color:var(--text-2);text-align:right;font-variant-numeric:tabular-nums}
details.sub .inner{padding:var(--sp-3) var(--sp-4) var(--sp-4)}
details.sub .table-wrap{margin-bottom:0}
.chev{width:14px;height:14px;fill:none;stroke:var(--muted);stroke-width:2.2;transition:transform .15s}
details[open]>summary .chev{transform:rotate(90deg)}
@media (max-width:700px){details.sub>summary{grid-template-columns:30px minmax(0,1fr) 14px}
details.sub>summary .meter,details.sub>summary .snums{grid-column:2 / 3}
details.sub>summary .snums{text-align:left}details.sub>summary .chev{grid-row:1;grid-column:3}}
.area{margin-top:var(--sp-6)}
.area>h3{margin:0 0 4px;font-size:var(--fs-lg)}
.area>h3 .muted{font-size:var(--fs-sm);font-weight:500}
.area>p{font-size:var(--fs-sm);color:var(--muted)}
.prefix-cards{display:grid;gap:var(--sp-3);grid-template-columns:repeat(auto-fill,minmax(min(330px,100%),1fr));margin:var(--sp-4) 0}
.prefix-card{display:flex;flex-direction:column;gap:8px}
.prefix-card .top{display:flex;align-items:center;gap:var(--sp-3)}
.prefix-card .top h3{margin:0;font-size:17px}
.prefix-card .top h3 a{text-decoration:none}
.prefix-card .top .short{display:block;font-size:13px;color:var(--muted)}
.prefix-card p{margin:0;font-size:var(--fs-sm);color:var(--text-2)}
.prefix-card .nums{font-size:var(--fs-sm);color:var(--text-2);font-variant-numeric:tabular-nums;margin-top:auto}
.examples{font-size:13px;color:var(--muted)}
.examples code{font-size:12px}
.group-nav{display:flex;flex-wrap:wrap;justify-content:space-between;gap:10px;margin:var(--sp-5) 0}
.group-nav a{text-decoration:none;padding:8px 14px;border:1px solid var(--border);border-radius:var(--r);background:var(--surface)}
.group-nav a:hover{border-color:var(--border-strong);background:var(--hover)}
.searchbox{background:var(--surface);border:1px solid var(--border);border-radius:var(--r-lg);padding:var(--sp-4) 18px;margin:var(--sp-3) 0}
.searchbox .filters{margin:0}
.results{list-style:none;margin:var(--sp-3) 0 0;padding:0;border-top:1px solid var(--border)}
.results:empty{display:none}
.results li{display:flex;flex-wrap:wrap;gap:4px 14px;align-items:baseline;padding:8px 2px;border-bottom:1px solid var(--border);font-size:var(--fs-sm)}
.results li a{font-weight:600}
.results .grow{flex:1}
.extra-names{line-height:2}
footer.site{border-top:1px solid var(--border);background:var(--surface)}
footer.site .wrap{padding-top:var(--sp-5);padding-bottom:var(--sp-6);color:var(--muted);font-size:var(--fs-sm)}
footer.site nav ul{list-style:none;margin:0 0 var(--sp-3);padding:0;display:flex;flex-wrap:wrap;gap:4px 18px}
footer.site p{margin:0}
@media (max-width:560px){.item{grid-template-columns:minmax(0,1fr)}.item>.ico-tile{display:none}.item>:not(.ico-tile){grid-column:1}
.meta{grid-template-columns:minmax(0,1fr);gap:0}.meta dd{margin-bottom:8px}.count{margin-left:0;width:100%}
.stats{grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}.stat{padding:12px}.stat-value{font-size:24px}
.stat-value .of{font-size:15px}.home-head .lead{font-size:19px}}
@media (prefers-reduced-motion:reduce){*,*::before,*::after{transition:none!important;animation:none!important}}
@media print{header.site,.filters,.skip{display:none}body{background:#fff}}
"#;

/// Busca e filtro das listas longas, em JavaScript puro e sem dependências.
///
/// - A barra `[data-filter=ID]` filtra os `[data-item]` dentro de `#ID`:
///   o texto procura em `data-text` (ou no texto do item, sem acentos) e os
///   botões `[data-value]` comparam com `data-state`. O número de cada botão
///   acompanha a busca por texto.
/// - Um `[data-section]` some quando fica sem itens visíveis e um
///   `[data-group]` some quando todas as suas seções sumiram; um `<details>`
///   com resultados abre sozinho enquanto há busca por texto.
/// - `?q=texto` e `?estado=valor` no endereço já chegam aplicados.
/// - Um link `#id` para um item escondido pelo filtro limpa o filtro, abre
///   os `<details>` em volta e rola até ele.
pub const FILTER_SCRIPT: &str = r#"
(function(){
  var d=document;
  function all(s,r){return Array.prototype.slice.call((r||d).querySelectorAll(s));}
  function fold(s){s=(s||'').toLowerCase();return s.normalize?s.normalize('NFD').replace(/[̀-ͯ]/g,''):s;}
  var bar=d.querySelector('[data-filter]'),scope=bar&&d.getElementById(bar.getAttribute('data-filter'));
  var input,buttons=[],count,empty,items=[],sections=[],groups=[],state='';
  function apply(){
    var q=fold(input.value.trim()),active=!!(q||state),shown=0,hits=0,per={};
    items.forEach(function(item){
      var hit=!q||item._t.indexOf(q)>=0,s=item.getAttribute('data-state')||'';
      if(hit){hits++;per[s]=(per[s]||0)+1;}
      var show=hit&&(!state||s===state);
      item.hidden=!show;if(show)shown++;
    });
    buttons.forEach(function(b){var v=b.getAttribute('data-value'),n=b.querySelector('.n');if(n)n.textContent=v?(per[v]||0):hits;});
    sections.forEach(function(s){
      var any=all('[data-item]',s).some(function(i){return !i.hidden;});
      s.hidden=active&&!any;
      if(q&&any&&s.tagName==='DETAILS')s.open=true;
    });
    groups.forEach(function(g){g.hidden=active&&all('[data-section]',g).every(function(s){return s.hidden;});});
    if(count)count.textContent=shown+' '+(shown===1?count.getAttribute('data-one'):count.getAttribute('data-many'));
    if(empty)empty.hidden=shown>0;
  }
  function choose(value){
    state=value;
    buttons.forEach(function(b){b.setAttribute('aria-pressed',b.getAttribute('data-value')===value?'true':'false');});
    apply();
  }
  if(scope){
    input=bar.querySelector('input');buttons=all('button[data-value]',bar);count=bar.querySelector('.count');
    empty=d.getElementById('vazio');items=all('[data-item]',scope);sections=all('[data-section]',scope);groups=all('[data-group]',scope);
    items.forEach(function(item){item._t=fold(item.getAttribute('data-text')||item.textContent);});
    input.addEventListener('input',apply);
    buttons.forEach(function(b){b.addEventListener('click',function(){choose(b.getAttribute('data-value'));});});
    all('[data-clear]').forEach(function(b){b.addEventListener('click',function(){input.value='';choose('');input.focus();});});
    var params=window.URLSearchParams?new URLSearchParams(location.search):null,wanted=params&&params.get('estado');
    if(params&&params.get('q'))input.value=params.get('q');
    if(wanted&&buttons.some(function(b){return b.getAttribute('data-value')===wanted;}))choose(wanted);else apply();
  }
  function reveal(){
    var id=decodeURIComponent(location.hash.slice(1)),target=id&&d.getElementById(id);
    if(!target)return;
    var item=target.closest('[data-item]');
    if(item&&item.hidden&&input){input.value='';choose('');}
    for(var node=target;node;node=node.parentElement){if(node.tagName==='DETAILS')node.open=true;}
    target.scrollIntoView({block:'start'});
  }
  if(location.hash)reveal();
  window.addEventListener('hashchange',reveal);
})();
"#;

/// A busca por nome em `ntoskrnl.html`. Recebe `EXPORTS` (um token por
/// export: tipo, grupo e nome; veja `exports::search_data`), `GROUPS`
/// (arquivo e nome de cada grupo) e `LIMIT` (resultados mostrados).
/// `?q=nome` no endereço já chega pesquisado.
pub const SEARCH_SCRIPT: &str = r#"
(function(){
  var input=document.getElementById('busca'),out=document.getElementById('resultados'),info=document.getElementById('busca-info');
  var E=EXPORTS.split(' ');
  function rank(token,q){var l=token.slice(2).toLowerCase();return l===q?0:(l.indexOf(q)===0?1:2);}
  function run(){
    var q=input.value.trim().toLowerCase(),hits=[],html='';
    if(!q){out.innerHTML='';info.textContent='';return;}
    E.forEach(function(token){if(token.slice(2).toLowerCase().indexOf(q)>=0)hits.push(token);});
    hits.sort(function(a,b){return rank(a,q)-rank(b,q)||(a.slice(2)<b.slice(2)?-1:1);});
    hits.slice(0,LIMIT).forEach(function(token){
      var kind=token.charAt(0),group=GROUPS[token.charCodeAt(1)-97],name=token.slice(2),yes=kind==='a'||kind==='c';
      html+='<li><a href="ntoskrnl-'+group[0]+'.html#e-'+name+'"><code>'+name+'</code></a><span class="muted grow">'+
        (kind<'c'?'função':'variável')+' · grupo '+group[1]+'</span>'+
        (yes?'<span class="mark yes">o OpenNT exporta</span>':'<span class="mark no">falta no OpenNT</span>')+'</li>';
    });
    out.innerHTML=html;
    info.textContent=hits.length===0?'Nenhum export do ntoskrnl.exe contém esse texto.':
      (hits.length>LIMIT?'Mostrando '+LIMIT+' de '+hits.length+' resultados; continue digitando para refinar.':
      hits.length+(hits.length===1?' resultado.':' resultados.'));
  }
  input.addEventListener('input',run);
  var params=window.URLSearchParams?new URLSearchParams(location.search):null;
  if(params&&params.get('q'))input.value=params.get('q');
  if(input.value)run();
})();
"#;
