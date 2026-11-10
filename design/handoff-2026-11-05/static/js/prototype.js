/* Prototype behaviour only: theme, lanes, join steps, tabs, skip link. Production behaviour is specified in CODING_AGENT_SPEC.md. */
(function(){
var root=document.querySelector('.d1');if(!root)return;
var saved=null;try{saved=localStorage.getItem('dog.theme')}catch(e){}
var theme=saved||(window.matchMedia&&matchMedia('(prefers-color-scheme: light)').matches?'light':'dark');
root.setAttribute('data-theme',theme);
var ft=document.querySelector('.ft');
if(ft){var b=document.createElement('button');b.className='btn s';b.type='button';b.style.marginTop='12px';b.textContent='Switch to '+(theme==='dark'?'light':'dark')+' theme';
b.onclick=function(){var n=root.getAttribute('data-theme')==='dark'?'light':'dark';root.setAttribute('data-theme',n);try{localStorage.setItem('dog.theme',n)}catch(e){}b.textContent='Switch to '+(n==='dark'?'light':'dark')+' theme'};ft.appendChild(b)}
function q(s,r){return Array.prototype.slice.call((r||document).querySelectorAll(s))}
function lane(w){q('[data-lane]').forEach(function(e){e.hidden=e.getAttribute('data-lane')!==w});q('[data-act=setPeople],[data-act=setAgents]').forEach(function(t){t.classList.toggle('on',(t.getAttribute('data-act')==='setPeople')===(w==='people'))})}
var join={path:'',code:false};
function showJoin(){q('[data-join]').forEach(function(e){var k=e.getAttribute('data-join');e.hidden=!(k==='any'?!!join.path:k==='new'?join.path==='new':k==='back'?join.path==='back':join.code&&join.path==='new')});
q('[data-act=pathNew],[data-act=pathBack]').forEach(function(t){t.classList.toggle('on',t.getAttribute('data-act')==='pathNew'?join.path==='new':join.path==='back')})}
function tab(g,id){q('[data-tab-group='+g+']').forEach(function(t){var on=t.getAttribute('data-tab')===id;t.classList.toggle('on',on);t.setAttribute('aria-selected',on);t.tabIndex=on?0:-1});q('[data-panel-group='+g+']').forEach(function(p){p.hidden=p.getAttribute('data-panel')!==id})}
document.addEventListener('click',function(e){
var a=e.target.closest('[data-act]');
if(a){var n=a.getAttribute('data-act');
if(n==='skipTo'){e.preventDefault();var m=document.getElementById('main')||document.querySelector('h1');if(m){m.setAttribute('tabindex','-1');m.focus()}}
if(n==='setPeople')lane('people');if(n==='setAgents')lane('agents');
if(n==='pathNew'){join.path='new';join.code=false;showJoin()}
if(n==='pathBack'){join.path='back';join.code=false;showJoin()}
if(n==='getCode'){join.code=true;showJoin()}}
var t=e.target.closest('[data-tab-group]');if(t)tab(t.getAttribute('data-tab-group'),t.getAttribute('data-tab'))});
document.addEventListener('keydown',function(e){var t=e.target.closest&&e.target.closest('[data-tab-group]');if(!t)return;
var g=t.getAttribute('data-tab-group'),list=q('[data-tab-group='+g+']'),i=list.indexOf(t),n=-1;
if(e.key==='ArrowRight')n=(i+1)%list.length;else if(e.key==='ArrowLeft')n=(i-1+list.length)%list.length;else if(e.key==='Home')n=0;else if(e.key==='End')n=list.length-1;
if(n>=0){e.preventDefault();list[n].focus();tab(g,list[n].getAttribute('data-tab'))}});
q('[role=tab][data-tab]').forEach(function(t){t.tabIndex=t.classList.contains('on')?0:-1});
showJoin();
})();
