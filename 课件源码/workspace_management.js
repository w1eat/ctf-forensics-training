const MANAGER={page:'analysis',history:[],filesSelected:new Set(),jobsSelected:new Set(),filePage:0,jobPage:0,pageSize:20,deleting:false,lastJobState:'',supported:false};

function setSidebarCollapsed(collapsed,persist=true){
  const y=window.scrollY,sidebar=$('main-sidebar'),toggle=$('sidebar-toggle');
  document.body.classList.toggle('sidebar-collapsed',collapsed);sidebar.hidden=collapsed;sidebar.inert=collapsed;
  toggle.setAttribute('aria-expanded',String(!collapsed));toggle.setAttribute('aria-label',collapsed?'展开左侧导航':'收起左侧导航');toggle.querySelector('span').textContent=collapsed?'展开导航':'收起导航';
  $('sidebar-backdrop').hidden=collapsed||!matchMedia('(max-width:900px)').matches;
  if(persist)try{localStorage.setItem('forensics-sidebar-collapsed',collapsed?'1':'0')}catch{}
  requestAnimationFrame(()=>window.scrollTo({top:y,behavior:'instant'}));
}

function showWorkspacePage(page){
  MANAGER.page=['analysis','attachments','history'].includes(page)?page:'analysis';
  $$('[data-workspace-view]').forEach(e=>e.hidden=e.dataset.workspaceView!==MANAGER.page);
  $$('[data-workspace-page]').forEach(e=>{const active=e.dataset.workspacePage===MANAGER.page;e.classList.toggle('active',active);if(e.closest('#workspace-nav')){if(active)e.setAttribute('aria-current','page');else e.removeAttribute('aria-current')}});
  if(MANAGER.page==='attachments')renderAttachmentList();
  if(MANAGER.page==='history'){renderHistoryList();refreshHistory()}
}

function locallyQueued(path){
  const batch=path.slice(0,path.lastIndexOf('/'));
  if(state.busy&&(state.job?.input===path||(path.startsWith('inputs/')&&state.job?.input?.startsWith(batch+'/'))))return true;
  return state.queue.some(entry=>entry.path===path||(path.startsWith('inputs/')&&entry.path?.startsWith(batch+'/')));
}

function canDeleteAttachment(file){return state.connected&&MANAGER.supported&&file.path.startsWith('inputs/')&&!file.in_use&&!locallyQueued(file.path)}
function activeHistory(job){return ['running','queued'].includes(job.state)}
function fileKind(file){return file.path.startsWith('inputs/')?'导入附件':file.generated||file.path.startsWith('out/')?'分析输出':'练习附件'}
function emptyManager(container,title,description){const box=node('div',undefined,'manager-empty');box.append(node('b',title),node('p',description));container.append(box)}
function managerAction(text,callback,extra=''){const b=node('button',text,'text-btn '+extra);b.type='button';b.addEventListener('click',callback);return b}
function managerCheckbox(label,selected,disabled,change){const input=node('input');input.type='checkbox';input.checked=selected;input.disabled=disabled;input.setAttribute('aria-label',label);input.addEventListener('change',()=>change(input));return input}
function toggleSelection(set,key,input){if(input.checked&&set.size>=100){input.checked=false;toast('每次最多选择 100 项。');return}input.checked?set.add(key):set.delete(key);updateManagementButtons()}

function pagination(container,total,index,onChange){
  container.replaceChildren();const pages=Math.max(1,Math.ceil(total/MANAGER.pageSize));
  const prev=managerAction('← 上一页',()=>onChange(index-1)),next=managerAction('下一页 →',()=>onChange(index+1));prev.disabled=index===0;next.disabled=index>=pages-1;
  container.append(node('span','共 '+total+' 项 · 第 '+(index+1)+' / '+pages+' 页'),prev,next);
}

function filteredAttachments(){const q=$('attachment-search').value.trim().toLowerCase(),filter=$('attachment-filter').value;return state.files.filter(f=>(!q||f.path.toLowerCase().includes(q))&&(filter==='all'||filter==='imported'&&f.path.startsWith('inputs/')||filter==='exercise'&&!f.path.startsWith('inputs/')&&!f.generated&&!f.path.startsWith('out/')||filter==='output'&&(f.generated||f.path.startsWith('out/')))).sort((a,b)=>(b.modified||0)-(a.modified||0)||a.path.localeCompare(b.path))}
function attachmentPage(){return filteredAttachments().slice(MANAGER.filePage*MANAGER.pageSize,(MANAGER.filePage+1)*MANAGER.pageSize)}
function filteredHistory(){const q=$('history-search').value.trim().toLowerCase(),filter=$('history-filter').value;return MANAGER.history.filter(j=>(!q||(j.title+' '+j.id+' '+j.input).toLowerCase().includes(q))&&(filter==='all'||filter==='active'&&activeHistory(j)||filter==='finished'&&!activeHistory(j)||filter==='completed'&&j.state==='completed'||filter==='finding'&&j.state==='finding'||filter==='failed'&&['failed','timeout','interrupted','cancelled'].includes(j.state)))}
function historyPage(){return filteredHistory().slice(MANAGER.jobPage*MANAGER.pageSize,(MANAGER.jobPage+1)*MANAGER.pageSize)}

function updateManagementButtons(){
  $('attachment-count').textContent=String(state.files.filter(f=>f.path.startsWith('inputs/')).length);$('history-count').textContent=String(MANAGER.history.length);
  $('attachment-selection-count').textContent=String(MANAGER.filesSelected.size);$('history-selection-count').textContent=String(MANAGER.jobsSelected.size);
  $('delete-attachments').disabled=!state.connected||!MANAGER.supported||MANAGER.deleting||!MANAGER.filesSelected.size;
  $('delete-history').disabled=!state.connected||!MANAGER.supported||MANAGER.deleting||!MANAGER.jobsSelected.size;
  $('refresh-attachments').disabled=!state.connected||MANAGER.deleting;$('refresh-history').disabled=!state.connected||MANAGER.deleting;
  $('analysis-running').hidden=!state.busy&&!state.queue.length;
  for(const [id,rows,selected,eligible,key]of [['attachment-select-all',attachmentPage(),MANAGER.filesSelected,canDeleteAttachment,'path'],['history-select-all',historyPage(),MANAGER.jobsSelected,j=>state.connected&&MANAGER.supported&&!activeHistory(j),'id']]){
    const checkbox=$(id),available=rows.filter(eligible),count=available.filter(r=>selected.has(r[key])).length;
    checkbox.disabled=!available.length||MANAGER.deleting;checkbox.checked=available.length>0&&count===available.length;checkbox.indeterminate=count>0&&count<available.length;
  }
}

function renderAttachmentList(){
  const imported=state.files.filter(f=>f.path.startsWith('inputs/')),existing=new Set(state.files.map(f=>f.path));for(const p of MANAGER.filesSelected)if(!existing.has(p))MANAGER.filesSelected.delete(p);
  $('attachment-summary').textContent=state.connected?'已导入 '+imported.length+' 个附件 · '+bytes(imported.reduce((n,f)=>n+(f.bytes||0),0)):'静态阅读模式；启动本地平台后可上传和删除附件。';
  const files=filteredAttachments(),box=$('attachment-list');MANAGER.filePage=Math.min(MANAGER.filePage,Math.max(0,Math.ceil(files.length/MANAGER.pageSize)-1));box.replaceChildren();
  if(!files.length)emptyManager(box,$('attachment-search').value?'没有匹配的附件':'还没有导入附件','点击“导入附件”或将文件拖到上方区域。');
  for(const file of attachmentPage()){
    const row=node('article',undefined,'manager-row attachment-row');row.dataset.filePath=file.path;
    const allowed=canDeleteAttachment(file);row.append(managerCheckbox('选择附件 '+file.path,MANAGER.filesSelected.has(file.path),!allowed||MANAGER.deleting,input=>toggleSelection(MANAGER.filesSelected,file.path,input)));
    const content=node('div',undefined,'manager-item-content');content.append(node('strong',file.path.split('/').pop()),node('code',file.path));
    const meta=node('div',undefined,'manager-meta');meta.append(node('span',fileKind(file),'file-badge'),node('span',bytes(file.bytes)));
    if(file.in_use||locallyQueued(file.path))meta.append(node('span','正在使用','file-badge busy-badge'));else if(!file.path.startsWith('inputs/'))meta.append(node('span','只读','muted'));content.append(meta);row.append(content);
    const actions=node('div',undefined,'manager-actions');const use=managerAction('用于分析',()=>{changeEvidenceFile(file.path);route('workbench')});actions.append(use);
    if(state.connected){const link=node('a','下载','text-btn');link.href=dataURL(file.path);link.download=file.path.split('/').pop();actions.append(link)}
    if(file.path.startsWith('inputs/')){const remove=managerAction('删除',()=>deleteAttachments([file.path]),'danger-text');remove.disabled=!allowed||MANAGER.deleting;remove.title=allowed?'删除该导入附件':'附件正在上传、排队或分析，请等待对应任务完成。';actions.append(remove)}
    else if(file.generated||file.path.startsWith('out/'))actions.append(managerAction('历史管理',()=>route('workbench/history')));
    row.append(actions);box.append(row);
  }
  pagination($('attachment-pagination'),files.length,MANAGER.filePage,index=>{MANAGER.filePage=index;renderAttachmentList()});updateManagementButtons();
}

function renderHistoryList(){
  const existing=new Set(MANAGER.history.filter(j=>!activeHistory(j)).map(j=>j.id));for(const id of MANAGER.jobsSelected)if(!existing.has(id))MANAGER.jobsSelected.delete(id);
  const jobs=filteredHistory(),box=$('job-history');MANAGER.jobPage=Math.min(MANAGER.jobPage,Math.max(0,Math.ceil(jobs.length/MANAGER.pageSize)-1));box.replaceChildren();
  $('history-summary').textContent=state.connected?'最近 '+MANAGER.history.length+' 条记录（最多 500 条） · 删除记录会一并删除该次导出文件，原始附件保留。':'启动本地平台后可查看和管理分析记录。';
  if(!jobs.length)emptyManager(box,MANAGER.history.length?'没有匹配的记录':'还没有分析记录','运行工具后，结果与报告会保存在这里。');
  for(const job of historyPage()){
    const row=node('article',undefined,'manager-row history-row');row.dataset.jobId=job.id;
    row.append(managerCheckbox('选择记录 '+job.title,MANAGER.jobsSelected.has(job.id),!state.connected||!MANAGER.supported||activeHistory(job)||MANAGER.deleting,input=>toggleSelection(MANAGER.jobsSelected,job.id,input)));
    const content=node('div',undefined,'manager-item-content');content.append(node('strong',job.title),node('code',job.input||'文本 / 无输入附件'));
    const meta=node('div',undefined,'manager-meta');meta.append(node('span',STATE_NAMES[job.state]||job.state,'file-badge '+(activeHistory(job)?'busy-badge':'')),node('span',(job.created||'').slice(0,19).replace('T',' ')),node('span',job.duration+' 秒'),node('span',job.id,'task-id'));content.append(meta);row.append(content);
    const actions=node('div',undefined,'manager-actions');actions.append(managerAction('打开结果',()=>openHistory(job.id)));
    const remove=managerAction('删除',()=>deleteHistory([job.id]),'danger-text');remove.disabled=!state.connected||!MANAGER.supported||activeHistory(job)||MANAGER.deleting;remove.title=activeHistory(job)?'请先停止并等待任务结束。':'删除这条记录及其导出文件';actions.append(remove);row.append(actions);box.append(row);
  }
  pagination($('history-pagination'),jobs.length,MANAGER.jobPage,index=>{MANAGER.jobPage=index;renderHistoryList()});updateManagementButtons();
}

function updateManagementState(){
  const job=state.job,key=job?job.id+':'+job.state:'';
  if(job&&key!==MANAGER.lastJobState){MANAGER.lastJobState=key;const row={id:job.id,title:job.title,action:job.action,state:job.state,created:job.created,duration:job.duration,input:job.input};const i=MANAGER.history.findIndex(j=>j.id===job.id);if(i>=0)MANAGER.history[i]=row;else MANAGER.history.unshift(row);if(MANAGER.page==='history')renderHistoryList()}
  updateManagementButtons();
}

function confirmDeletion(title,description,names){
  return new Promise(resolve=>{const dialog=$('delete-dialog');$('delete-title').textContent=title;$('delete-description').textContent=description;$('delete-items').replaceChildren(...names.slice(0,8).map(name=>node('li',name)));if(names.length>8)$('delete-items').append(node('li','另有 '+(names.length-8)+' 项'));dialog.returnValue='';dialog.addEventListener('close',()=>resolve(dialog.returnValue==='confirm'),{once:true});dialog.showModal()});
}

function reconcileRemovedFiles(paths,prefixes=[]){
  const removed=value=>typeof value==='string'&&(paths.includes(value)||prefixes.some(prefix=>value.startsWith(prefix)));
  const params=getParams(),fallback=state.files.find(f=>f.path.startsWith('inputs/'))?.path||state.files.find(f=>!f.generated)?.path||'';
  const existing=new Set(state.files.map(f=>f.path));
  if(removed(state.currentFile)||!existing.has(state.currentFile))state.currentFile=fallback;
  for(const [key,value]of Object.entries(params))if(removed(value)||(['file','input_file'].includes(key)&&value&&!existing.has(value)))params[key]=key==='file'||key==='input_file'?fallback:'';
  for(const key of Object.keys(WB.contexts))if(removed(key))delete WB.contexts[key];
  renderFields(params);renderAnalysisFiles();
}

async function deleteAttachments(paths){
  if(MANAGER.deleting||!state.connected||!MANAGER.supported)return;
  if(!await confirmDeletion('删除 '+paths.length+' 个附件？','将从本工具包中删除这些导入文件。已有分析记录与报告会保留。',paths))return;
  MANAGER.deleting=true;renderAttachmentList();
  try{const result=await api('/api/files/delete',{paths});for(const path of result.deleted)MANAGER.filesSelected.delete(path);state.files=await api('/api/files');reconcileRemovedFiles(result.deleted);toast(result.failed.length?'已删除 '+result.deleted.length+' 项；'+result.failed[0].error:'已删除 '+result.deleted.length+' 个附件。')}
  catch(error){toast(error.message)}finally{MANAGER.deleting=false;await refreshFiles().catch(()=>{});renderAttachmentList()}
}

async function deleteHistory(ids){
  if(MANAGER.deleting||!state.connected||!MANAGER.supported)return;
  const names=ids.map(id=>{const job=MANAGER.history.find(j=>j.id===id);return (job?.title||id)+' · '+id});
  if(!await confirmDeletion('删除 '+ids.length+' 条分析记录？','将一并删除这些记录的导出文件和报告，上传的原始附件保留。',names))return;
  MANAGER.deleting=true;renderHistoryList();
  try{const result=await api('/api/jobs/delete',{ids});for(const id of result.deleted)MANAGER.jobsSelected.delete(id);
    if(result.deleted.includes(state.job?.id)){clearTimeout(pollTimer);state.job=null;state.busy=false;WB.lastJob='';MANAGER.lastJobState='';$('results').hidden=true;$('result-empty').hidden=false}
    for(const row of state.queueRows)if(result.deleted.includes(row.job)){row.job='';row.state='记录已删除'}renderQueue();
    state.files=await api('/api/files');reconcileRemovedFiles([],result.deleted.map(id=>'out/platform_runs/'+id+'/'));toast(result.failed.length?'已删除 '+result.deleted.length+' 条；'+result.failed[0].error:'已删除 '+result.deleted.length+' 条分析记录。');await refreshHistory()
  }catch(error){toast(error.message)}finally{MANAGER.deleting=false;await refreshFiles().catch(()=>{});renderHistoryList();updateRunButton()}
}

function initializeManagement(){
  let collapsed=matchMedia('(max-width:900px)').matches;try{const saved=localStorage.getItem('forensics-sidebar-collapsed');if(saved!==null)collapsed=saved==='1'}catch{}setSidebarCollapsed(collapsed,false);
  $('sidebar-toggle').addEventListener('click',()=>setSidebarCollapsed(!document.body.classList.contains('sidebar-collapsed')));
  $('sidebar-close').addEventListener('click',()=>setSidebarCollapsed(true));$('sidebar-backdrop').addEventListener('click',()=>setSidebarCollapsed(true));
  const topbar=document.querySelector('.topbar'),observer=new ResizeObserver(()=>document.documentElement.style.setProperty('--app-topbar-height',Math.ceil(topbar.getBoundingClientRect().height)+'px'));observer.observe(topbar);
  document.addEventListener('click',event=>{const button=event.target.closest('[data-workspace-page]');if(button){event.preventDefault();route(button.dataset.workspacePage==='analysis'?'workbench':'workbench/'+button.dataset.workspacePage)}});
  document.addEventListener('keydown',event=>{if(event.key==='Escape'&&!$('delete-dialog').open&&matchMedia('(max-width:900px)').matches)setSidebarCollapsed(true,false)});
  for(const id of ['attachment-search','attachment-filter'])$(id).addEventListener(id.endsWith('search')?'input':'change',()=>{MANAGER.filePage=0;renderAttachmentList()});
  for(const id of ['history-search','history-filter'])$(id).addEventListener(id.endsWith('search')?'input':'change',()=>{MANAGER.jobPage=0;renderHistoryList()});
  $('attachment-select-all').addEventListener('change',event=>{for(const file of attachmentPage().filter(canDeleteAttachment)){if(event.target.checked&&MANAGER.filesSelected.size<100)MANAGER.filesSelected.add(file.path);else if(!event.target.checked)MANAGER.filesSelected.delete(file.path)}renderAttachmentList()});
  $('history-select-all').addEventListener('change',event=>{for(const job of historyPage().filter(j=>!activeHistory(j))){if(event.target.checked&&MANAGER.jobsSelected.size<100)MANAGER.jobsSelected.add(job.id);else if(!event.target.checked)MANAGER.jobsSelected.delete(job.id)}renderHistoryList()});
  $('delete-attachments').addEventListener('click',()=>deleteAttachments([...MANAGER.filesSelected]));$('delete-history').addEventListener('click',()=>deleteHistory([...MANAGER.jobsSelected]));
  $('refresh-attachments').addEventListener('click',()=>refreshFiles().catch(error=>toast(error.message)));$('refresh-history').addEventListener('click',refreshHistory);
  renderAttachmentList();renderHistoryList();
}
