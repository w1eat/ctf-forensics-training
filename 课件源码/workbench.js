const WB={tab:'recipes',category:'all',recipe:null,step:0,version:'3',resultTab:'visual',contexts:{},lastJob:''};
const WB_LABELS={imdisk:'ImDisk · RAW 分区',windows:'Windows · ISO / VHD / VHDX',veracrypt:'VeraCrypt 1.26.29 容器',truecrypt:'TrueCrypt · 1.25.9 兼容模式',text:'输入文本',file:'附件文件',utf8:'UTF-8 文本',utf16le:'UTF-16LE 文本',hex:'十六进制字节',base64:'Base64 字节',plan:'查看准备与命令',status:'查看当前状态',mount:'执行只读挂载',unmount:'卸载本工作区卷',install_imdisk:'安装随包 ImDisk 驱动',list:'查看列表',import:'导入工作台',calculate:'计算摘要',dictionary:'验证口令候选',decrypt:'解密',encrypt:'加密',pkcs7:'PKCS#7 填充',none:'无 / 不使用',all:'全部',deleted:'仅删除项',auto:'自动识别',general:'系统 / 进程 / 参数 / 文件',history:'启动参数与控制台历史',files:'文件对象与 MFT',registry:'注册表与主机信息',credentials:'样本账号与哈希',container:'加密容器线索',clipboard:'复制粘贴与剪贴板',base64_decode:'Base64 解码',base64_encode:'Base64 编码',base64url_decode:'Base64URL 解码',base64url_encode:'Base64URL 编码',base32_decode:'Base32 解码',base32_encode:'Base32 编码',base85_decode:'Base85 解码',base85_encode:'Base85 编码',hex_decode:'HEX 还原字节',hex_encode:'字节转 HEX',url_decode:'URL 百分号解码',url_encode:'URL 百分号编码',html_decode:'HTML 实体解码',html_encode:'HTML 实体编码',unicode_decode:'还原 Unicode / 字节转义',rot13:'ROT13',caesar:'凯撒 · 指定位移',caesar_all:'凯撒 · 全部 26 个候选',atbash:'Atbash 字母反转',reverse_text:'反转文本字符',reverse_bytes:'反转原始字节',ascii_shift:'字符码位加减',binary_decode:'二进制字节串解码',decimal_decode:'十进制字节串解码',octal_decode:'八进制字节串解码',core_values_decode:'核心价值观编码解码',core_values_encode:'核心价值观编码',xor:'已知密钥 XOR',xor_single_byte:'单字节 XOR · 256 个候选',replace:'按表逐字符替换'};

function isMemoryAction(action){return !!action&&(action.ram||action.casework==='memory')}
function rememberCurrentContext(){if(!state.action)return;const p=getParams(),file=state.currentFile||p.file;if(!file)return;const context=WB.contexts[file]||={};for(const key of ['profile','pid','sector','sector_size','address','address_type'])if(key in p&&(key!=='profile'||isMemoryAction(state.action)))context[key]=p[key]}
function changeEvidenceFile(path){
  const params=getParams(),previous=state.currentFile;if(previous){const context=WB.contexts[previous]||={};for(const key of ['profile','pid','sector','sector_size','address','address_type'])if(key in params&&(key!=='profile'||isMemoryAction(state.action)))context[key]=params[key]}
  state.currentFile=path;const next={...params,file:path},context=WB.contexts[path]||{};
  for(const f of state.action?.fields||[])if(['profile','pid','sector','sector_size','address','address_type'].includes(f.key)&&(f.key!=='profile'||isMemoryAction(state.action)))next[f.key]=context[f.key]??(['profile','pid','sector','address'].includes(f.key)?'':f.default);
  renderAnalysisFiles();if(state.action?.fields.some(f=>f.key==='file'))renderFields(next);
}
function contextualParams(action,params){
  const file=params.file||state.currentFile,context=WB.contexts[file]||{},value={...params};
  for(const f of action.fields){if((f.key!=='profile'||isMemoryAction(action))&&f.key in context&&(!(f.key in value)||value[f.key]===''))value[f.key]=context[f.key];if(action.ram&&['pid','address'].includes(f.key)&&!(f.key in value))value[f.key]=''}
  if(action.casework&&action.fields.some(f=>f.key==='input_file')&&value.source==='file'&&!value.input_file)value.input_file=file;
  return value;
}
function applyFieldConditions(){const params=getParams();for(const f of state.action?.fields||[]){const label=$$('#tool-fields [data-field-key]').find(e=>e.dataset.fieldKey===f.key);if(!label)continue;label.hidden=!!f.when&&!Object.entries(f.when).every(([key,values])=>values.includes(params[key]));for(const e of label.querySelectorAll('input,textarea,select'))e.disabled=label.hidden}}
function updateEvidenceContext(){const file=state.files.find(f=>f.path===state.currentFile);$('evidence-size').textContent=file?bytes(file.bytes):'';$('evidence-kind').textContent=state.currentFile.startsWith('out/')?'分析输出':state.currentFile.startsWith('inputs/')?'已导入附件':'练习附件'}
function showWorkbenchTab(tab){WB.tab=tab;$$('[data-wb-tab]').forEach(e=>{e.classList.toggle('active',e.dataset.wbTab===tab);e.setAttribute('aria-selected',String(e.dataset.wbTab===tab))});$('recipe-list').hidden=tab!=='recipes';$('recipe-filters').hidden=tab!=='recipes';$('action-list').hidden=tab!=='tools';$('action-search').placeholder=tab==='recipes'?'搜索题目线索或流程':'搜索 '+DATA.actions.length+' 个工具操作';if(tab==='recipes')renderRecipeList($('action-search').value);else actionList($('action-search').value)}
function renderRecipeList(query=''){
  const list=$('recipe-list');list.replaceChildren();const q=query.toLowerCase();
  for(const recipe of DATA.recipes||[]){if(WB.category!=='all'&&recipe.category!==WB.category)continue;if(q&&!(recipe.title+recipe.clue+recipe.source).toLowerCase().includes(q))continue;const b=node('button',undefined,'recipe-choice');b.type='button';b.dataset.recipe=recipe.id;b.classList.toggle('active',WB.recipe?.id===recipe.id);b.append(node('b',recipe.title),node('small',recipe.steps.length+' 步 · '+recipe.source));list.append(b)}
  if(!list.childNodes.length)list.append(node('p','未找到对应路线，可切换全部工具。','coverage-note'));
}
function pickRecipe(id){const recipe=DATA.recipes.find(r=>r.id===id);if(!recipe)return;WB.recipe=recipe;WB.step=0;renderRecipeList($('action-search').value);pickRecipeStep(0)}
function pickRecipeStep(index,overrides={}){
  if(!WB.recipe)return;const step=WB.recipe.steps[index];if(!step)return;rememberCurrentContext();WB.step=index;
  const version=WB.version,action=version==='2'&&step.v2_action?step.v2_action:step.action;
  const params={...step.params,...(version==='2'&&step.v2_params?step.v2_params:{}),...overrides};
  if(action==='memory_triage')params.version=version;
  if(DATA.actions.find(a=>a.id===action)?.fields.some(f=>f.key==='file')&&!params.file)params.file=state.currentFile;
  chooseAction(action,params);renderRecipeDetail();
}
function renderRecipeDetail(){
  const box=$('recipe-detail');box.replaceChildren();if(!WB.recipe){box.hidden=true;return}box.hidden=false;const recipe=WB.recipe,current=recipe.steps[WB.step];
  const heading=node('div',undefined,'recipe-heading');heading.append(node('span','解题路线 · '+(WB.step+1)+' / '+recipe.steps.length,'eyebrow'),node('b',recipe.title));const source=node('small',recipe.source);heading.append(source);box.append(heading);
  const steps=node('div',undefined,'recipe-steps');recipe.steps.forEach((s,i)=>{const b=node('button',undefined,'recipe-step');b.type='button';b.dataset.recipeStep=String(i);b.classList.toggle('active',i===WB.step);b.append(node('span',String(i+1).padStart(2,'0')),node('b',s.title));steps.append(b)});box.append(steps);
  const active=current.action===state.action?.id||current.v2_action===state.action?.id;const reason=node('p',active?current.why:'当前打开了单项工具。可点击上方某个步骤返回这条路线，也可继续独立分析。','step-rationale');reason.prepend(node('strong',active?'为什么这样做：':'路线参考：'));box.append(reason);
  if(active&&current.input_hint)box.append(node('p','输入提醒：'+current.input_hint+'。可点击结果文件的“作为下一步输入”。','input-reminder'));
  const detail=node('details',undefined,'recipe-boundary');detail.append(node('summary','题意线索与验证条件'),node('p',recipe.clue),node('p',recipe.check));box.append(detail);
  $('memory-version-wrap').hidden=recipe.category!=='memory';
}
function setResultTab(name){WB.resultTab=name;$$('[data-result-tab]').forEach(e=>{e.classList.toggle('active',e.dataset.resultTab===name);e.setAttribute('aria-selected',String(e.dataset.resultTab===name))});$$('[data-result-panel]').forEach(e=>{e.hidden=e.dataset.resultPanel!==name;if(e.tagName==='DETAILS')e.open=true})}
function updateWorkbenchJob(job){
  if(WB.lastJob!==job.id){WB.lastJob=job.id;WB.resultTab='visual'}
  $('result-empty').hidden=true;$('output-count').textContent=String((job.files||[]).length);setResultTab(WB.resultTab);
  const file=job.input,volumes=job.data?.volumes;if(file&&volumes?.length===1){const context=WB.contexts[file]||={};context.sector=String(volumes[0].sector);context.sector_size=String(volumes[0].sector_size)}
}
async function executeStep(action,params){if(!state.connected||state.busy||state.uploading||state.queueActive){toast('请先连接本地服务，并等待当前任务结束。');return}try{chooseAction(action,params);const job=await api('/api/run',{action,params:getParams()});WB.resultTab='visual';renderJob(job);clearTimeout(pollTimer);pollTimer=setTimeout(poll,350)}catch(e){toast(e.message)}}
function goHex(offset,file){executeStep('hex_view',{file:file||state.job?.input||state.currentFile,offset:String(offset),length:'256'})}
function extraTable(columns,rows,buttons){const wrap=node('div',undefined,'table'),t=node('table'),head=node('thead'),tr=node('tr');for(const label of columns)tr.append(node('th',label));if(buttons)tr.append(node('th','操作'));head.append(tr);t.append(head);const body=node('tbody');rows.forEach((row,index)=>{const r=node('tr');for(const c of row)r.append(node('td',String(c??'')));if(buttons){const td=node('td');for(const b of buttons(index))td.append(b);r.append(td)}body.append(r)});t.append(body);wrap.append(t);return wrap}
function opButton(label,action,params,runNow=false){const b=node('button',label,'text-btn');b.type='button';b.addEventListener('click',()=>{const merged=action===state.action?.id?{...getParams(),...params}:params;runNow?executeStep(action,merged):chooseAction(action,merged)});return b}
function renderHex(job,box,data){
  const controls=node('div',undefined,'hex-controls'),previous=node('button','← 上一页','btn secondary small'),next=node('button','下一页 →','btn secondary small');previous.disabled=data.offset===0;next.disabled=data.next>=data.total_bytes;previous.addEventListener('click',()=>goHex(data.previous,job.input));next.addEventListener('click',()=>goHex(data.next,job.input));controls.append(previous,node('span',data.offset.toString(16).padStart(8,'0')+' / '+bytes(data.total_bytes)),next);
  const jump=node('input');jump.setAttribute('aria-label','十六进制视图定位偏移');jump.placeholder='十进制或 0x 偏移';const go=node('button','定位','text-btn');go.addEventListener('click',()=>{const n=Number(jump.value);if(!Number.isSafeInteger(n)||n<0||n>data.total_bytes)return toast('请输入范围内的字节偏移。');goHex(n,job.input)});jump.addEventListener('keydown',e=>{if(e.key==='Enter'){e.preventDefault();go.click()}});controls.append(jump,go);box.append(controls);
  const grid=node('div',undefined,'hex-grid');const raw=(data.hex.match(/../g)||[]);let selected=null;for(let i=0;i<raw.length;i+=16){const row=node('div',undefined,'hex-row'),offset=node('span',(data.offset+i).toString(16).padStart(8,'0'),'hex-offset');row.append(offset);const values=node('div',undefined,'hex-bytes');for(let j=i;j<Math.min(i+16,raw.length);j++){const b=node('button',raw[j]);b.type='button';b.title='偏移 0x'+(data.offset+j).toString(16);b.addEventListener('click',()=>{selected?.classList.remove('selected');selected=b;b.classList.add('selected');info.textContent='偏移 0x'+(data.offset+j).toString(16)+' · 十进制 '+parseInt(raw[j],16)+' · 二进制 '+parseInt(raw[j],16).toString(2).padStart(8,'0')});values.append(b)}row.append(values,node('span',raw.slice(i,i+16).map(v=>{const c=parseInt(v,16);return c>=32&&c<127?String.fromCharCode(c):'.'}).join(''),'hex-ascii'));grid.append(row)}const info=node('p','点击字节查看偏移、十进制和二进制值。','hex-inspector');box.append(grid,info);
  const search=node('div',undefined,'hex-search'),input=node('input');input.placeholder='搜索 HEX、UTF-8 或 UTF-16LE';input.setAttribute('aria-label','在当前文件中搜索字节');const format=node('select');format.setAttribute('aria-label','搜索字节表示');for(const [value,label]of [['hex','HEX'],['utf8','UTF-8'],['utf16le','UTF-16LE']]){const o=node('option',label);o.value=value;format.append(o)}const find=node('button','搜索全文件','btn secondary small');find.addEventListener('click',()=>executeStep('byte_search',{file:job.input,pattern:input.value,pattern_format:format.value,offset:'0',scan_mib:'0'}));search.append(input,format,find);box.append(search,opButton('在副本中修复这些字节','binary_patch',{file:job.input,offset:String(data.offset)}),node('p',data.note,'coverage-note'));
}
function renderCasework(job,box,data){
  if(data.kind==='hex'){renderHex(job,box,data);return}
  if(data.note)box.append(node('p',data.note,'coverage-note'));
  if(data.operation==='transform'){
    const header=node('div',undefined,'transform-summary');header.append(node('b',bytes(data.bytes)+' · 完整字节已导出'),node('small','SHA256 '+data.sha256));box.append(header);
    const tabs=node('div',undefined,'transform-views'),preview=node('pre',data.text,'transform-preview');for(const [key,label]of [['text','UTF-8'],['hex','HEX'],['base64','Base64']]){const b=node('button',label,'text-btn');b.addEventListener('click',()=>{preview.textContent=data[key]||''});tabs.append(b)}box.append(tabs,preview);
    const cont=node('button','文本继续下一步转换','btn secondary small');cont.type='button';cont.disabled=!!data.preview_limited||data.text_roundtrip===false;cont.addEventListener('click',()=>{const params={source:'text',input_format:'utf8',text:data.text};if(WB.recipe?.steps[WB.step+1]?.action==='codec')pickRecipeStep(WB.step+1,params);else chooseAction('codec',{...params,operation:'base64_decode'});toast('已填入完整文本，可调整转换方法。')});box.append(cont);if(data.preview_limited||data.text_roundtrip===false)box.append(node('p','预览有截断或字节无法无损转成 UTF-8，请选择完整 .bin 文件继续转换。','coverage-note'));
  }
  if(data.operation==='disk_inventory')box.append(extraTable(data.columns,data.rows,i=>{const r=data.entries[i],buttons=[opButton('查看元数据','disk_istat',{file:job.input,sector:String(r.sector),inode:r.inode})];if(r.type.split('/').at(-1)==='r')buttons.push(opButton('导出此文件','disk_recover',{file:job.input,sector:String(r.sector),sector_size:String(r.sector_size),inode:r.inode},true));return buttons}));
  else if(data.operation==='disk_timeline')box.append(extraTable(data.columns,data.rows,i=>{const r=data.entries[i],buttons=[opButton('查看元数据','disk_istat',{file:job.input,sector:String(r.sector),inode:r.inode})];if(r.mode.startsWith('r/'))buttons.push(opButton('导出此文件','disk_recover',{file:job.input,sector:String(r.sector),sector_size:String(r.sector_size),inode:r.inode},true));return buttons}));
  else if(data.operation==='byte_search')box.append(extraTable(data.columns,data.rows,i=>{const b=node('button','查看字节','text-btn');b.addEventListener('click',()=>goHex(data.offsets[i],job.input));return [b]}));
  else if(data.operation==='mounted_files')box.append(extraTable(data.columns,data.rows,i=>{const e=data.entries[i];return [opButton(e.directory?'进入目录':'导入此文件','mounted_files',{drive:data.drive,relative:e.path,mode:e.directory?'list':'import'},true)]}));
  else if(data.columns&&data.rows)box.append(table(data));
  if(data.tables)for(const t of data.tables){const d=node('details',undefined,'casework-table');d.open=data.tables.length<=2;d.append(node('summary',t.title+' · '+(t.rows?.length||0)+' 行'),table(t));box.append(d)}
  if(data.found!==undefined){box.append(node('b',data.found?'候选命中：'+data.candidate:'当前候选集未命中'),node('p','已检查 '+data.checked+' 个候选。','coverage-note'))}
  if(data.next_actions?.length){const next=node('div',undefined,'next-actions');next.append(node('b','依据当前结果继续'));for(const item of data.next_actions)next.append(opButton(item.title,item.action,item.params||{}));box.append(next)}
  if(data.warnings?.length){const d=node('details');d.append(node('summary',data.warnings.length+' 条候选未导出 / 需复核'),node('pre',JSON.stringify(data.warnings,null,2),'structured-preview'));box.append(d)}
  if(data.partial||data.limited)box.append(node('p','本次有未完成步骤或展示 / 预算限制，请结合完整输出与验证条件复核。','input-reminder'));
}
function useEvidenceOutput(path){
  state.currentFile=path;renderAnalysisFiles();const next=WB.recipe?.steps.findIndex((s,i)=>i>WB.step&&s.input_hint);
  if(next>=0)pickRecipeStep(next,{file:path,input_file:path,source:'file'});else chooseAction('auto_analyze',{file:path,profile:$('analysis-profile').value,workflow:'auto'});
  toast('已切换到导出文件；原结果仍保留在结果区。');
}
function initializeWorkbench(){
  const filters=$('recipe-filters');for(const [key,label]of DATA.recipe_categories||[]){const b=node('button',label);b.type='button';b.dataset.recipeCategory=key;b.classList.toggle('active',key==='all');filters.append(b)}
  showWorkbenchTab('recipes');pickRecipe('unknown');updateEvidenceContext();
  $('memory-version').addEventListener('change',event=>{WB.version=event.target.value;if(WB.recipe?.category==='memory')pickRecipeStep(WB.step)});
  $('tool-fields').addEventListener('input',()=>{rememberCurrentContext();applyFieldConditions()});$('tool-fields').addEventListener('change',()=>{rememberCurrentContext();applyFieldConditions()});
  document.addEventListener('click',event=>{const e=event.target.closest('button');if(!e)return;if(e.dataset.wbTab)showWorkbenchTab(e.dataset.wbTab);if(e.dataset.recipe)pickRecipe(e.dataset.recipe);if(e.dataset.recipeStep)pickRecipeStep(Number(e.dataset.recipeStep));if(e.dataset.recipeCategory){WB.category=e.dataset.recipeCategory;$$('[data-recipe-category]').forEach(b=>b.classList.toggle('active',b===e));renderRecipeList($('action-search').value)}if(e.dataset.resultTab)setResultTab(e.dataset.resultTab);if(e.dataset.quickAction){showWorkbenchTab('tools');chooseAction(e.dataset.quickAction)}if(e.id==='open-cyberchef'){if(DATA.distribution==='study'||DATA.distribution==='course')return toast('离线 CyberChef 在 Windows 完整工具包中。');window.open(DATA.toolkit+'tools/CyberChef/CyberChef_v9.28.0.html','_blank','noopener')}});
}
