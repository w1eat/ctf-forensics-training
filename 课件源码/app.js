(() => {
  'use strict';
  const slides = Array.from(document.querySelectorAll('.slide'));
  const overview = document.getElementById('overview');
  const overviewGrid = document.getElementById('overview-grid');
  const search = document.getElementById('slide-search');
  const chapterButtons = Array.from(document.querySelectorAll('.chapter'));
  const toastBox = document.getElementById('toast');
  let current = 0;
  let toastTimer;
  let readingObserver;
  const answered = new Map();
  function toast(message) {
    toastBox.textContent = message;
    toastBox.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { toastBox.hidden = true; }, 2600);
  }
  function updateChrome() {
    const active = slides[current];
    document.getElementById('current-page').textContent = String(current + 1).padStart(2, '0');
    document.getElementById('progress').style.width = `${(current + 1) / slides.length * 100}%`;
    document.getElementById('chapter-now').textContent = active.dataset.chapterName;
    document.getElementById('top-chapter').textContent = active.dataset.chapterName;
    document.getElementById('prev').disabled = current === 0;
    document.getElementById('next').disabled = current === slides.length - 1;
    chapterButtons.forEach(b => {
      const selected = b.dataset.chapter === active.dataset.chapter;
      b.classList.toggle('active', selected);
      if (selected) b.setAttribute('aria-current', 'step'); else b.removeAttribute('aria-current');
    });
    overviewGrid.querySelectorAll('.overview-item').forEach((b) => b.classList.toggle('current', +b.dataset.index === current));
    document.getElementById('slide-announcement').textContent = `第 ${current + 1} 页，共 ${slides.length} 页：${active.dataset.title}`;
    document.title = `${active.dataset.title} · 证据实验室`;
  }
  function savePosition() {
    const hash = `#slide-${current + 1}`;
    try { history.replaceState(null, '', hash); } catch (_) { /* Local files can restrict history. */ }
  }
  function goTo(index, scroll = true) {
    const nextIndex = Math.max(0, Math.min(slides.length - 1, index));
    slides[current].classList.remove('active');
    current = nextIndex;
    slides[current].classList.add('active');
    updateChrome();
    savePosition();
    if (scroll) {
      if (document.body.classList.contains('reading')) slides[current].scrollIntoView({ block: 'start' });
      else window.scrollTo({ top: 0 });
    }
  }
  function renderOverview(query = '') {
    overviewGrid.replaceChildren();
    const terms = query.trim().toLowerCase().split(/\s+/).filter(Boolean);
    slides.forEach((slide, index) => {
      const searchable = `${slide.dataset.title} ${slide.dataset.chapterName} ${slide.querySelector('.slide-body').textContent}`.toLowerCase();
      if (!terms.every(term => searchable.includes(term))) return;
      const button = document.createElement('button');
      button.className = `overview-item${index === current ? ' current' : ''}`;
      button.dataset.index = index;
      const label = document.createElement('small');
      label.textContent = `${String(index + 1).padStart(2, '0')} / ${slide.dataset.chapterName}`;
      const title = document.createElement('strong');
      title.textContent = slide.dataset.title;
      button.append(label, title);
      button.addEventListener('click', () => { overview.close(); goTo(index); });
      overviewGrid.append(button);
    });
    if (!overviewGrid.children.length) {
      const empty = document.createElement('p');
      empty.className = 'no-results';
      empty.textContent = '没有找到相关页面，试试“文件头”“流量”或“时间线”。';
      overviewGrid.append(empty);
    }
  }
  function openOverview() {
    search.value = '';
    renderOverview();
    overview.showModal();
    search.focus();
  }
  document.querySelectorAll('[data-overview]').forEach(b => b.addEventListener('click', openOverview));
  document.getElementById('close-overview').addEventListener('click', () => overview.close());
  overview.addEventListener('click', e => { if (e.target === overview) { const r = overview.getBoundingClientRect(); if (e.clientX < r.left || e.clientX > r.right || e.clientY < r.top || e.clientY > r.bottom) overview.close(); } });
  search.addEventListener('input', () => renderOverview(search.value));
  chapterButtons.forEach(b => b.addEventListener('click', () => goTo(slides.findIndex(s => s.dataset.chapter === b.dataset.chapter))));
  document.querySelectorAll('[data-goto]').forEach(b => b.addEventListener('click', () => goTo(+b.dataset.goto - 1)));
  document.getElementById('prev').addEventListener('click', () => goTo(current - 1));
  document.getElementById('next').addEventListener('click', () => goTo(current + 1));
  document.getElementById('notes-toggle').addEventListener('click', () => {
    const enabled = document.body.classList.toggle('show-notes');
    document.getElementById('notes-toggle').setAttribute('aria-pressed', String(enabled));
    toast(enabled ? '讲师备注已显示，投影前可按 N 收起' : '讲师备注已收起');
  });
  document.getElementById('reading-toggle').addEventListener('click', () => {
    const enabled = document.body.classList.toggle('reading');
    document.getElementById('reading-toggle').setAttribute('aria-pressed', String(enabled));
    if (readingObserver) readingObserver.disconnect();
    if (enabled) {
      readingObserver = new IntersectionObserver(entries => {
        const candidate = entries.filter(e => e.isIntersecting).sort((a, b) => b.intersectionRatio - a.intersectionRatio)[0];
        if (candidate) {
          slides[current].classList.remove('active');
          current = slides.indexOf(candidate.target);
          slides[current].classList.add('active');
          updateChrome();
          savePosition();
        }
      }, { rootMargin: '-10% 0px -40% 0px', threshold: [0, .25, .5] });
      slides.forEach(s => readingObserver.observe(s));
    }
    goTo(current);
    toast(enabled ? '阅读模式：向下滚动查看全部课件' : '已回到逐页演示模式');
  });
  const fullscreenBtn = document.getElementById('fullscreen-toggle');
  fullscreenBtn.addEventListener('click', async () => {
    if (document.body.classList.contains('focus')) {
      document.body.classList.remove('focus');
      fullscreenBtn.setAttribute('aria-pressed', 'false');
      if (document.fullscreenElement) await document.exitFullscreen().catch(() => {});
    } else {
      document.body.classList.add('focus');
      fullscreenBtn.setAttribute('aria-pressed', 'true');
      if (document.documentElement.requestFullscreen) await document.documentElement.requestFullscreen().catch(() => { toast('已进入专注演示模式'); });
    }
  });
  document.addEventListener('fullscreenchange', () => {
    if (!document.fullscreenElement) {
      document.body.classList.remove('focus');
      fullscreenBtn.setAttribute('aria-pressed', 'false');
    }
  });
  document.getElementById('print').addEventListener('click', () => window.print());
  document.addEventListener('keydown', e => {
    if (overview.open || e.ctrlKey || e.metaKey || e.altKey) return;
    if (e.target.closest('input,textarea,select,[contenteditable=true]')) return;
    if (['ArrowRight', 'PageDown', 'ArrowLeft', 'PageUp', 'Home', 'End'].includes(e.key)) {
      e.preventDefault();
      if (e.key === 'Home') goTo(0);
      else if (e.key === 'End') goTo(slides.length - 1);
      else goTo(current + (['ArrowRight', 'PageDown'].includes(e.key) ? 1 : -1));
    } else if (e.code === 'Space' && !e.target.closest('button,a,summary')) {
      e.preventDefault(); goTo(current + (e.shiftKey ? -1 : 1));
    } else if (e.key.toLowerCase() === 'o') openOverview();
    else if (e.key.toLowerCase() === 'n') document.getElementById('notes-toggle').click();
    else if (e.key.toLowerCase() === 'r') document.getElementById('reading-toggle').click();
    else if (e.key.toLowerCase() === 'f') fullscreenBtn.click();
    else if (e.key === 'Escape' && document.body.classList.contains('focus')) fullscreenBtn.click();
  });
  window.addEventListener('hashchange', () => { const m = location.hash.match(/^#slide-(\d+)$/); if (m) goTo(+m[1] - 1); });
  async function copyCode(button) {
    const value = button.closest('.codebox').querySelector('code').textContent;
    try {
      if (navigator.clipboard && window.isSecureContext) await navigator.clipboard.writeText(value);
      else {
        const area = document.createElement('textarea'); area.value = value; area.style.position = 'fixed'; area.style.top = '-1000px'; document.body.append(area); area.select();
        const ok = document.execCommand('copy'); area.remove(); if (!ok) throw new Error('Copy unavailable');
      }
      const old = button.textContent; button.textContent = '已复制'; setTimeout(() => { button.textContent = old; }, 1600);
    } catch (_) { toast('请选中代码后按 Ctrl+C 复制'); }
  }
  document.querySelectorAll('[data-copy]').forEach(b => b.addEventListener('click', () => copyCode(b)));
  const zipData = document.getElementById('practice-data').textContent.trim();
  document.querySelectorAll('[data-download]').forEach(button => button.addEventListener('click', () => {
    const bytes = Uint8Array.from(atob(zipData), c => c.charCodeAt(0));
    const url = URL.createObjectURL(new Blob([bytes], { type: 'application/zip' }));
    const link = document.createElement('a'); link.href = url; link.download = document.getElementById('practice-data').dataset.filename || 'CTF取证基础_学员练习.zip'; document.body.append(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(url), 30000);
    toast('练习 ZIP 已交给浏览器下载，解压后再分析');
  }));
  document.querySelectorAll('.flag-form').forEach(form => form.addEventListener('submit', e => {
    e.preventDefault();
    const result = form.querySelector('.flag-result');
    const input = form.querySelector('input');
    const value = input.value.trim();
    if (!value) { result.textContent = '请输入你的 flag，再验证答案。'; result.className = 'flag-result'; input.focus(); return; }
    const correct = value === form.dataset.answer;
    result.className = `flag-result ${correct ? 'good' : 'bad'}`;
    result.textContent = correct ? '✓ 答案正确。再补齐文件、定位位置和操作步骤，形成完整证据记录。' : '还不匹配。检查大小写、花括号和题目格式；可以展开分级提示。';
    input.setAttribute('aria-invalid', String(!correct));
  }));
  function updateScore() {
    const score = Array.from(answered.values()).filter(Boolean).length;
    document.querySelectorAll('[data-quiz-score]').forEach(el => { el.textContent = `${score} / 8`; });
    document.querySelectorAll('[data-quiz-count]').forEach(el => { el.textContent = String(answered.size); });
  }
  document.querySelectorAll('.question').forEach(question => {
    question.querySelectorAll('.option').forEach(button => button.addEventListener('click', () => {
      const correct = button.dataset.choice === question.dataset.correct;
      answered.set(question.dataset.question, correct);
      question.querySelectorAll('.option').forEach(b => { b.classList.remove('correct', 'incorrect'); b.setAttribute('aria-pressed', String(b === button)); });
      button.classList.add(correct ? 'correct' : 'incorrect');
      const feedback = question.querySelector('.feedback');
      feedback.hidden = false;
      feedback.classList.toggle('incorrect', !correct);
      feedback.textContent = `${correct ? '✓ 回答正确。' : '再想一想。'}${question.dataset.explanation}`;
      updateScore();
    }));
  });
  document.querySelectorAll('[data-reset-quiz]').forEach(button => button.addEventListener('click', () => {
    answered.clear();
    document.querySelectorAll('.option').forEach(b => { b.classList.remove('correct', 'incorrect'); b.setAttribute('aria-pressed', 'false'); });
    document.querySelectorAll('.feedback').forEach(f => { f.hidden = true; });
    updateScore(); toast('8 道自测题已重置');
  }));
  const decodeInput = document.getElementById('decode-input');
  const decodeOutput = document.getElementById('decode-output');
  document.querySelectorAll('[data-decode]').forEach(button => button.addEventListener('click', () => {
    const input = decodeInput.value.trim();
    try {
      let output;
      if (!input) throw new Error('empty');
      if (button.dataset.decode === 'base64') {
        const clean = input.replace(/\s/g, '');
        if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(clean)) throw new Error('base64');
        output = new TextDecoder('utf-8', { fatal: true }).decode(Uint8Array.from(atob(clean), c => c.charCodeAt(0)));
      } else if (button.dataset.decode === 'hex') {
        const clean = input.replace(/\s/g, '');
        if (clean.length % 2 || !/^[0-9a-f]+$/i.test(clean)) throw new Error('hex');
        output = new TextDecoder('utf-8', { fatal: true }).decode(Uint8Array.from(clean.match(/../g), h => parseInt(h, 16)));
      } else output = decodeURIComponent(input);
      decodeOutput.textContent = output;
    } catch (_) { decodeOutput.textContent = '解码失败：检查输入是否符合所选编码。本演示只把 UTF-8 文本作为输出。'; }
  }));
  document.querySelectorAll('[data-encoding-example]').forEach(button => button.addEventListener('click', () => { decodeInput.value = button.dataset.encodingExample; decodeOutput.textContent = '选择对应的解码方式。'; }));
  document.querySelectorAll('[data-timezone]').forEach(button => button.addEventListener('click', () => {
    document.querySelectorAll('[data-timezone]').forEach(b => b.setAttribute('aria-pressed', String(b === button)));
    document.querySelectorAll('[data-time-utc]').forEach(time => { time.textContent = button.dataset.timezone === 'utc' ? time.dataset.timeUtc : time.dataset.timeLocal; });
  }));
  const hashMatch = location.hash.match(/^#slide-(\d+)$/);
  renderOverview();
  goTo(hashMatch ? +hashMatch[1] - 1 : 0, false);
})();
