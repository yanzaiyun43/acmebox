/* acmebox 前端：四步签发流程加一个独立的续期入口，全部由本文件驱动。
 * 会话 ID 先取 state.session.id，再回退 sessionStorage；请求用 X-AcmeBox-Session 头带上，
 * 服务端启用访问令牌时还要 X-AcmeBox-Token（401 时才向用户要一次）。
 * 敏感输入只留在输入框；签发后服务端 60 秒就释放证书与私钥，导出内容因此临时缓存在
 * 内存（state.logPayload），刷新即消失。api() 抛出的错误带服务端原文，由调用点用 msg()
 * 就地显示，不做全局提示，也不改写措辞。
 */

(() => {
  'use strict';

  const SESSION_KEY = 'acmebox.session';
  const TOKEN_KEY = 'acmebox.token';
  // 使用须知每个浏览器只自动弹一次；隐私模式下 localStorage 写不进去，会每次刷新都弹
  const NOTICE_KEY = 'acmebox.notice.v1';

  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

  const state = {
    session: null,
    config: null,
    step: 1,
    busy: false,
    cert: null,
    logPayload: null,
  };

  /* ------------------------------------------------------------------ */
  /* 传输层：会话头、令牌、错误原文都在这里统一处理                      */
  /* ------------------------------------------------------------------ */

  function sessionId() {
    return state.session?.id || sessionStorage.getItem(SESSION_KEY) || null;
  }

  async function api(path, body) {
    const headers = { 'Content-Type': 'application/json' };
    const sid = sessionId();
    if (sid) headers['X-AcmeBox-Session'] = sid;
    const accessToken = sessionStorage.getItem(TOKEN_KEY);
    if (accessToken) headers['X-AcmeBox-Token'] = accessToken;

    let res;
    try {
      res = await fetch(path, {
        method: body === undefined ? 'GET' : 'POST',
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
      });
    } catch (err) {
      throw new Error('连不上本机服务，确认它还在运行');
    }

    // 服务端可以不带访问令牌启动，页面事先无从判断是否要令牌，所以被拒时再问一次；
    // 令牌只进 sessionStorage，刷新后还在，用户不必反复输入。
    if (res.status === 401) {
      const entered = window.prompt('这个服务需要访问令牌：');
      if (entered) {
        sessionStorage.setItem(TOKEN_KEY, entered.trim());
        return api(path, body);
      }
      throw new Error('缺少访问令牌');
    }

    let data = {};
    try {
      data = await res.json();
    } catch (_) {
      throw new Error(`服务返回了无法解析的响应（HTTP ${res.status}）`);
    }

    // 错误文案直接用服务端给的 error；detail 里是 ACME 的问题描述或校验错误数组，
    // 拼在换行后面，宁可长也不丢信息。
    if (!res.ok) {
      const detail = data.detail && !Array.isArray(data.detail)
        ? `\n${JSON.stringify(data.detail)}`
        : Array.isArray(data.detail) && data.detail.length
          ? `\n${data.detail.map((d) => d.message || JSON.stringify(d)).join('\n')}`
          : '';
      throw new Error((data.error || `请求失败（HTTP ${res.status}）`) + detail);
    }

    if (data.session) adoptSession(data.session);
    return data;
  }

  // 每个响应都可能顺带回最新的会话，统一在这里落内存和 sessionStorage，刷新后才能接着用。
  function adoptSession(sess) {
    state.session = sess;
    if (sess?.id) sessionStorage.setItem(SESSION_KEY, sess.id);
    renderChrome();
  }

  /* ------------------------------------------------------------------ */
  /* 小工具：消息位、状态标签、转义、按钮忙碌态、复制、下载、两个对话框     */
  /* ------------------------------------------------------------------ */

  // 每次写消息都重置 className，否则上一次的 ok/err 颜色会留在下一次的提示上。
  function msg(el, text, kind) {
    const node = typeof el === 'string' ? $(el) : el;
    if (!text) {
      node.hidden = true;
      node.textContent = '';
      node.className = 'msg';
      return;
    }
    node.hidden = false;
    node.className = `msg ${kind || 'info'}`;
    node.textContent = text;
  }

  function statusChip(text, kind) {
    return `<span class="status ${kind}">${esc(text)}</span>`;
  }

  // 全文件用 innerHTML 拼模板，域名、错误信息这些都是外部字符串，进去之前必须过这里。
  function esc(value) {
    return String(value ?? '').replace(/[&<>"']/g, (c) => (
      { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
    ));
  }

  // 原按钮文案暂存进 dataset.label：恢复时不能读 textContent，它已被「处理中」盖掉。
  function setBusy(button, on, label) {
    if (!button) return;
    if (on) {
      button.dataset.label = button.textContent;
      button.disabled = true;
      button.innerHTML = `<span class="spin"></span> ${esc(label || '处理中')}`;
    } else {
      button.disabled = false;
      button.textContent = button.dataset.label || button.textContent;
    }
  }

  // navigator.clipboard 只在安全上下文（https 或 localhost）可用，纯 http 或内嵌 WebView 下
  // 会缺失或直接抛错，退回 execCommand 才复制得动；1.2 秒后把按钮文案还原。
  async function copyText(text, button) {
    try {
      await navigator.clipboard.writeText(text);
    } catch (_) {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      ta.remove();
    }
    const old = button.textContent;
    button.textContent = '已复制';
    button.classList.add('copied');
    setTimeout(() => {
      button.textContent = old;
      button.classList.remove('copied');
    }, 1200);
  }

  // 立刻 revokeObjectURL 会让部分浏览器直接取消下载，所以留一秒缓冲。
  function download(name, text, type) {
    const blob = new Blob([text], { type: type || 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = name;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  function confirmDialog(title, text, okLabel) {
    return new Promise((resolve) => {
      const dlg = $('#confirmDlg');
      $('#dlgTitle').textContent = title;
      $('#dlgText').textContent = text;
      $('#dlgOk').textContent = okLabel || '确定';

      const finish = (value) => {
        dlg.close();
        $('#dlgOk').onclick = null;
        $('#dlgCancel').onclick = null;
        dlg.oncancel = null;
        dlg.onclick = null;
        resolve(value);
      };
      $('#dlgOk').onclick = () => finish(true);
      $('#dlgCancel').onclick = () => finish(false);
      // ESC 默认直接关闭对话框，不触发任何回调，Promise 就永远悬着；
      // 先 preventDefault，再自己走 finish(false)。
      dlg.oncancel = (e) => { e.preventDefault(); finish(false); };
      // 点遮罩也算取消，和 ESC 同一处理路径。
      dlg.onclick = (e) => { if (e.target === dlg) finish(false); };
      dlg.showModal();
    });
  }

  function keyDialog(title) {
    return new Promise((resolve) => {
      const dlg = $('#keyDlg');
      $('#keyDlgTitle').textContent = title;
      const input = $('#keyDlgInput');
      input.value = '';
      const finish = (value) => {
        dlg.close();
        $('#keyDlgOk').onclick = null;
        $('#keyDlgCancel').onclick = null;
        dlg.oncancel = null;
        resolve(value);
      };
      // 空白内容按取消处理，别把空字符串当私钥发出去。
      $('#keyDlgOk').onclick = () => finish(input.value.trim() || null);
      $('#keyDlgCancel').onclick = () => finish(null);
      dlg.oncancel = (e) => { e.preventDefault(); finish(null); };
      dlg.showModal();
      // 先打开再聚焦：对话框没显示时 focus() 不生效。
      input.focus();
    });
  }

  /* ------------------------------------------------------------------ */
  /* 导航：只切 .panel 的 on 类，不重建 DOM，所以表单里填的内容不会丢       */
  /* ------------------------------------------------------------------ */

  function go(step) {
    state.step = step;
    const stepsBar = $('#steps');
    $$('.panel').forEach((p) => p.classList.toggle('on', p.id === `p${step}`));
    $$('#steps button').forEach((b) => {
      // 续期那格不参与进度：既不算「已完成」，也不抢 aria-current。
      if (b.dataset.go === 'renew') {
        b.setAttribute('aria-current', 'false');
        b.classList.remove('done');
        return;
      }
      const target = Number(b.dataset.go);
      b.setAttribute('aria-current', target === step ? 'step' : 'false');
      b.classList.toggle('done', target < step);
    });
    // 步骤条靠 --step 平移指示块：五格等宽，传 0 基下标；改 CSS 布局时两边要一起改。
    if (stepsBar) stepsBar.style.setProperty('--step', String(step - 1));
    window.scrollTo({ top: 0, behavior: 'auto' });
  }

  /**
   * 续期是步骤条上的第五格，却不在线性流程里：进来时不能把前面四步标成已完成，
   * 也不用 state.step 记位置（那个值只给 1–4 步用）。
   */
  function openRenew() {
    $$('.panel').forEach((p) => p.classList.toggle('on', p.id === 'p5'));
    $$('#steps button').forEach((b) => {
      b.setAttribute('aria-current', b.dataset.go === 'renew' ? 'step' : 'false');
    });
    const stepsBar = $('#steps');
    if (stepsBar) stepsBar.style.setProperty('--step', '4');
    window.scrollTo({ top: 0, behavior: 'auto' });
    refreshRenewState();
  }

  /** data-go 里既有步骤号也有 'renew'，统一在这里分流 */
  function navigate(target) {
    if (target === 'renew') openRenew();
    else go(Number(target));
  }

  /* ------------------------------------------------------------------ */
  /* 顶部与状态文案：所有随会话变化的文字都在这里刷新                       */
  /* ------------------------------------------------------------------ */

  function renderChrome() {
    const sess = state.session;
    // 冷启动时还没有会话，但第一张卡片已经被选中；若只从会话推导，
    // 就会出现「卡片打着勾、标题却写着未选择服务」的矛盾，所以先看选中的单选框。
    const selected = $('#caCards input:checked')?.value || sess?.directory;
    const ca = state.config?.directories?.find((d) => d.url === selected);
    $('#barSub').textContent = ca ? ca.name : '未选择服务';

    const email = sess?.email;
    const chip = $('#barEmail');
    chip.hidden = !email;
    chip.textContent = email || '';
    chip.title = email || '';

    const caName = ca?.name || '';
    // 配置里没有「这个 CA 要不要 EAB」的字段，只能按显示名判；后端改名时这里会默默失效。
    $('#eabBox').hidden = !(caName === 'ZeroSSL' || caName === 'Google Trust Services');

    // 两把密钥的状态只看会话，不从表单反推：输入框里有内容不代表服务端真有一把密钥。
    const keyState = $('#keyState');
    if (sess?.cert_key_type) {
      const label = { RS256: 'RSA', ES256: 'ECC P-256', ES384: 'ECC P-384' }[sess.cert_key_type]
        || sess.cert_key_type;
      keyState.textContent = `已就绪：${label} 私钥在内存中。`;
    } else {
      keyState.textContent = '尚未生成。RSA 适用性最广；ECC 证书体积小、性能更好，但很老的客户端可能不认。';
    }

    const acctState = $('#acctState');
    if (sess?.account_thumbprint) {
      acctState.textContent = `账户已注册，指纹 ${sess.account_thumbprint.slice(0, 16)}…`;
    } else if (sess?.has_account_key) {
      acctState.textContent = '已生成账户私钥，点上面的按钮完成注册。';
    } else {
      acctState.textContent = '建议固定用一个账户私钥，多次续期时可以复用已有的验证结果。';
    }
  }

  // 只有 valid/pending 才翻译；其余状态（invalid、expired 等）原样显示，不替他猜。
  function renderAuthorizations(list) {
    const wrap = $('#authzList');
    wrap.innerHTML = (list || []).map((a) => `
      <div class="list-row">
        <span class="v">${esc(a.domain)}</span>
        ${statusChip(a.status === 'valid' ? '已验证' : a.status === 'pending' ? '待验证' : a.status,
          a.status === 'valid' ? 'ok' : a.status === 'pending' ? 'idle' : 'bad')}
      </div>`).join('');
  }

  function renderDnsPlans(plans) {
    const has = !!(plans && plans.length);
    // 没有记录时不能留一片空白：隐藏表格、说清下一步，并把验证按钮置灰。
    $('#dnsEmpty').hidden = has;
    $('#dnsOut').hidden = !has;
    $('#dnsHint').hidden = !has;
    $('#dnsNote2').hidden = !has;
    $('#btnVerify').disabled = !has;
    $('#dnsList').innerHTML = (plans || []).map((p) => `
      <div class="list-row">
        <span class="k">记录名</span>
        <span class="v">${esc(p.name)}</span>
      </div>
      ${p.values.map((v) => `
        <div class="list-row">
          <span class="k">TXT 值</span>
          <span class="v">${esc(v)}</span>
          <button type="button" class="ghost small" data-copyval="${esc(v)}">复制</button>
        </div>`).join('')}
    `).join('');
  }

  // 时间已由后端转成北京时间并格式化成字符串，这里只排版，不再算日期。
  function renderCert(data) {
    state.cert = data;
    const info = data.info;
    $('#certArea').hidden = false;
    $('#certInfo').innerHTML = `
      <div class="list-row"><span class="k">主体</span><span class="v">${esc(info.subject)}</span></div>
      <div class="list-row"><span class="k">域名</span><span class="v">${esc(info.domains.join(', '))}</span></div>
      <div class="list-row"><span class="k">签发者</span><span class="v">${esc(info.issuer)}</span></div>
      <div class="list-row"><span class="k">生效</span><span class="v">${esc(info.not_before)}<span style="color:var(--text-dim)"> 北京时间</span></span></div>
      <div class="list-row"><span class="k">到期</span><span class="v">${esc(info.not_after)}
        <span style="color:var(--text-dim)"> 北京时间</span>
        ${statusChip(`剩 ${info.days_left} 天`, info.days_left > 20 ? 'ok' : 'warn')}</span></div>
      <div class="list-row"><span class="k">证书链</span><span class="v">${esc(data.chain_length)} 段（含中间与根）</span></div>`;
    $('#certPem').textContent = data.certificate;
    $('#keyPem').textContent = data.private_key;
  }

  /* ------------------------------------------------------------------ */
  /* step 1：选 CA、填邮箱、准备两把私钥                                */
  /* ------------------------------------------------------------------ */

  function renderCaCards() {
    const box = $('#caCards');
    box.innerHTML = (state.config?.directories || []).map((d, i) => `
      <label class="card">
        <input type="radio" name="ca" value="${esc(d.url)}" ${i === 0 ? 'checked' : ''}>
        <span class="dot"></span>
        <span class="body">
          <span class="title">${esc(d.name)}</span>
          <span class="desc">${esc(d.note)}</span>
        </span>
      </label>`).join('');
  }

  // 刷新或恢复会话后把已有选择回填到卡片：不回填的话卡片会停在默认的第一项，
  // 和会话里真正的 CA 不一致，下次保存设置就把服务改掉了。
  async function initStep1() {
    const sess = state.session;
    if (sess) {
      const current = sess.directory;
      const radio = $$('#caCards input').find((r) => r.value === current);
      if (radio) radio.checked = true;
      if (sess.email) $('#email').value = sess.email;
      renderChrome();
    }
  }

  // EAB 两项成对提交：只填一半时后端会明确报错，比前端静静丢掉一半更容易发现填错。
  async function saveSettings() {
    const body = {
      directory: $('#caCards input:checked')?.value,
      email: $('#email').value.trim(),
    };
    const kid = $('#eabKid').value.trim();
    const key = $('#eabKey').value.trim();
    if (kid || key) {
      body.eab_kid = kid;
      body.eab_hmac_key = key;
    }
    return api('/api/session', body);
  }

  // 账户密钥生成后必须马上注册：CA 认下这个账户，第 2 步下单才不会因缺账户而失败。
  async function generateKey(kind, bits, which) {
    const out = await api('/api/key', { which, kind, bits });
    if (which === 'account') {
      const acct = await api('/api/account', {});
      msg('#m1', `账户已注册，指纹 ${acct.thumbprint.slice(0, 16)}…`, 'ok');
    } else {
      msg('#m1', `已生成 ${kind.toUpperCase()} 私钥（${out.algorithm}）。`, 'ok');
    }
    renderChrome();
  }

  /* ------------------------------------------------------------------ */
  /* step 2：下单前先存设置，后端用的是会话里的 CA 与邮箱                    */
  /* ------------------------------------------------------------------ */

  /** 新下单后上一张证书已不属于当前订单，先清掉第 4 步的展示与缓存，
   *  否则会看到旧证书，误以为这次已经签好。 */
  function clearCertView() {
    state.cert = null;
    const area = $('#certArea');
    if (area) area.hidden = true;
    const all = $('#allInfoOut');
    if (all) all.hidden = true;
    const m4 = $('#m4');
    if (m4) { m4.hidden = true; m4.textContent = ''; }
    const m4mem = $('#m4mem');
    if (m4mem) { m4mem.hidden = true; m4mem.textContent = ''; }
    const cp = $('#certPem');
    if (cp) cp.textContent = '';
    const kp = $('#keyPem');
    if (kp) kp.textContent = '';
  }

  async function createOrder() {
    const btn = $('#btnStep2');
    msg('#m2', '');
    const raw = $('#domains').value.trim();
    if (!raw) {
      msg('#m2', '请填写至少一个域名。', 'err');
      return;
    }
    setBusy(btn, true, '创建中');
    try {
      // 先存设置：后端下单读的是会话里的 CA 和邮箱，改了卡片没保存就会用旧配置签。
      await saveSettings();
      clearCertView();
      const data = await api('/api/order', { domains: raw });
      $('#orderOut').hidden = false;
      $('#orderStatus').className = `status ${data.status === 'pending' ? 'idle' : 'ok'}`;
      $('#orderStatus').textContent = data.status === 'pending' ? '待验证' : data.status;
      renderAuthorizations(data.authorizations);
      renderDnsPlans(data.dns_plans);
      if (data.warning) msg('#m2', data.warning, 'warn');
      go(3);
    } catch (err) {
      msg('#m2', err.message, 'err');
    } finally {
      setBusy(btn, false);
    }
  }

  /* ------------------------------------------------------------------ */
  /* step 3：把 TXT 记录交给用户自己去加，回来这里等 DNS 生效               */
  /* ------------------------------------------------------------------ */

  // timeout 是服务端轮询授权状态的上限：TXT 还没传播时会一直等到这里为止，
  // 所以结果要逐域名列错，让用户分得清是还没生效还是一开始就加错了。
  async function verify() {
    const btn = $('#btnVerify');
    setBusy(btn, true, '验证中');
    msg('#m3', '');
    try {
      const data = await api('/api/verify', { challenge_type: 'dns-01', timeout: 180 });
      const lines = data.authorizations.map((a) => {
        const mark = a.status === 'valid' ? '✓' : '✕';
        return `${mark} ${a.domain}${a.error ? `：${a.error}` : ''}`;
      }).join('\n');
      msg('#m3', lines, data.ok ? 'ok' : 'err');
      if (data.ok) {
        // 先把逐域名结果留在屏上，稍等一下再自动跳到第 4 步。
        setTimeout(() => go(4), 400);
      }
    } catch (err) {
      msg('#m3', err.message, 'err');
    } finally {
      setBusy(btn, false);
    }
  }

  /* ------------------------------------------------------------------ */
  /* step 4：签发、下载、导出全部信息                                     */
  /* ------------------------------------------------------------------ */

  async function finalize() {
    const btn = $('#btnFinalize');
    setBusy(btn, true, '签发中');
    msg('#m4', '');
    msg('#m4mem', '');
    try {
      const data = await api('/api/finalize', {});
      renderCert(data);
      // 签发 60 秒后服务端就释放证书与私钥，趁现在把「全部信息」取回内存，
      // 否则用户过一会儿再点下载只会拿到空结果。
      await cacheExport();
      msg('#m4', '证书已签发。请下载 cert.pem 与 key.pem，并保存记录文件以便续期。', 'ok');
      msg('#m4mem',
          '证书与私钥现在只在服务器内存里，没有写入磁盘。签发完成 60 秒后，'
          + '服务器会自动删除这份数据；请在这之前把下面的 cert.pem、key.pem '
          + '和「全部信息」存到本地，否则刷新页面就找不回来了。', 'warn');
    } catch (err) {
      msg('#m4', err.message, 'err');
    } finally {
      setBusy(btn, false);
    }
  }

  /** 趁会话还在把「全部信息」取回内存一份，服务端释放后仍可下载。 */
  async function cacheExport() {
    try {
      const data = stripInternal(await api('/api/log/export', {}));
      state.logPayload = data;
      state.logText = JSON.stringify(data, null, 2);
    } catch (_) { /* 缓存失败不影响签发结果，下载时再试一次 */ }
  }

  /** 去掉响应层统一附带的内部 session 字段：剩下的就是原样写进文件的 JSON。 */
  function stripInternal(payload) {
    const clean = { ...payload };
    delete clean.session;
    return clean;
  }

  // 通配符带不进文件名，先把开头的 * 换成 wildcard，免得系统拒绝。
  async function exportLog() {
    const data = state.logPayload || stripInternal(await api('/api/log/export', {}));
    state.logPayload = data;
    state.logText = JSON.stringify(data, null, 2);
    const host = (state.session?.domains?.[0] || 'certificate').replace(/^\*\./, 'wildcard.');
    download(`acmebox-${host}.json`, state.logText, 'application/json');
  }

  /** 在页面里直接看导出内容；缓存里已有就不再请求，会话被释放后也看得到。 */
  async function showAllInfo(btn) {
    setBusy(btn, true, '读取');
    try {
      const data = state.logPayload || stripInternal(await api('/api/log/export', {}));
      state.logPayload = data;
      state.logText = JSON.stringify(data, null, 2);
      $('#allInfoText').textContent = state.logText;
      $('#allInfoOut').hidden = false;
      $('#allInfoOut').scrollIntoView({ block: 'nearest', behavior: 'auto' });
      // 贴在预览区上方，紧挨着用户正在看的内容；放到页面顶部的通用消息位会被滑过去。
      const warnBox = $('#allInfoWarn');
      if (warnBox) {
        warnBox.hidden = !data.warning;
        warnBox.textContent = data.warning || '';
      }
    } catch (err) {
      msg('#m4', err.message, 'err');
    } finally {
      setBusy(btn, false);
    }
  }

  async function importLog(text) {
    let parsed;
    try {
      parsed = JSON.parse(text);
    } catch (_) {
      msg('#mrenew', '这个文件不是合法的 JSON。', 'err');
      return false;
    }
    // 导入会覆盖当前会话的设置、两把私钥和域名（已签出的证书不受影响），先让用户确认。
    const yes = await confirmDialog(
      '导入记录',
      '会用文件里的设置、私钥和域名覆盖当前会话。已经生成的证书不受影响。',
      '导入',
    );
    if (!yes) return false;
    try {
      await api('/api/log/import', { log: parsed });
      applySessionToForm();
      renderChrome();
      await refreshRenewState();
      msg('#mrenew', '记录已导入，配置和私钥都已恢复。', 'ok');
      return true;
    } catch (err) {
      msg('#mrenew', err.message, 'err');
      return false;
    }
  }

  /** 把会话里的设置回填到表单：导入、恢复会话后都得手动做一次，页面不会自己重绘输入框。 */
  function applySessionToForm() {
    const sess = state.session;
    if (!sess) return;
    if (sess.domains?.length) $('#domains').value = sess.domains.join(', ');
    const caRadio = $$('#caCards input').find((r) => r.value === sess.directory);
    if (caRadio) caRadio.checked = true;
    if (sess.email) $('#email').value = sess.email;
  }

  /* ------------------------------------------------------------------ */
  /* 续期：和四步流程共用第 3、4 步，数据来源可能是会话，也可能是刚选的记录文件 */
  /* ------------------------------------------------------------------ */

  /**
   * 续期不是另一种申请，而是带着旧凭据重跑一遍。
   * 关键是账户私钥要沿用：CA 认得它，同一账户的域名验证会保留（LE 为 30 天），
   * 期内免验证；换新账户则全部重验。
   */
  /** 把一份证书摘要画到「现有证书」：precheck 给会话里的，preview 给文件里的。
   * 用 from_file 区分文案——文件还没导入，写「当前证书」会误导。 */
  function paintRenewInfo(data) {
    const textEl = $('#renewText');
    if (!textEl) return;
    if (!data.has_certificate) {
      textEl.textContent = data.advice;
      textEl.style.color = 'var(--text-dim)';
      return;
    }
    const fromFile = !!data.from_file;
    const domains = (data.domains || []).join('、');
    const label = fromFile
      ? '记录文件里的证书（尚未导入）'
      : (data.renewing ? '上一张证书（续期进行中）' : '当前会话的证书');
    textEl.innerHTML =
      `<span style="color:var(--text-dim)">${label}</span><br>` +
      `${esc(domains)}<br>` +
      `到期：${esc(data.not_after || '—')} 北京时间（剩 ${esc(String(data.days_left))} 天）<br>` +
      `<span style="color:var(--${data.urgent ? 'warn' : 'ok'})">${esc(data.advice)}</span>`;
  }

  async function refreshRenewState() {
    const textEl = $('#renewText');
    const goBtn = $('#btnRenewGo');
    if (!textEl || !goBtn) return;

    // 预检失败就安静退出：这一步只是提示，不该占掉错误位，也不该挡住其他步骤。
    let data;
    try {
      data = await api('/api/renew/precheck', {});
    } catch (_) {
      return;
    }

    // 有证书就能续；没有证书时，只有会话已备好账户私钥才放开按钮（记录文件在点下去时才导入）。
    goBtn.disabled = data.has_certificate ? false : !state.session?.has_account_key;
    state.renewUrgent = data.has_certificate ? !!data.urgent : undefined;
    paintRenewInfo(data);
  }

  /**
   * 只读预览：还没导入也能看出是哪张证书、还剩几天。
   * 边粘边解析，文本不是完整 JSON 就直接返回、不报错——用户还在打字，报错只会刷屏。
   */
  async function previewLog(text) {
    const t = (text || '').trim();
    if (!t) {
      await refreshRenewState();
      return;
    }
    let parsed;
    try {
      parsed = JSON.parse(t);
    } catch (_) {
      return;
    }
    try {
      const data = await api('/api/log/preview', { log: parsed });
      paintRenewInfo(data);
      state.renewUrgent = data.has_certificate ? !!data.urgent : undefined;
      // 文件里有账户密钥就能直接续；点下去会先把这份记录导入
      $('#btnRenewGo').disabled = !data.has_account_key;
    } catch (err) {
      msg('#mrenew', err.message, 'err');
    }
  }

  /** 读文件内容：先填进粘贴框（让「导入」按钮可用），再走预览。 */
  async function loadLogFile(file) {
    const text = await file.text();
    const ta = $('#logPaste');
    if (ta) ta.value = text;
    await previewLog(text);
    msg('#mrenew', '已读取记录文件。可以直接点「一键续期」，或先「导入」再动手。', 'info');
  }

  /** 一键续期：沿用会话里的账户私钥重新下单；只在文件上预览过时，先把粘贴框里的记录导入。 */
  async function renewNow() {
    const btn = $('#btnRenewGo');
    msg('#mrenew', '');

    if (!(state.session?.domains || []).length) {
      const text = ($('#logPaste')?.value || '').trim();
      if (!text) {
        msg('#mrenew', '先选一个记录文件，或把内容粘进框里。', 'err');
        return;
      }
      const imported = await importLog(text);
      if (!imported) return;
      $('#logPaste').value = '';
    }
    // 还没到建议续期的时间也要让用户能续，但得提醒：会白耗一次 CA 的频率额度。
    if (state.renewUrgent === false) {
      const yes = await confirmDialog(
        '现在续期？',
        '现有证书还没到建议续期的时间。续期会立即签发一张新证书，'
        + '在 CA 有频率限制的情况下，短期内反复签可能被拒。',
        '仍然续期',
      );
      if (!yes) return;
    }
    setBusy(btn, true, '创建订单');
    try {
      const raw = (state.session?.domains || []).join(', ');
      if (!raw) throw new Error('记录文件里没有域名，无法续期');
      $('#domains').value = raw;
      clearCertView();
      const data = await api('/api/order', { domains: raw });
      renderAuthorizations(data.authorizations);
      renderDnsPlans(data.dns_plans);
      if (data.warning) msg('#m2', data.warning, 'warn');
      go(3);
      msg('#m3', '已用同一账户重新下单。同一账户的域名验证 CA 保留 30 天，期内不需重新验证；'
               + '若已过期或换了账户，下面会列出需要重新添加的 TXT 记录。', 'info');
    } catch (err) {
      msg('#mrenew', err.message, 'err');
    } finally {
      setBusy(btn, false);
    }
  }

  /* ------------------------------------------------------------------ */
  /* 事件绑定：脚本在 body 末尾加载，元素都已存在，直接绑即可（动态行用委托） */
  /* ------------------------------------------------------------------ */

  function wire() {
    // 切卡片时立即刷新顶部标题，不等保存：冷启动还没有会话，也要能显示当前选择。
    $('#caCards').addEventListener('change', () => renderChrome());

    $('#steps').addEventListener('click', (e) => {
      const btn = e.target.closest('button[data-go]');
      if (!btn || btn.disabled) return;
      navigate(btn.dataset.go);
    });

    $$('[data-go]').forEach((b) => {
      if (b.closest('#steps')) return;
      b.addEventListener('click', () => navigate(b.dataset.go));
    });

    $('#btnStep1').addEventListener('click', async () => {
      const btn = $('#btnStep1');
      msg('#m1', '');
      if (!$('#caCards input:checked')) {
        msg('#m1', '请选择一个证书颁发机构。', 'err');
        return;
      }
      if (!$('#email').value.trim()) {
        msg('#m1', '请填写联系邮箱。', 'err');
        $('#email').focus();
        return;
      }
      setBusy(btn, true, '保存中');
      try {
        await saveSettings();
        if (!state.session?.cert_key_type) {
          await generateKey('rsa', 2048, 'cert');
        }
        const acct = $('#acctState').textContent;
        if (!/已注册/.test(acct)) {
          // 顺手把账户注册掉：第 2 步下单就不必再等一次，也不会因缺账户而失败。
          try {
            await api('/api/account', {});
            msg('#m1', '服务已就绪：账户已注册，证书私钥在内存中。', 'ok');
          } catch (err) {
            msg('#m1', `私钥已就绪，但账户注册失败：${err.message}`, 'warn');
          }
        }
        renderChrome();
        go(2);
      } catch (err) {
        msg('#m1', err.message, 'err');
      } finally {
        setBusy(btn, false);
      }
    });

    $$('#keyRow [data-key]').forEach((b) => {
      b.addEventListener('click', async () => {
        // 按钮只带 data-key，后端要的 kind 和位数在这里映射，两边得一起改。
        const map = {
          rsa2048: ['rsa', 2048], rsa3072: ['rsa', 3072],
          ecc256: ['ecc', 256], ecc384: ['ecc', 384],
        };
        const [kind, bits] = map[b.dataset.key];
        setBusy(b, true);
        try {
          await generateKey(kind, bits, 'cert');
        } catch (err) {
          msg('#m1', err.message, 'err');
        } finally {
          setBusy(b, false);
        }
      });
    });

    $('#btnAcctKey').addEventListener('click', async () => {
      const btn = $('#btnAcctKey');
      setBusy(btn, true, '注册中');
      try {
        // 先存设置再生成：账户属于当前选中的 CA 目录，EAB 也按这个目录用。
        await saveSettings();
        await generateKey('rsa', 2048, 'account');
      } catch (err) {
        msg('#m1', err.message, 'err');
      } finally {
        setBusy(btn, false);
      }
    });

    $('#btnImportKey').addEventListener('click', async () => {
      const pem = await keyDialog('手动填写证书私钥');
      if (!pem) return;
      try {
        await api('/api/key/import', { which: 'cert', pem });
        msg('#m1', '证书私钥已导入。', 'ok');
        renderChrome();
      } catch (err) {
        msg('#m1', err.message, 'err');
      }
    });

    $('#btnImportAcct').addEventListener('click', async () => {
      const pem = await keyDialog('导入账户私钥');
      if (!pem) return;
      try {
        // 只导入私钥 CA 还不认；注册一次，后面的下单才能复用旧账户和已验证结果。
        await api('/api/key/import', { which: 'account', pem });
        await api('/api/account', {});
        msg('#m1', '账户私钥已导入并注册。', 'ok');
        renderChrome();
      } catch (err) {
        msg('#m1', err.message, 'err');
      }
    });

    $('#btnStep2').addEventListener('click', createOrder);
    $('#btnVerify').addEventListener('click', verify);
    $('#btnFinalize').addEventListener('click', finalize);

    $('#btnShowAll').addEventListener('click', (e) => showAllInfo(e.currentTarget));

    $('#btnPasteImport').addEventListener('click', async (e) => {
      const btn = e.currentTarget;
      const text = $('#logPaste').value.trim();
      if (!text) {
        msg('#mrenew', '还没有粘贴内容。', 'err');
        return;
      }
      setBusy(btn, true, '导入');
      try {
        const done = await importLog(text);
        // 导入成功后清空粘贴框，避免同一份记录被重复提交覆盖当前会话。
        if (done) $('#logPaste').value = '';
      } finally {
        setBusy(btn, false);
      }
    });

    // 边粘边看：不导入也能先确认是哪张证书。防抖 600ms，避免每敲一个字就打一次后端。
    let previewTimer = null;
    $('#logPaste').addEventListener('input', () => {
      clearTimeout(previewTimer);
      previewTimer = setTimeout(() => previewLog($('#logPaste').value), 600);
    });
    $('#btnRenewGo').addEventListener('click', renewNow);

    // 事件委托：TXT 行和复制/下载按钮都是按需重绘的，逐行绑监听会在重绘后失效。
    document.addEventListener('click', (e) => {
      const copyBtn = e.target.closest('[data-copyval]');
      if (copyBtn) {
        copyText(copyBtn.dataset.copyval, copyBtn);
        return;
      }
      const c = e.target.closest('[data-copy]');
      if (c) {
        const el = $(`#${c.dataset.copy}`);
        if (el) copyText(el.textContent, c);
        return;
      }
      const d = e.target.closest('[data-dl]');
      if (d) {
        const host = (state.session?.domains?.[0] || 'certificate').replace(/^\*\./, 'wildcard.');
        if (d.dataset.dl === 'cert') download(`${host}.pem`, $('#certPem').textContent);
        if (d.dataset.dl === 'key') download(`${host}.key`, $('#keyPem').textContent);
        if (d.dataset.dl === 'log') exportLog().catch((err) => msg('#m4', err.message, 'err'));
      }
    });

    const drop = $('#logDrop');
    const fileInput = $('#logFile');

    /**
     * 有些内嵌浏览器（应用内的 WebView）压根不实现文件选择器，input.click() 没有任
     * 何反应，用户会以为页面坏了；这里点完看一眼是否真的弹出了选择器，没弹就自动
     * 展开粘贴入口并说明原因。
     *
     * 判断不能看 click 事件有没有派发：WebView 会把事件正常派发到 input 上，只是
     * 不弹窗，监听 click 必然误判成功。能区分的信号是页面失焦——真正的系统选择器
     * 弹出时 document 会触发 visibilitychange 或 blur，两者都没发生就是被拦了。
     */
    const openPicker = () => {
      // 先展开粘贴入口：某些环境里 input.click() 会同步阻塞，之后就没有代码能执行，
      // 只能先把这条可用的路铺好。
      const wrap = $('#pasteWrap');
      if (wrap) wrap.open = true;

      let leftPage = false;
      const markLeft = () => { leftPage = true; };
      window.addEventListener('blur', markLeft, { once: true });
      document.addEventListener('visibilitychange', markLeft, { once: true });

      try {
        fileInput.click();
      } catch (_) { /* 少数环境直接抛错 */ }

      setTimeout(() => {
        window.removeEventListener('blur', markLeft);
        document.removeEventListener('visibilitychange', markLeft);
        if (!leftPage) {
          const ta = $('#logPaste');
          if (ta) ta.focus({ preventScroll: true });
          msg('#mrenew',
              '这个浏览器没有打开文件选择器（常见于应用内置的网页视图）。'
              + '把 .json 内容粘进下面展开的框里即可。', 'warn');
        }
      }, 700);
    };

    drop.addEventListener('click', openPicker);
    drop.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); openPicker(); }
    });
    fileInput.addEventListener('change', async () => {
      const file = fileInput.files?.[0];
      if (file) await loadLogFile(file);
      // 清空 value，同一个文件才可能再次触发 change。
      fileInput.value = '';
    });
    // 不 preventDefault 的话，浏览器会直接用拖进来的文件替换整个页面，填的内容全丢。
    ['dragenter', 'dragover'].forEach((ev) => drop.addEventListener(ev, (e) => {
      e.preventDefault();
      drop.classList.add('over');
    }));
    ['dragleave', 'drop'].forEach((ev) => drop.addEventListener(ev, (e) => {
      e.preventDefault();
      drop.classList.remove('over');
    }));
    drop.addEventListener('drop', async (e) => {
      const file = e.dataTransfer?.files?.[0];
      if (file) await loadLogFile(file);
    });
  }

  /* ------------------------------------------------------------------ */
  /* 启动：先绑事件再取配置，配置拉不到也能打开使用须知                     */
  /* ------------------------------------------------------------------ */

  function openNotice() {
    const dlg = $('#noticeDlg');
    if (!dlg) return;
    // 老 WebView 没有 dialog.showModal，退化成加 open 属性（此时没有遮罩和 ESC 处理）。
    if (typeof dlg.showModal === 'function') dlg.showModal();
    else dlg.setAttribute('open', '');
  }

  /** 首次使用时自动弹一次；关掉后记在本地，不再打扰。 */
  function maybeNotice() {
    let seen = null;
    try { seen = localStorage.getItem(NOTICE_KEY); } catch (_) { /* 隐私模式可能禁用 */ }
    if (!seen) openNotice();
  }

  function wireNotice() {
    $('#btnNotice').addEventListener('click', openNotice);
    const dlg = $('#noticeDlg');
    const remember = () => {
      try { localStorage.setItem(NOTICE_KEY, String(Date.now())); } catch (_) { /* 忽略 */ }
    };
    $('#noticeOk').addEventListener('click', () => { remember(); dlg.close(); });
    // close 里也记一次：ESC、点遮罩关掉都不会走按钮的 click，只靠 close 才能不漏。
    dlg.addEventListener('close', remember);
    // 点遮罩外部也关；此时同样记成已读，否则下次刷新还会再弹一遍。
    dlg.addEventListener('click', (e) => {
      if (e.target === dlg) { remember(); dlg.close(); }
    });
  }

  async function boot() {
    wire();
    wireNotice();
    maybeNotice();
    try {
      state.config = await api('/api/config');
    } catch (err) {
      msg('#m1', err.message, 'err');
      return;
    }
    renderCaCards();

    // 刷新后接着用本地记着的会话；服务端已经不认（404）就丢掉 id，
    // 否则每次刷新都会先报一次错。
    if (sessionStorage.getItem(SESSION_KEY)) {
      try {
        const data = await api('/api/session');
        if (data.session) {
          adoptSession(data.session);
          applySessionToForm();
          if (data.session.plans?.length) renderDnsPlans(data.session.plans);
        } else {
          sessionStorage.removeItem(SESSION_KEY);
        }
      } catch (_) {
        sessionStorage.removeItem(SESSION_KEY);
      }
    }
    // 卡片建好之后才能回填选中项，顺序反了会找不到单选框。
    await initStep1();
    // 会话里带着上次的 TXT 记录，刷回来后第 3 步不该变回空白。
    renderDnsPlans(state.session?.plans || []);
    renderChrome();
    await refreshRenewState();
    go(1);
  }

  document.addEventListener('DOMContentLoaded', boot);
})();
