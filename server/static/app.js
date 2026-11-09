(function () {
  'use strict';

  var TOKEN_KEY = 'remotemgr_token';
  var PROTO_LABEL = {rdp: 'RDP', radmin: 'Radmin', ssh: 'SSH', realvnc: 'RealVNC',
                     tightvnc: 'TightVNC', ftp: 'FTP / FlashFXP',
                     web: 'Web (HTTP/HTTPS)', winscp: 'WinSCP (SFTP/FTP)'};
  var PROTO_PORT = {rdp: 3389, radmin: 4899, ssh: 22, realvnc: 5900, tightvnc: 5900,
                    ftp: 21, web: 443, winscp: 22};
  // FlashFXP Quick Connect URL prefixes; the port follows the chosen scheme.
  var SCHEME_PORT = {ftp: {ftp: 21, ftps: 990, ftpes: 21, sftp: 22},
                     web: {https: 443, http: 80},
                     winscp: {sftp: 22, scp: 22, ftp: 21, ftps: 990,
                              webdav: 80, webdavs: 443}};
  var OPTION_ENUMS = {
    ftp_scheme: {valid: ['ftp', 'ftps', 'ftpes', 'sftp'], fallback: 'ftp'},
    ftp_auth: {valid: ['password', 'anonymous'], fallback: 'password'},
    ftp_window: {valid: ['normal', 'max', 'min', 'tray'], fallback: 'normal'},
    web_scheme: {valid: ['https', 'http'], fallback: 'https'},
    web_auth: {valid: ['none', 'basic'], fallback: 'none'},
    winscp_scheme: {valid: ['sftp', 'scp', 'ftp', 'ftps', 'webdav', 'webdavs'],
                    fallback: 'sftp'},
    winscp_auth: {valid: ['password', 'anonymous'], fallback: 'password'},
    winscp_window: {valid: ['normal', 'min', 'new'], fallback: 'normal'}
  };
  var state = {token: localStorage.getItem(TOKEN_KEY) || '', user: null, groups: [],
               hosts: [], selected: 0, online: {}, settings: {}, keyword: ''};

  var $ = function (sel) { return document.querySelector(sel); };
  var esc = function (value) {
    return String(value == null ? '' : value).replace(/[&<>"']/g, function (ch) {
      return {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[ch];
    });
  };
  var canWrite = function () { return state.user && state.user.role !== 'viewer'; };
  var isAdmin = function () { return state.user && state.user.role === 'admin'; };

  function setStatus(text) { $('#status').textContent = text; }
  function toast(message, isError) {
    var el = $('#toast');
    el.textContent = message;
    el.className = 'toast' + (isError ? ' error' : '');
    clearTimeout(el._timer);
    el._timer = setTimeout(function () { el.classList.add('hidden'); }, 3200);
  }

  async function api(path, options) {
    options = options || {};
    var headers = {'Content-Type': 'application/json'};
    if (state.token) headers['Authorization'] = 'Bearer ' + state.token;
    var response;
    try {
      response = await fetch(path, {
        method: options.method || 'GET', headers: headers,
        body: options.body ? JSON.stringify(options.body) : undefined
      });
    } catch (err) {
      throw new Error('无法连接服务端：' + err.message);
    }
    var payload;
    try { payload = await response.json(); } catch (err) { throw new Error('服务端返回格式异常'); }
    if (!response.ok || payload.ok === false) {
      if (response.status === 401) { logout(false); }
      throw new Error(payload.error || ('HTTP ' + response.status));
    }
    return payload.data;
  }

  // ------------------------------------------------------------------ auth
  function showApp() {
    $('#login').classList.add('hidden');
    $('#app').classList.remove('hidden');
    $('#who').textContent = state.user.username + ' · ' + state.user.role;
    Promise.all([loadGroups(), loadSettings(), loadHosts(), loadHealth()]).catch(function (e) {
      toast(e.message, true);
    });
  }

  async function loadHealth() {
    try {
      var info = await api('/api/health');
      $('#dbInfo').textContent = '数据库：' + info.database + ' · 服务端 ' + info.time;
    } catch (e) { /* status bar is optional */ }
  }

  function logout(redirect) {
    state.token = ''; state.user = null;
    localStorage.removeItem(TOKEN_KEY);
    if (redirect !== false) {
      $('#app').classList.add('hidden');
      $('#login').classList.remove('hidden');
    }
  }

  $('#loginForm').addEventListener('submit', async function (event) {
    event.preventDefault();
    $('#loginError').textContent = '';
    try {
      var data = await api('/api/login', {method: 'POST', body: {
        username: $('#loginUser').value.trim(), password: $('#loginPass').value}});
      state.token = data.token; state.user = data.user;
      localStorage.setItem(TOKEN_KEY, data.token);
      $('#loginPass').value = '';
      showApp();
    } catch (err) { $('#loginError').textContent = err.message; }
  });

  // ------------------------------------------------------------------ data
  async function loadGroups() {
    state.groups = await api('/api/groups');
    renderTree();
  }
  async function loadSettings() { state.settings = await api('/api/settings'); }
  async function loadHosts() {
    var params = new URLSearchParams();
    if (state.selected) { params.set('group_id', state.selected); params.set('include_desc', '1'); }
    if (state.keyword) params.set('q', state.keyword);
    var result = await api('/api/hosts?' + params.toString());
    state.hosts = result;
    $('#count').textContent = '共 ' + result.length + ' 台主机';
    renderHosts();
    setStatus('已加载 ' + result.length + ' 台主机');
  }
  function refresh() { return Promise.all([loadGroups(), loadHosts()]); }

  function renderTree() {
    var byParent = {};
    state.groups.forEach(function (g) {
      (byParent[g.parent_id] = byParent[g.parent_id] || []).push(g);
    });
    var html = '<div class="tree-node' + (state.selected === 0 ? ' active' : '') +
      '" data-group="0" data-drop="0">全部主机</div>';
    var guard = 0;
    function walk(parentId, depth) {
      if (guard++ > 2000) return '';
      var list = byParent[parentId] || [];
      return list.map(function (group) {
        var pad = Math.min(depth, 8) * 14;
        return '<div class="tree-node' + (state.selected === group.id ? ' active' : '') +
          '" data-group="' + group.id + '" data-drop="' + group.id + '" style="padding-left:' + (8 + pad) + 'px">' +
          '<span class="caret">' + ((byParent[group.id] || []).length ? '▾' : '·') + '</span>' +
          esc(group.name) + '</div>' + walk(group.id, depth + 1);
      }).join('');
    }
    html += walk(0, 0);
    $('#tree').innerHTML = html;
  }

  function stateCell(host) {
    var value = state.online[host.id];
    if (value === true) return '<span class="state on">● 在线</span>';
    if (value === false) return '<span class="state off">○ 离线</span>';
    return '<span class="state">—</span>';
  }

  function renderHosts() {
    hideHostTip();   // data may have changed; force the card to rebuild
    var rows = state.hosts.map(function (host) {
      var protocolClass = host.protocol.indexOf('vnc') >= 0 ? 'vnc' : host.protocol;
      return '<tr draggable="true" data-host="' + host.id + '">' +
        '<td><span class="tag ' + protocolClass + '">' + esc(PROTO_LABEL[host.protocol] || host.protocol) + '</span></td>' +
        '<td>' + esc(host.name) + '</td>' +
        '<td class="mono">' + esc(host.address) + '</td>' +
        '<td class="mono">' + host.port + '</td>' +
        '<td>' + esc(host.account) + (host.has_password ? ' <span class="state">*</span>' : '') + '</td>' +
        '<td>' + stateCell(host) + '</td>' +
        '<td class="note-cell" title="' + esc(host.note) + '">' + esc(host.note) + '</td>' +
        '<td><div class="row-actions">' +
          '<button class="btn sm" data-act="connect" data-id="' + host.id + '">连接</button>' +
          '<button class="btn sm" data-act="cmd" data-id="' + host.id + '">命令</button>' +
          '<button class="btn sm" data-act="host-edit" data-id="' + host.id + '">编辑</button>' +
          '<button class="btn sm" data-act="wol" data-id="' + host.id + '">唤醒</button>' +
          '<button class="btn sm danger-text" data-act="host-del" data-id="' + host.id + '">删除</button>' +
        '</div></td></tr>';
    }).join('');
    $('#hostRows').innerHTML = rows;
    $('#empty').classList.toggle('hidden', state.hosts.length > 0);
  }

  function findHost(id) { return state.hosts.find(function (h) { return h.id === Number(id); }); }

  // ------------------------------------------------- hover connection-parameter card
  // Rendered lazily from the host object itself (never a data- attribute), so
  // names, notes and SSH templates stay escaped and cannot inject markup.
  var tipVisibleFor = null;

  function tipPair(pairs, value, fallback) {
    var hit = pairs.find(function (p) { return String(p[0]) === String(value); });
    return hit ? hit[1] : (fallback || String(value == null || value === '' ? '—' : value));
  }
  function tipRow(key, value) {
    return '<div class="tip-k">' + esc(key) + '</div><div class="tip-v">' + esc(value) + '</div>';
  }
  function tipSection(title) { return '<div class="tip-sec">' + esc(title) + '</div>'; }
  function tipOnOff(value) {
    return (value === true || String(value) === '1') ? '开' : '关';
  }

  function tipEffective(host) {
    var s = state.settings || {}, o = host.options || {};
    var eff = {};
    // Mirror the Agent's _effective_settings(): start from the global legacy
    // values, then let ONLY the keys present in this record override them.
    // A partially configured record (e.g. Radmin display+control but no
    // colour) must not silently pick up the Add/Edit form's defaults.
    if (host.protocol === 'rdp') {
      eff.rdp_resolution = String(s.rdp_fullscreen || '1') === '1' ? 'fullscreen' :
        (s.rdp_width || '1024') + 'x' + (s.rdp_height || '768');
      eff.rdp_color = s.rdp_color || '32';
      eff.rdp_wallpaper = String(s.rdp_wallpaper || '0') === '1';
      eff.rdp_drives = String(s.rdp_drives || '0') === '1';
      eff.rdp_audio = String(s.rdp_audio || '0') === '1';
    } else if (host.protocol === 'radmin') {
      eff.radmin_display = String(s.radmin_fullscreen || '1') === '1' ? 'fullscreen' : 'window';
      eff.radmin_ctrl = ['full', 'view', 'file', 'shutdown'][Number(s.radmin_ctrl_mode) || 0] || 'full';
      eff.radmin_color = s.radmin_color || '24';
    } else if (host.protocol === 'ssh') {
      eff.ssh_param_format = s.ssh_param_format || '';
      eff.ssh_auth = 'password';
      eff.ssh_key_path = '';
    } else if (host.protocol === 'ftp') {
      eff.ftp_scheme = 'ftp'; eff.ftp_auth = 'password'; eff.ftp_path = '';
      eff.ftp_local_path = ''; eff.ftp_window = 'normal'; eff.ftp_param_format = '';
    } else if (host.protocol === 'web') {
      eff.web_scheme = 'https'; eff.web_auth = 'none'; eff.web_path = '';
      eff.web_param_format = '';
    } else if (host.protocol === 'winscp') {
      eff.winscp_scheme = 'sftp'; eff.winscp_auth = 'password'; eff.winscp_dir = '';
      eff.winscp_window = 'normal'; eff.winscp_param_format = '';
    }
    Object.keys(o).forEach(function (k) { eff[k] = o[k]; });
    if (host.protocol === 'ftp' || host.protocol === 'web' ||
        host.protocol === 'winscp') {
      // Mirror the server / Agent whitelist so the hover card never shows a
      // value that would actually be discarded at connect time.
      Object.keys(OPTION_ENUMS).forEach(function (k) {
        if (k in eff && OPTION_ENUMS[k].valid.indexOf(eff[k]) < 0) eff[k] = OPTION_ENUMS[k].fallback;
      });
      ['ftp_path', 'web_path', 'winscp_dir', 'ftp_local_path'].forEach(function (k) {
        if (k in eff) eff[k] = String(eff[k] || '')
          .replace(/[\x00-\x1f\x7f"']/g, '').trim().slice(0, 512);
      });
      ['ftp_param_format', 'web_param_format', 'winscp_param_format'].forEach(function (k) {
        if (k in eff) {
          var raw = String(eff[k] || '').replace(/[\x00-\x1f\x7f]/g, '').trim().slice(0, 512);
          eff[k] = raw.indexOf('%5') >= 0 ? raw : '';
        }
      });
    }
    if (host.protocol === 'ssh') {
      // Mirror the Agent's whitelist: only known auth modes, no control
      // characters in a path, and a template without %1 is discarded.
      if (eff.ssh_auth !== 'key' && eff.ssh_auth !== 'password') eff.ssh_auth = 'password';
      eff.ssh_key_path = String(eff.ssh_key_path || '')
        .replace(/[\x00-\x1f\x7f]/g, '').trim().slice(0, 512);
      if ('ssh_param_format' in o) {
        var raw = String(o.ssh_param_format || '')
          .replace(/[\x00-\x1f]/g, '').trim().slice(0, 512);
        eff.ssh_param_format = raw.indexOf('%1') >= 0 ? raw : '';
      }
    }
    var expected = {
      rdp: ['rdp_resolution', 'rdp_color', 'rdp_wallpaper', 'rdp_drives', 'rdp_audio'],
      radmin: ['radmin_display', 'radmin_ctrl', 'radmin_color'],
      ssh: ['ssh_auth', 'ssh_key_path', 'ssh_param_format'],
      ftp: ['ftp_scheme', 'ftp_auth', 'ftp_path', 'ftp_local_path',
            'ftp_window', 'ftp_param_format'],
      web: ['web_scheme', 'web_auth', 'web_path', 'web_param_format'],
      winscp: ['winscp_scheme', 'winscp_auth', 'winscp_dir',
               'winscp_window', 'winscp_param_format']
    }[host.protocol] || [];
    var complete = expected.length > 0 &&
      expected.every(function (k) { return k in o; });
    return {
      eff: eff,
      source: complete ? '本条记录' : (Object.keys(o).length ? '记录 + 默认值' : 'Agent 兼容默认值')
    };
  }

  function tipTarget(host) {
    var address = host.address, port = host.port;
    if (host.protocol === 'realvnc' || host.protocol === 'tightvnc' || host.protocol === 'ssh') {
      return address + ':' + port;
    }
    return port === PROTO_PORT[host.protocol] ? address : address + ':' + port;
  }

  // Split a full http(s) URL pasted into the host-address field. Kept as a
  // plain regex parser (no URL class) so it behaves identically in old
  // browsers and in the DOM-stub tests. Everything after the netloc is kept
  // verbatim: a SPA hash route must stay a fragment.
  function parseWebUrl(address) {
    var m = /^(https?):\/\/([^/?#]*)([^?#]*)(?:\?([^#]*))?(?:#(.*))?$/i
      .exec(String(address || '').trim());
    if (!m) return null;
    var scheme = m[1].toLowerCase();
    var netloc = m[2], at = netloc.lastIndexOf('@');
    var userinfo = at >= 0 ? netloc.slice(0, at + 1) : '';
    var hostpart = at >= 0 ? netloc.slice(at + 1) : netloc;
    var hostname = hostpart, portText = '';
    if (hostpart.charAt(0) === '[') {
      var close = hostpart.indexOf(']');
      if (close < 0) return null;
      hostname = hostpart.slice(1, close);
      if (hostpart.charAt(close + 1) === ':') portText = hostpart.slice(close + 2);
    } else {
      var colon = hostpart.lastIndexOf(':');
      if (colon >= 0) {
        hostname = hostpart.slice(0, colon);
        portText = hostpart.slice(colon + 1);
      }
    }
    if (!hostname) return null;
    return {
      scheme: scheme, hostname: hostname, hostpart: hostpart,
      userinfo: userinfo, path: m[3] || '/', query: m[4] || '',
      fragment: m[5] || '',
      port: Number(portText) || (scheme === 'http' ? 80 : 443)
    };
  }

  // The URL the local Agent will hand to FlashFXP / the browser. Passwords are
  // masked: the hover card (and the copy-command helper) are never allowed to
  // render a credential, even though the Agent receives the real one.
  function tipUrl(host, eff) {
    var proto = host.protocol;
    var isFtp = proto === 'ftp';
    var isWin = proto === 'winscp';
    // A full URL in the address field is authoritative: no re-assembly.
    if (proto === 'web') {
      var page = parseWebUrl(host.address);
      if (page) {
        var pagePrefix = page.userinfo;
        if (!pagePrefix && eff.web_auth === 'basic') {
          var pageUser = String(host.account || '');
          if (pageUser || host.has_password) {
            pagePrefix = encodeURIComponent(pageUser) +
              (host.has_password ? ':******' : '') + '@';
          }
        }
        return page.scheme + '://' + pagePrefix + page.hostpart + page.path +
          (page.query ? '?' + page.query : '') +
          (page.fragment ? '#' + page.fragment : '');
      }
    }
    var key = isFtp ? 'ftp_scheme' : (isWin ? 'winscp_scheme' : 'web_scheme');
    var scheme = OPTION_ENUMS[key].valid.indexOf(eff[key]) >= 0 ?
      eff[key] : OPTION_ENUMS[key].fallback;
    var port = Number(host.port) || PROTO_PORT[proto];
    var defaults = SCHEME_PORT[proto] || {};
    var address = String(host.address || '');
    if (address.indexOf(':') >= 0 && address.indexOf('[') < 0) address = '[' + address + ']';
    var netloc = address + (port === (defaults[scheme] || port) ? '' : ':' + port);
    var showCred = isFtp ? eff.ftp_auth !== 'anonymous' :
      (isWin ? eff.winscp_auth !== 'anonymous' : eff.web_auth === 'basic');
    var user = String(host.account || '');
    var prefix = '';
    if (isWin && !showCred) {
      // WinSCP anonymous: the Agent synthesizes anonymous:anonymous so the
      // Login dialog does not pop up (the stored password is never sent).
      prefix = encodeURIComponent(user || 'anonymous') + ':anonymous@';
    } else if (showCred && (user || host.has_password)) {
      prefix = encodeURIComponent(user) + (host.has_password ? ':******' : '') + '@';
    }
    var rawPath = String((isFtp ? eff.ftp_path :
      (isWin ? eff.winscp_dir : eff.web_path)) || '').replace(/^\/+/, '');
    // Keep ?query and #fragment as real URL parts (a SPA route such as
    // static/#/proxies/tcp must not become %23/proxies/tcp).
    var frag = null, query = null;
    var hashAt = rawPath.indexOf('#');
    if (hashAt >= 0) {
      frag = rawPath.slice(hashAt + 1);
      rawPath = rawPath.slice(0, hashAt);
    }
    var qAt = rawPath.indexOf('?');
    if (qAt >= 0) {
      query = rawPath.slice(qAt + 1);
      rawPath = rawPath.slice(0, qAt);
    }
    // Match the Agent's percent-encoding so the preview shows the real URL.
    var tail = scheme + '://' + prefix + netloc + '/' + encodeURI(rawPath);
    if (query !== null) tail += '?' + encodeURI(query);
    if (frag !== null) tail += '#' + encodeURI(frag);
    return tail;
  }

  function tipTemplateArgv(fmt, exe, host, eff, url, path) {
    // One single pass: chained replace() would re-scan a URL already inserted
    // for %5 and mangle percent-encoded characters such as %20 / %40.
    var map = {'%0': exe, '%1': host.address, '%2': String(host.port),
               '%3': String(host.account || ''), '%4': '******',
               '%5': url, '%6': path};
    var argv = fmt.trim().split(/\s+/).map(function (t) {
      return t.replace(/%[0-6]/g, function (m) {
        return map[m] === undefined ? m : map[m];
      });
    });
    var first = argv[0] || '';
    if (first === exe || /^(flashfxp|browser|winscp|chrome|msedge|firefox)(\.exe|\.com)?$/i.test(first)) {
      argv[0] = exe;
    }
    return argv.join(' ');
  }

  function tipCommand(host, eff) {
    var address = host.address, port = host.port, account = host.account || '';
    if (host.protocol === 'rdp') {
      return 'mstsc.exe <临时 .rdp>  ← 本机 Agent 生成，8 秒后自动删除';
    }
    if (host.protocol === 'radmin') {
      var modes = {full: '', view: '/noinput', file: '/file',
                   telnet: '/telnet', shutdown: '/shutdown'};
      var argv = ['radmin.exe', '/connect:' + tipTarget(host)];
      var mode = modes[eff.radmin_ctrl];
      if (mode) argv.push(mode);
      argv.push('/' + (eff.radmin_color || '24') + 'bpp');
      if (eff.radmin_display === 'fullscreen') argv.push('/fullscreen');
      return argv.join(' ');
    }
    if (host.protocol === 'ssh') {
      var auth = eff.ssh_auth === 'key' ? 'key' : 'password';
      // A key stored in the server database is materialised by the Agent as
      // a temporary file, so %5 / -i is still present in the real command.
      var keyPath = String(eff.ssh_key_path || '') ||
        (host.has_ssh_key ? '<Agent 临时私钥文件>' : '');
      var hasPwd = !!host.has_password;
      var fmt = String(eff.ssh_param_format || '').replace(/[\x00-\x1f]/g, '').trim();
      // Same rules as the Agent: a key login never sends -pw, and an empty
      // password / missing key file drops its switch instead of emitting "".
      if (fmt && fmt.indexOf('%1') >= 0) {
        if (auth === 'key' || !hasPwd) fmt = fmt.replace(/(^|\s)-pw\s+%4\b/g, ' ');
        if (!keyPath) fmt = fmt.replace(/(^|\s)-i\s+%5\b/g, ' ');
        var argv = fmt.trim().split(/\s+/);
        argv = argv.map(function (t) {
          return t.replace(/%1/g, address).replace(/%2/g, String(port))
                  .replace(/%3/g, account).replace(/%4/g, '******')
                  .replace(/%5/g, keyPath);
        }).filter(function (t) { return t !== ''; });
        var usedKeyPlaceholder = fmt.indexOf('%5') >= 0;
        if (auth === 'key' && keyPath && !usedKeyPlaceholder &&
            argv.indexOf('-i') < 0) {
          argv.splice(1, 0, '-i', keyPath);
        }
        return argv.join(' ');
      }
      var base = ['putty.exe', '-ssh'];
      if (account) base.push('-l', account);
      if (auth === 'key' && keyPath) base.push('-i', keyPath);
      else if (auth === 'password' && hasPwd) base.push('-pw', '******');
      base.push('-P', String(port), address);
      return base.join(' ');
    }
    if (host.protocol === 'ftp') {
      var ftpUrl = tipUrl(host, eff);
      var ftpExe = String((state.settings || {}).flashfxp_path || 'flashfxp.exe').trim();
      var ftpFmt = String(eff.ftp_param_format || '');
      if (ftpFmt.indexOf('%5') >= 0) {
        return tipTemplateArgv(ftpFmt, ftpExe, host, eff, ftpUrl,
          String(eff.ftp_path || ''));
      }
      var ftpArgv = [ftpExe];
      if (eff.ftp_window !== 'normal') ftpArgv.push('-' + eff.ftp_window);
      ftpArgv.push('"' + ftpUrl + '"');
      if (eff.ftp_local_path) ftpArgv.push('-localpath="' + eff.ftp_local_path + '"');
      return ftpArgv.join(' ');
    }
    if (host.protocol === 'winscp') {
      var winUrl = tipUrl(host, eff);
      var winExe = String((state.settings || {}).winscp_path || 'WinSCP.exe').trim();
      var winFmt = String(eff.winscp_param_format || '');
      if (winFmt.indexOf('%5') >= 0) {
        return tipTemplateArgv(winFmt, winExe, host, eff, winUrl,
          String(eff.winscp_dir || ''));
      }
      var winArgv = [winExe];
      if (eff.winscp_window === 'min') winArgv.push('/minimized');
      if (eff.winscp_window === 'new') winArgv.push('/newinstance');
      winArgv.push('"' + winUrl + '"');
      return winArgv.join(' ');
    }
    if (host.protocol === 'web') {
      var webUrl = tipUrl(host, eff);
      var browser = String((state.settings || {}).browser_path || '').trim();
      var webFmt = String(eff.web_param_format || '');
      if (webFmt.indexOf('%5') >= 0) {
        // %1 / %2 are the host and port, never the pasted URL string.
        var page = parseWebUrl(host.address);
        var previewHost = page ? {address: page.hostname, port: page.port,
                                  account: host.account} : host;
        return tipTemplateArgv(webFmt, browser || '<浏览器路径>',
          previewHost, eff, webUrl, '');
      }
      return (browser ? browser + ' ' : '系统默认浏览器打开 ') + '"' + webUrl + '"';
    }
    return 'vncviewer ' + tipTarget(host) +
      (host.protocol === 'tightvnc' ? ' -password=******' : '');
  }

  function tipRdpLines(host, eff) {
    var s = state.settings || {};
    var full = eff.rdp_resolution === 'fullscreen';
    var size = String(eff.rdp_resolution || 'fullscreen').split('x');
    var width = full ? (s.rdp_width || '1024') : size[0];
    var height = full ? (s.rdp_height || '768') : (size[1] || '768');
    return [
      'screen mode id:i:' + (full ? '2' : '1'),
      'desktopwidth:i:' + width,
      'desktopheight:i:' + height,
      'session bpp:i:' + (eff.rdp_color || '32'),
      'disable wallpaper:i:' + (tipOnOff(eff.rdp_wallpaper) === '开' ? '0' : '1'),
      'drivestoredirect:s:' + (eff.rdp_drives ? '*' : ''),
      'audiomode:i:' + (eff.rdp_audio ? '0' : '2')
    ].join('\n');
  }

  function hostTipHtml(host) {
    var resolved = tipEffective(host), eff = resolved.eff;
    var group = state.groups.find(function (g) { return g.id === host.group_id; });
    var tagClass = host.protocol.indexOf('vnc') >= 0 ? 'vnc' : host.protocol;
    var sshKey = eff.ssh_auth === 'key';
    var passwordText;
    if (sshKey) passwordText = '密钥对登录 · 不传密码';
    else if (host.protocol === 'ftp' && eff.ftp_auth === 'anonymous')
      passwordText = '匿名登录 · 不传密码';
    else if (host.protocol === 'winscp' && eff.winscp_auth === 'anonymous')
      passwordText = '匿名登录 · 不传密码';
    else if (host.protocol === 'web' && eff.web_auth !== 'basic')
      passwordText = '不用于连接 · 由网站登录页填写';
    else if (host.has_password)
      passwordText = host.protocol === 'web' ? '已保存 · URL Basic 认证' : '已保存 · Agent 自动填写';
    else passwordText = '未保存 · 连接时手输';
    var html = '<div class="tip-head"><b>' + esc(host.name) + '</b>' +
      '<span class="tag ' + tagClass + '">' + esc(PROTO_LABEL[host.protocol] || host.protocol) + '</span></div>' +
      '<div class="tip-grid">' +
      tipRow('连接目标', (host.protocol === 'web' || host.protocol === 'ftp' ||
        host.protocol === 'winscp') ?
        tipUrl(host, eff) : host.address + ':' + host.port) +
      tipRow('账号', host.account || '—') +
      tipRow('密码', passwordText) +
      tipRow('所属分组', group ? group.name : '未分组') +
      (host.mac ? tipRow('MAC', host.mac) : '') +
      '</div>' +
      tipSection('连接参数 · ' + resolved.source) +
      '<div class="tip-grid">';
    if (host.protocol === 'rdp') {
      html += tipRow('分辨率', tipPair(RDP_RESOLUTION_OPTIONS, eff.rdp_resolution, eff.rdp_resolution)) +
        tipRow('色深', eff.rdp_color + ' 位') +
        tipRow('桌面背景', tipOnOff(eff.rdp_wallpaper)) +
        tipRow('挂载磁盘', tipOnOff(eff.rdp_drives)) +
        tipRow('远程音频', tipOnOff(eff.rdp_audio));
    } else if (host.protocol === 'radmin') {
      html += tipRow('连接方式', eff.radmin_display === 'fullscreen' ? '全屏' : '窗口') +
        tipRow('控制方式', tipPair(RADMIN_CONTROL_OPTIONS, eff.radmin_ctrl, eff.radmin_ctrl)) +
        tipRow('控制颜色', tipPair(RADMIN_COLOR_OPTIONS, eff.radmin_color, eff.radmin_color));
    } else if (host.protocol === 'ssh') {
      var fmtText = eff.ssh_param_format || '（留空 · Agent 自动拼接）';
      if (sshKey && String(eff.ssh_param_format).indexOf('-pw') >= 0) {
        fmtText += ' · 密钥登录时 -pw 会被忽略';
      }
      var keySource = '未指定 · 由 Pageant / ssh-agent 或客户端交互提供';
      if (host.has_ssh_key) {
        keySource = '服务端数据库（AES-GCM 加密）· ' +
          (host.ssh_key_filename || 'private_key');
      } else if (eff.ssh_key_path) {
        keySource = 'Agent 本机路径：' + eff.ssh_key_path;
      }
      html += tipRow('认证方式', sshKey ? '密钥对（私钥 / -i）' : '密码') +
        (sshKey ? tipRow('私钥来源', keySource) : '') +
        tipRow('参数格式', fmtText);
    } else if (host.protocol === 'ftp') {
      html += tipRow('连接协议', tipPair(FTP_SCHEME_OPTIONS, eff.ftp_scheme, eff.ftp_scheme)) +
        tipRow('登录方式', tipPair(FTP_AUTH_OPTIONS, eff.ftp_auth, eff.ftp_auth)) +
        tipRow('远程路径', eff.ftp_path || '/（根目录）') +
        tipRow('本地路径', eff.ftp_local_path || '不指定') +
        tipRow('启动方式', tipPair(FTP_WINDOW_OPTIONS, eff.ftp_window, eff.ftp_window)) +
        tipRow('参数格式', eff.ftp_param_format || '（留空 · Agent 自动拼接）');
    } else if (host.protocol === 'web') {
      var fullPage = parseWebUrl(host.address);
      if (fullPage) {
        html += tipRow('地址模式', '地址栏完整 URL · 以下三项以 URL 为准') +
          tipRow('URL 协议 / 端口', fullPage.scheme + ' / ' + fullPage.port) +
          tipRow('URL 路径', fullPage.path +
            (fullPage.query ? '?' + fullPage.query : '') +
            (fullPage.fragment ? '#' + fullPage.fragment : '')) +
          tipRow('认证方式', tipPair(WEB_AUTH_OPTIONS, eff.web_auth, eff.web_auth)) +
          tipRow('参数格式', eff.web_param_format || '（留空 · 系统默认浏览器）');
      } else {
        html += tipRow('页面协议', tipPair(WEB_SCHEME_OPTIONS, eff.web_scheme, eff.web_scheme)) +
          tipRow('认证方式', tipPair(WEB_AUTH_OPTIONS, eff.web_auth, eff.web_auth)) +
          tipRow('URL 路径', eff.web_path || '/（根路径）') +
          tipRow('参数格式', eff.web_param_format || '（留空 · 系统默认浏览器）');
      }
    } else if (host.protocol === 'winscp') {
      html += tipRow('连接协议', tipPair(WINSCP_SCHEME_OPTIONS, eff.winscp_scheme, eff.winscp_scheme)) +
        tipRow('登录方式', tipPair(WINSCP_AUTH_OPTIONS, eff.winscp_auth, eff.winscp_auth)) +
        tipRow('远程初始目录', eff.winscp_dir || '/（登录默认）') +
        tipRow('启动方式', tipPair(WINSCP_WINDOW_OPTIONS, eff.winscp_window, eff.winscp_window)) +
        tipRow('参数格式', eff.winscp_param_format || '（留空 · Agent 自动拼接）');
    } else {
      html += tipRow('客户端', 'VNC Viewer') + tipRow('目标', tipTarget(host));
    }
    html += '</div>' + tipSection('本机 Agent 实际参数') +
      '<pre class="tip-pre">' + esc(tipCommand(host, eff)) + '</pre>';
    if (host.protocol === 'rdp') {
      html += '<pre class="tip-pre">' + esc(tipRdpLines(host, eff)) + '</pre>';
    }
    if (host.note) html += '<div class="tip-note">备注：' + esc(host.note) + '</div>';
    var foot;
    if (sshKey) {
      foot = host.has_ssh_key ?
        '私钥密文存服务端，连接时由一次性票据下发到本机 Agent 并落地为临时文件，用完删除' :
        '私钥只留在本机；带口令的私钥请先用 Pageant / ssh-agent 加载';
    } else if (host.protocol === 'web' && eff.web_auth === 'basic') {
      foot = 'Basic 认证会把账号密码写进 URL，可能留在浏览器历史里；优先用网站自带登录页';
    } else if (host.protocol === 'ftp') {
      foot = '账号密码会出现在 FlashFXP 命令行参数里，同机其他进程可能看到';
    } else if (host.protocol === 'winscp') {
      foot = '账号密码会出现在 WinSCP 命令行 URL 里，同机其他进程可能看到；' +
        '匿名登录自动用 anonymous，不传保存的密码';
    } else if (host.protocol === 'web') {
      foot = 'Web 记录默认不向 Agent 下发密码，由网站登录页自行输入';
    } else {
      foot = '密码一律隐藏；未单独配置的项由 Agent 默认值兜底';
    }
    return html + '<div class="tip-foot">' + foot + '</div>';
  }

  function hideHostTip() {
    var tip = $('#hostTip');
    if (tip) tip.classList.add('hidden');
    tipVisibleFor = null;
  }
  function positionHostTip(x, y) {
    var tip = $('#hostTip');
    if (!tip) return;
    var w = tip.offsetWidth || 320, h = tip.offsetHeight || 260;
    var vw = window.innerWidth || 1280, vh = window.innerHeight || 800;
    var left = x + 16, top = y + 16;
    if (left + w > vw - 10) left = Math.max(10, x - w - 16);
    if (top + h > vh - 10) top = Math.max(10, y - h - 16);
    tip.style.left = left + 'px';
    tip.style.top = top + 'px';
  }
  function showHostTip(host, x, y) {
    var tip = $('#hostTip');
    if (!tip) return;
    if (tipVisibleFor !== host.id) {
      tip.innerHTML = hostTipHtml(host);
      tipVisibleFor = host.id;
    }
    tip.classList.remove('hidden');
    positionHostTip(x, y);
  }

  // ------------------------------------------------------------------ modal
  function showModal(title, html, wide) {
    $('#modalTitle').textContent = title;
    $('#modalBody').innerHTML = html;
    $('#modal').classList.toggle('wide', !!wide);
    $('#modal').classList.remove('hidden');
    return $('#modalBody');
  }
  function hideModal() {
    $('#modal').classList.add('hidden');
    $('#modal').classList.remove('wide');
  }
  $('#modalClose').addEventListener('click', hideModal);
  $('#modal').addEventListener('click', function (e) { if (e.target === $('#modal')) hideModal(); });

  function groupOptions(selected) {
    return '<option value="0">（未分组）</option>' + state.groups.map(function (g) {
      return '<option value="' + g.id + '"' + (Number(selected) === g.id ? ' selected' : '') + '>' +
        esc(g.name) + '</option>';
    }).join('');
  }

  var RDP_RESOLUTION_OPTIONS = [
    ['fullscreen', '全屏（跟随本机分辨率）'], ['800x600', '800 × 600'],
    ['1024x768', '1024 × 768'], ['1280x720', '1280 × 720'],
    ['1366x768', '1366 × 768'], ['1600x900', '1600 × 900'],
    ['1920x1080', '1920 × 1080'], ['1920x1200', '1920 × 1200'],
    ['2560x1440', '2560 × 1440']
  ];
  var RADMIN_CONTROL_OPTIONS = [
    ['full', '完全控制'], ['view', '仅限查看'], ['file', '文件传送'],
    ['telnet', '命令行连接'], ['shutdown', '远程关机（原版）']
  ];
  var RADMIN_COLOR_OPTIONS = [['8', '8 位'], ['16', '16 位'], ['24', '24 位']];
  var SSH_FORMAT_HELP = '%1 = 主机地址，%2 = 端口，%3 = 用户名，%4 = 密码，%5 = 私钥文件路径' +
    '（数据库里的私钥会由 Agent 落地为临时文件）；必须包含 %1。密钥对登录时不会传 %4，' +
    '模板没写 %5 时 Agent 会自动补 -i 私钥。留空则由 Agent 自动拼接 PuTTY / ssh 参数。';
  var SSH_AUTH_OPTIONS = [['password', '密码登录'], ['key', '密钥对登录（私钥）']];
  var FTP_SCHEME_OPTIONS = [['ftp', 'FTP（21）'], ['ftps', 'FTPS 隐式 SSL（990）'],
                            ['ftpes', 'FTPES 显式 TLS（21）'], ['sftp', 'SFTP over SSH（22）']];
  var FTP_AUTH_OPTIONS = [['password', '账号 + 密码'], ['anonymous', '匿名登录（不传密码）']];
  var FTP_WINDOW_OPTIONS = [['normal', '默认窗口'], ['max', '最大化（-max）'],
                            ['min', '最小化（-min）'], ['tray', '系统托盘（-tray）']];
  var WEB_SCHEME_OPTIONS = [['https', 'HTTPS（443）'], ['http', 'HTTP（80）']];
  var WEB_AUTH_OPTIONS = [['none', '不传密码（推荐）'], ['basic', 'URL 内嵌 Basic 认证']];
  var WINSCP_SCHEME_OPTIONS = [['sftp', 'SFTP over SSH（22）'], ['scp', 'SCP（22）'],
                               ['ftp', 'FTP（21）'], ['ftps', 'FTPS 隐式 SSL（990）'],
                               ['webdav', 'WebDAV（80）'], ['webdavs', 'WebDAVS（443）']];
  var WINSCP_AUTH_OPTIONS = [['password', '账号 + 密码'],
    ['anonymous', '匿名登录（自动 anonymous，不传密码）']];
  var WINSCP_WINDOW_OPTIONS = [['normal', '默认窗口'], ['min', '最小化（/minimized）'],
                               ['new', '新实例（/newinstance）']];
  var WINSCP_FORMAT_HELP = '%0 = WinSCP 路径，%1 = 主机地址，%2 = 端口，%3 = 账号，' +
    '%4 = 密码，%5 = 完整会话 URL，%6 = 远程初始目录；必须包含 %5。' +
    '留空则由 Agent 自动拼 URL 与 /minimized /newinstance 开关。' +
    '密钥登录可在模板里加 /privatekey="…ppk"。';
  var FTP_FORMAT_HELP = '%0 = FlashFXP 路径，%1 = 主机地址，%2 = 端口，%3 = 账号，' +
    '%4 = 密码，%5 = 完整连接 URL，%6 = 远程路径；必须包含 %5。' +
    '留空则由 Agent 自动拼 URL、启动方式开关与 -localpath。';
  var WEB_FORMAT_HELP = '%0 = 浏览器路径，%1 = 主机名，%2 = 端口，%3 = 账号，' +
    '%4 = 密码，%5 = 完整 URL（含 ?参数 与 #锚点）；必须包含 %5。' +
    '地址栏填完整 URL 时，%1 / %2 取 URL 里的主机名与端口。' +
    '使用自定义参数（如 --incognito）前，请先在「系统设置 → 客户端程序路径」' +
    '指定浏览器路径；留空则用系统默认浏览器打开。';
  var HOST_OPTION_DEFAULTS = {
    rdp: {rdp_resolution: 'fullscreen', rdp_color: '32', rdp_wallpaper: false,
          rdp_drives: false, rdp_audio: false},
    radmin: {radmin_display: 'fullscreen', radmin_ctrl: 'full', radmin_color: '24'},
    ssh: {ssh_auth: 'password', ssh_key_path: '', ssh_param_format: ''},
    ftp: {ftp_scheme: 'ftp', ftp_auth: 'password', ftp_path: '',
          ftp_local_path: '', ftp_window: 'normal', ftp_param_format: ''},
    web: {web_scheme: 'https', web_auth: 'none', web_path: '', web_param_format: ''},
    winscp: {winscp_scheme: 'sftp', winscp_auth: 'password', winscp_dir: '',
             winscp_window: 'normal', winscp_param_format: ''}
  };
  function optionSelect(id, label, pairs, value) {
    return '<label>' + label + '<select id="' + id + '">' + pairs.map(function (p) {
      return '<option value="' + p[0] + '"' +
        (String(value) === p[0] ? ' selected' : '') + '>' + esc(p[1]) + '</option>';
    }).join('') + '</select></label>';
  }
  function optionCheck(id, label, checked) {
    return '<label class="opt-check"><input type="checkbox" id="' + id + '"' +
      (checked ? ' checked' : '') + '> ' + label + '</label>';
  }
  function hostForm(host) {
    var isEdit = !!host;
    host = host || {protocol: 'rdp', port: 3389, group_id: state.selected || 0};
    var cur = {};
    var defaults = HOST_OPTION_DEFAULTS[host.protocol] || {};
    Object.keys(defaults).forEach(function (k) { cur[k] = defaults[k]; });
    Object.keys(host.options || {}).forEach(function (k) { cur[k] = host.options[k]; });
    var protoOpts = Object.keys(PROTO_LABEL).map(function (key) {
      return '<option value="' + key + '"' + (host.protocol === key ? ' selected' : '') + '>' +
        PROTO_LABEL[key] + '</option>';
    }).join('');
    var body = showModal(isEdit ? '编辑主机 · ' + host.name : '新增主机',
      '<div class="form-grid">' +
      '<label>主机名称<input id="f_name" value="' + esc(host.name || '') + '" maxlength="64"></label>' +
      '<label>连接类型<select id="f_protocol">' + protoOpts + '</select></label>' +
      '<label><span class="field-caption" id="f_address_caption">主机地址</span>' +
        '<input id="f_address" value="' + esc(host.address || '') + '" maxlength="512"></label>' +
      '<label><span class="field-caption" id="f_port_caption">端口</span>' +
        '<input id="f_port" type="number" min="1" max="65535" value="' + host.port + '"></label>' +
      '<label>账号<input id="f_account" value="' + esc(host.account || '') + '" maxlength="64"></label>' +
      '<label>密码<input id="f_password" type="password" placeholder="' +
        (isEdit ? '留空表示不修改' : '可留空') + '" autocomplete="new-password"></label>' +
      '<label>MAC（网络唤醒用）<input id="f_mac" value="' + esc(host.mac || '') +
        '" placeholder="AA:BB:CC:DD:EE:FF"></label>' +
      '<label>所属分组<select id="f_group">' + groupOptions(host.group_id) + '</select></label>' +
      '<label class="full">备注<textarea id="f_note" maxlength="512">' + esc(host.note || '') + '</textarea></label>' +
      (isEdit ? '<div class="full" style="display:flex;gap:6px;align-items:center">' +
        '<input type="checkbox" id="f_clear" style="width:auto"> <span>清空已保存的密码</span></div>' : '') +
      '</div>' +
      '<div class="opt-section hidden" id="sec_rdp_title">RDP 设置</div>' +
      '<div class="form-grid hidden" id="sec_rdp">' +
      optionSelect('f_rdp_resolution', '分辨率', RDP_RESOLUTION_OPTIONS, cur.rdp_resolution) +
      optionSelect('f_rdp_color', '色深', [['16', '16 位'], ['24', '24 位'], ['32', '32 位']], cur.rdp_color) +
      '<div class="full opt-checks">' +
      optionCheck('f_rdp_wallpaper', '显示桌面背景', cur.rdp_wallpaper) +
      optionCheck('f_rdp_drives', '挂载本地磁盘', cur.rdp_drives) +
      optionCheck('f_rdp_audio', '连接远程音频', cur.rdp_audio) +
      '</div></div>' +
      '<div class="opt-section hidden" id="sec_radmin_title">Radmin 设置</div>' +
      '<div class="form-grid hidden" id="sec_radmin">' +
      optionSelect('f_radmin_display', '连接方式', [['fullscreen', '全屏'], ['window', '窗口']], cur.radmin_display) +
      optionSelect('f_radmin_ctrl', '控制方式', RADMIN_CONTROL_OPTIONS, cur.radmin_ctrl) +
      optionSelect('f_radmin_color', '控制颜色', RADMIN_COLOR_OPTIONS, cur.radmin_color) +
      '</div>' +
      '<div class="opt-section hidden" id="sec_ssh_title">SSH 设置</div>' +
      '<div class="form-grid hidden" id="sec_ssh">' +
      optionSelect('f_ssh_auth', '认证方式', SSH_AUTH_OPTIONS, cur.ssh_auth || 'password') +
      '<div class="full hidden key-db" id="row_ssh_key_db">' +
        '<div class="key-db-title">私钥内容 · 加密存入服务端数据库（换机器也能用）</div>' +
        '<div class="key-db-status">' +
          '<span id="f_ssh_key_state" class="path-state ' + (host.has_ssh_key ? 'ok' : '') + '">' +
          (host.has_ssh_key ? '已保存：' + esc(host.ssh_key_filename || 'private_key') +
            ' · 指纹 ' + esc(host.ssh_key_fingerprint || '') : '未保存私钥') + '</span>' +
          '<input type="file" id="f_ssh_key_file" accept=".ppk,.pem,.key,.txt">' +
          '<button type="button" class="btn sm" id="f_ssh_key_clear">清除已保存私钥</button>' +
        '</div>' +
        '<textarea id="f_ssh_key_content" class="path-input mono" spellcheck="false" ' +
          'placeholder="也可直接粘贴 OpenSSH PEM / PuTTY .ppk 私钥内容（留空表示不改动）"></textarea>' +
      '</div>' +
      '<div class="hint full hidden" id="ssh_key_db_hint">私钥经 AES-256-GCM 加密后写入数据库，' +
        '主密钥只存放在服务端本机；连接时由一次性票据下发给本机 Agent，落地为权限收紧的临时文件，' +
        '用完自动删除。带口令的私钥仍需客户端弹窗输入口令。</div>' +
      '<label class="full hidden" id="row_ssh_key">或：私钥文件（运行 Agent 那台机器上的 .ppk / .pem 路径，不上传）' +
        '<span class="key-pick"><input id="f_ssh_key_path" class="path-input mono" ' +
        'spellcheck="false" placeholder="留空则由数据库私钥 / Pageant / ssh-agent 提供密钥" value="' +
        esc(cur.ssh_key_path || '') + '">' +
        '<button type="button" class="btn sm" data-browse="ssh_key_path">浏览…</button></span></label>' +
      '<div class="hint full hidden" id="ssh_key_hint">数据库里的私钥优先；若未保存，' +
        '则使用这里的本机路径，两者都为空时由 Pageant / ssh-agent 提供密钥。</div>' +
      '<label class="full">软件命令行参数格式' +
        '<span class="input-with-help"><input id="f_ssh_param_format" value="' +
        esc(cur.ssh_param_format || '') + '" placeholder="留空则自动拼接 PuTTY / ssh 参数">' +
        '<button type="button" class="help-dot" data-help="ssh_fmt" title="参数说明">?</button>' +
        '</span></label>' +
      '<div class="hint full hidden" id="ssh_fmt_help">' + SSH_FORMAT_HELP + '</div>' +
      '</div>' +
      '<div class="opt-section hidden" id="sec_ftp_title">FTP / FlashFXP 设置</div>' +
      '<div class="form-grid hidden" id="sec_ftp">' +
      optionSelect('f_ftp_scheme', '连接协议', FTP_SCHEME_OPTIONS, cur.ftp_scheme) +
      optionSelect('f_ftp_auth', '登录方式', FTP_AUTH_OPTIONS, cur.ftp_auth) +
      optionSelect('f_ftp_window', '启动方式', FTP_WINDOW_OPTIONS, cur.ftp_window) +
      '<label class="full">远程初始路径（登录后进入的目录）' +
        '<input id="f_ftp_path" class="mono" spellcheck="false" ' +
        'placeholder="留空为 FTP 根目录，例如 pub/files" value="' + esc(cur.ftp_path || '') + '"></label>' +
      '<label class="full">本地初始路径（运行 Agent 那台机器上的目录）' +
        '<input id="f_ftp_local_path" class="path-input mono" spellcheck="false" ' +
        'placeholder="留空则不指定，例如 D:\\Downloads" value="' +
        esc(cur.ftp_local_path || '') + '"></label>' +
      '<label class="full">命令行参数格式（可选）' +
        '<span class="input-with-help"><input id="f_ftp_param_format" class="mono" value="' +
        esc(cur.ftp_param_format || '') + '" placeholder="留空则自动拼接 flashfxp.exe &quot;ftp://…&quot;">' +
        '<button type="button" class="help-dot" data-help="ftp_fmt" title="参数说明">?</button>' +
        '</span></label>' +
      '<div class="hint full hidden" id="ftp_fmt_help">' + FTP_FORMAT_HELP + '</div>' +
      '</div>' +
      '<div class="opt-section hidden" id="sec_web_title">Web（HTTP / HTTPS）设置</div>' +
      '<div class="form-grid hidden" id="sec_web">' +
      '<div class="hint full">「主机地址」可以直接粘贴完整 URL（含 http(s)://、端口、路径、?参数、#锚点），' +
        '此时下面的「页面协议」「端口」「URL 路径」都不参与拼接，以 URL 原文为准；' +
        '只填主机名 / IP 时才按这些字段拼接。</div>' +
      optionSelect('f_web_scheme', '页面协议（仅填主机名时生效）', WEB_SCHEME_OPTIONS, cur.web_scheme) +
      optionSelect('f_web_auth', '认证方式', WEB_AUTH_OPTIONS, cur.web_auth) +
      '<label class="full">URL 路径（仅填主机名时生效）' +
        '<input id="f_web_path" class="mono" spellcheck="false" ' +
        'placeholder="留空为 /，例如 admin/login?tab=1#/node/2" value="' +
        esc(cur.web_path || '') + '"></label>' +
      '<label class="full">浏览器命令行参数格式（可选）' +
        '<span class="input-with-help"><input id="f_web_param_format" class="mono" value="' +
        esc(cur.web_param_format || '') + '" placeholder="留空则用系统默认浏览器直接打开">' +
        '<button type="button" class="help-dot" data-help="web_fmt" title="参数说明">?</button>' +
        '</span></label>' +
      '<div class="hint full hidden" id="web_fmt_help">' + WEB_FORMAT_HELP + '</div>' +
      '<div class="hint full">浏览器路径在「系统设置 → 客户端程序路径」里配置；' +
        '留空则用系统默认浏览器。密码默认不下发，选 Basic 认证才会写进 URL。</div>' +
      '</div>' +
      '<div class="opt-section hidden" id="sec_winscp_title">WinSCP 设置</div>' +
      '<div class="form-grid hidden" id="sec_winscp">' +
      optionSelect('f_winscp_scheme', '连接协议', WINSCP_SCHEME_OPTIONS, cur.winscp_scheme) +
      optionSelect('f_winscp_auth', '登录方式', WINSCP_AUTH_OPTIONS, cur.winscp_auth) +
      optionSelect('f_winscp_window', '启动方式', WINSCP_WINDOW_OPTIONS, cur.winscp_window) +
      '<label class="full">远程初始目录（登录后进入的目录）' +
        '<input id="f_winscp_dir" class="mono" spellcheck="false" ' +
        'placeholder="留空为登录默认目录，例如 /home/user/www" value="' +
        esc(cur.winscp_dir || '') + '"></label>' +
      '<label class="full">命令行参数格式（可选）' +
        '<span class="input-with-help"><input id="f_winscp_param_format" class="mono" value="' +
        esc(cur.winscp_param_format || '') + '" placeholder="留空则自动拼接 WinSCP.exe &quot;sftp://…&quot;">' +
        '<button type="button" class="help-dot" data-help="winscp_fmt" title="参数说明">?</button>' +
        '</span></label>' +
      '<div class="hint full hidden" id="winscp_fmt_help">' + WINSCP_FORMAT_HELP + '</div>' +
      '<div class="hint full">WinSCP 路径在「系统设置 → 客户端程序路径」里配置；' +
        '选 SFTP / FTPS 时端口会自动跟着变。匿名登录自动用 anonymous 凭据，' +
        '保存的密码不会传给客户端。</div>' +
      '</div>' +
      '<div class="hint" id="opt_hint"></div>' +
      '<div class="hint">密码与 SSH 私钥均经 AES-256-GCM 加密后才写入数据库；' +
        '明文只在连接时按需取出并记入审计日志。</div>' +
      '<div class="modal-foot"><button class="btn" data-role="cancel">取消</button>' +
      '<button class="btn primary" data-role="save">保存</button></div>');
    var oldProtocol = host.protocol;
    function toggleOptionSections(proto) {
      ['sec_rdp_title', 'sec_rdp'].forEach(function (id) {
        body.querySelector('#' + id).classList.toggle('hidden', proto !== 'rdp');
      });
      ['sec_radmin_title', 'sec_radmin'].forEach(function (id) {
        body.querySelector('#' + id).classList.toggle('hidden', proto !== 'radmin');
      });
      ['sec_ssh_title', 'sec_ssh'].forEach(function (id) {
        body.querySelector('#' + id).classList.toggle('hidden', proto !== 'ssh');
      });
      ['sec_ftp_title', 'sec_ftp'].forEach(function (id) {
        body.querySelector('#' + id).classList.toggle('hidden', proto !== 'ftp');
      });
      ['sec_web_title', 'sec_web'].forEach(function (id) {
        body.querySelector('#' + id).classList.toggle('hidden', proto !== 'web');
      });
      ['sec_winscp_title', 'sec_winscp'].forEach(function (id) {
        body.querySelector('#' + id).classList.toggle('hidden', proto !== 'winscp');
      });
      body.querySelector('#f_address_caption').textContent =
        proto === 'web' ? '页面 URL（可粘贴完整地址）' : '主机地址';
      body.querySelector('#f_address').placeholder = proto === 'web' ?
        'http://192.168.1.10:6443/static/#/proxies/tcp 或只填主机名' : '';
      body.querySelector('#f_port_caption').textContent =
        proto === 'web' ? '端口（完整 URL 时不生效）' : '端口';
      var useKey = body.querySelector('#f_ssh_auth').value === 'key';
      ['row_ssh_key', 'ssh_key_hint', 'row_ssh_key_db', 'ssh_key_db_hint'].forEach(function (id) {
        body.querySelector('#' + id).classList.toggle('hidden', proto !== 'ssh' || !useKey);
      });
      body.querySelector('#opt_hint').textContent =
        proto === 'rdp' ? '选具体分辨率时自动用窗口模式：全屏由本机屏幕决定，无法指定远程分辨率。' :
        proto === 'radmin' ? '命令行连接对应 Radmin 的 /telnet；远程关机是原版第四项 /shutdown。' :
        proto === 'ssh' ? '密码或密钥对只作用于这一台主机；密钥登录不会把密码传给客户端，格式说明点右侧 ? 查看。' :
        proto === 'ftp' ? 'FlashFXP 快速连接用 URL：选 FTPS / SFTP 时端口会自动跟着变；' +
          '密码会写进命令行，匿名登录不传密码。' :
        proto === 'web' ? 'HTTP / HTTPS 记录由本机 Agent 打开浏览器；默认不传密码，' +
          '账号密码只用于可选的 URL Basic 认证。' :
        proto === 'winscp' ? 'WinSCP 记录用会话 URL 一键登录：选协议时端口自动跟着变；' +
          '匿名登录不传保存的密码。' : '';
    }
    function protoDefault(proto) {
      if (proto === 'ftp') {
        return SCHEME_PORT.ftp[body.querySelector('#f_ftp_scheme').value] || 21;
      }
      if (proto === 'web') {
        return SCHEME_PORT.web[body.querySelector('#f_web_scheme').value] || 443;
      }
      if (proto === 'winscp') {
        return SCHEME_PORT.winscp[body.querySelector('#f_winscp_scheme').value] || 22;
      }
      return PROTO_PORT[proto];
    }
    toggleOptionSections(host.protocol);
    body.querySelector('#f_protocol').addEventListener('change', function (e) {
      var portInput = body.querySelector('#f_port');
      if (Number(portInput.value) === protoDefault(oldProtocol)) {
        portInput.value = protoDefault(e.target.value);
      }
      oldProtocol = e.target.value;
      toggleOptionSections(e.target.value);
    });
    // Changing the URL scheme also changes FlashFXP / browser default ports,
    // but only when the operator has not typed a custom port by hand.
    [['f_ftp_scheme', 'ftp'], ['f_web_scheme', 'web'],
     ['f_winscp_scheme', 'winscp']].forEach(function (pair) {
      var sel = body.querySelector('#' + pair[0]);
      var last = sel.value;
      sel.addEventListener('change', function (e) {
        var portInput = body.querySelector('#f_port');
        if (Number(portInput.value) === SCHEME_PORT[pair[1]][last]) {
          portInput.value = SCHEME_PORT[pair[1]][e.target.value];
        }
        last = e.target.value;
      });
    });
    body.querySelector('#f_ssh_auth').addEventListener('change', function () {
      toggleOptionSections(body.querySelector('#f_protocol').value);
    });
    [['ssh_fmt', 'ssh_fmt_help'], ['ftp_fmt', 'ftp_fmt_help'],
     ['web_fmt', 'web_fmt_help'], ['winscp_fmt', 'winscp_fmt_help']].forEach(function (pair) {
      body.querySelector('[data-help=' + pair[0] + ']').addEventListener('click', function () {
        body.querySelector('#' + pair[1]).classList.toggle('hidden');
      });
    });
    // The key BODY is uploaded (server encrypts it) so any PC can connect;
    // the Agent materialises it as a temporary file at connect time. Leaving
    // everything untouched means "keep whatever is already in the database".
    var keyAction = null, keyPayload = null;
    var keyState = body.querySelector('#f_ssh_key_state');
    var keyFile = body.querySelector('#f_ssh_key_file');
    var keyText = body.querySelector('#f_ssh_key_content');
    function setKeyState(text, cls) {
      keyState.textContent = text;
      keyState.className = 'path-state' + (cls ? ' ' + cls : '');
    }
    keyFile.addEventListener('change', function () {
      var file = keyFile.files && keyFile.files[0];
      if (!file) return;
      if (file.size > 65536) {
        toast('私钥文件过大（上限 64 KB）', true); keyFile.value = ''; return;
      }
      var reader = new FileReader();
      reader.onload = function () {
        keyPayload = {filename: file.name, content: String(reader.result || '')};
        keyAction = 'replace';
        keyText.value = '';
        setKeyState('已选择 ' + file.name + '（' + file.size + ' 字节，保存后加密上传）', 'ok');
      };
      reader.onerror = function () { toast('读取私钥文件失败', true); };
      reader.readAsText(file);
    });
    keyText.addEventListener('input', function () {
      if (!keyText.value.trim()) return;
      keyPayload = {filename: 'pasted.pem', content: keyText.value};
      keyAction = 'replace';
      keyFile.value = '';
      setKeyState('已粘贴私钥内容（保存后加密上传）', 'ok');
    });
    body.querySelector('#f_ssh_key_clear').addEventListener('click', function () {
      keyAction = 'remove'; keyPayload = null;
      keyFile.value = ''; keyText.value = '';
      setKeyState('保存后将清除数据库里的私钥', 'bad');
    });
    body.querySelectorAll('[data-browse]').forEach(function (btn) {
      btn.addEventListener('click', function () {
        browseClient(body, btn.dataset.browse, 'f_');
      });
    });
    body.querySelector('[data-role=cancel]').addEventListener('click', hideModal);
    body.querySelector('[data-role=save]').addEventListener('click', async function () {
      var payload = {
        name: body.querySelector('#f_name').value.trim(),
        protocol: body.querySelector('#f_protocol').value,
        address: body.querySelector('#f_address').value.trim(),
        port: Number(body.querySelector('#f_port').value),
        account: body.querySelector('#f_account').value.trim(),
        mac: body.querySelector('#f_mac').value.trim(),
        group_id: Number(body.querySelector('#f_group').value),
        note: body.querySelector('#f_note').value.trim()
      };
      var proto = body.querySelector('#f_protocol').value;
      var options = {};
      if (proto === 'rdp') {
        options.rdp_resolution = body.querySelector('#f_rdp_resolution').value;
        options.rdp_color = body.querySelector('#f_rdp_color').value;
        options.rdp_wallpaper = body.querySelector('#f_rdp_wallpaper').checked;
        options.rdp_drives = body.querySelector('#f_rdp_drives').checked;
        options.rdp_audio = body.querySelector('#f_rdp_audio').checked;
      } else if (proto === 'radmin') {
        options.radmin_display = body.querySelector('#f_radmin_display').value;
        options.radmin_ctrl = body.querySelector('#f_radmin_ctrl').value;
        options.radmin_color = body.querySelector('#f_radmin_color').value;
      } else if (proto === 'ssh') {
        options.ssh_auth = body.querySelector('#f_ssh_auth').value;
        options.ssh_key_path = body.querySelector('#f_ssh_key_path').value.trim();
        options.ssh_param_format = body.querySelector('#f_ssh_param_format').value.trim();
      } else if (proto === 'ftp') {
        options.ftp_scheme = body.querySelector('#f_ftp_scheme').value;
        options.ftp_auth = body.querySelector('#f_ftp_auth').value;
        options.ftp_window = body.querySelector('#f_ftp_window').value;
        options.ftp_path = body.querySelector('#f_ftp_path').value.trim();
        options.ftp_local_path = body.querySelector('#f_ftp_local_path').value.trim();
        options.ftp_param_format = body.querySelector('#f_ftp_param_format').value.trim();
      } else if (proto === 'web') {
        options.web_scheme = body.querySelector('#f_web_scheme').value;
        options.web_auth = body.querySelector('#f_web_auth').value;
        options.web_path = body.querySelector('#f_web_path').value.trim();
        options.web_param_format = body.querySelector('#f_web_param_format').value.trim();
      } else if (proto === 'winscp') {
        options.winscp_scheme = body.querySelector('#f_winscp_scheme').value;
        options.winscp_auth = body.querySelector('#f_winscp_auth').value;
        options.winscp_window = body.querySelector('#f_winscp_window').value;
        options.winscp_dir = body.querySelector('#f_winscp_dir').value.trim();
        options.winscp_param_format =
          body.querySelector('#f_winscp_param_format').value.trim();
      }
      payload.options = options;
      if (proto === 'ssh') {
        if (keyAction === 'remove') payload.ssh_key = {remove: true};
        else if (keyAction === 'replace' && keyPayload) payload.ssh_key = keyPayload;
      }
      var password = body.querySelector('#f_password').value;
      var clear = body.querySelector('#f_clear');
      if (password) payload.password = password;
      if (clear && clear.checked) payload.password = '';
      try {
        await api(isEdit ? '/api/hosts/' + host.id : '/api/hosts',
          {method: isEdit ? 'PUT' : 'POST', body: payload});
        hideModal(); toast(isEdit ? '主机已更新' : '主机已新增'); refresh();
      } catch (err) { toast(err.message, true); }
    });
  }

  // ------------------------------------------------------------------ actions
  async function oneClick(host) {
    // Open synchronously so popup blockers do not swallow the async result.
    var win = window.open('about:blank', '_blank');
    try {
      var ticket = await api('/api/connect-ticket', {method: 'POST', body: {host_id: host.id}});
      var port = state.settings.agent_port || 17860;
      var url = 'http://127.0.0.1:' + port + '/connect?ticket=' +
        encodeURIComponent(ticket.ticket) + '&server=' + encodeURIComponent(location.origin);
      if (win) win.location.href = url; else window.open(url, '_blank');
      setStatus('已向本地 Agent 发起连接：' + host.name);
      toast('已请求本地连接；若没反应，请先启动 remotemgr_agent.py serve');
    } catch (err) { if (win) win.close(); toast(err.message, true); }
  }

  function copyCommand(host) {
    var target = host.port === PROTO_PORT[host.protocol] ? host.address : host.address + ':' + host.port;
    var sshOpts = host.options || {};
    var sshKey = sshOpts.ssh_auth === 'key' ?
      (String(sshOpts.ssh_key_path || '') ||
        (host.has_ssh_key ? '<Agent 临时私钥文件>' : '')) : '';
    var sshCmd = 'ssh -p ' + host.port +
      (sshKey ? ' -i ' + (sshKey.indexOf(' ') >= 0 ? '"' + sshKey + '"' : sshKey) : '') +
      ' ' + (host.account || 'root') + '@' + host.address;
    var eff = tipEffective(host).eff;
    var url = (host.protocol === 'ftp' || host.protocol === 'web' ||
      host.protocol === 'winscp') ? tipUrl(host, eff) : '';
    var map = {
      rdp: 'mstsc /v:' + target,
      radmin: 'radmin.exe /connect:' + target,
      ssh: sshCmd,
      realvnc: 'vncviewer ' + target, tightvnc: 'vncviewer ' + target + ' -password=******',
      ftp: 'flashfxp.exe "' + url + '"',
      web: (String(state.settings.browser_path || '系统默认浏览器').trim()) + ' "' + url + '"',
      winscp: 'WinSCP.exe "' + url + '"'
    };
    var text = map[host.protocol] || target;
    if (navigator.clipboard) {
      navigator.clipboard.writeText(text).then(function () { toast('连接命令已复制：' + text); },
        function () { prompt('复制这条命令：', text); });
    } else { prompt('复制这条命令：', text); }
  }

  async function probe() {
    var ids = state.hosts.map(function (h) { return h.id; });
    if (!ids.length) { toast('当前没有主机'); return; }
    setStatus('正在通过本机 Agent 检测 ' + ids.length + ' 台主机…');

    // Reachability is measured ONLY by the local Agent, on the machine that
    // actually opens the remote client. The server deliberately has no probe
    // endpoint: on a different LAN segment it would report every host offline.
    var targets = state.hosts.map(function (h) {
      // A Web record may keep the whole URL in the address field: probe the
      // host/port inside it, not the URL string itself.
      var page = h.protocol === 'web' ? parseWebUrl(h.address) : null;
      return {id: h.id, address: page ? page.hostname : h.address,
              port: page ? page.port : h.port};
    });
    var ctrl = new AbortController();
    var timer = setTimeout(function () { ctrl.abort(); }, 15000);
    try {
      var res = await fetch(agentOrigin() + '/probe', {
        method: 'POST', signal: ctrl.signal,
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({targets: targets,
          timeout_ms: Number(state.settings.probe_timeout_ms) || 500})
      });
      // A pre-POST Agent has no do_POST at all (501) and no /probe route (404).
      if (res.status === 404 || res.status === 501) {
        throw new Error('本地 Agent 版本过旧，请用新版 start-agent.bat 重启');
      }
      if (!res.ok) throw new Error('HTTP ' + res.status);
      var payload = await res.json();
      if (payload.ok === false) throw new Error(payload.error || '探测失败');
      state.online = payload.data || {};
      var online = ids.filter(function (id) { return state.online[id] === true; }).length;
      renderHosts();
      setStatus('在线检测完成（本机 Agent）· ' + online + '/' + ids.length + ' 在线');
    } catch (err) {
      // "Agent unavailable" is an unknown state, NOT an offline result. Never
      // paint every row red/grey as 离线 just because detection did not run.
      state.online = {};
      renderHosts();
      var reason = (err && err.name === 'AbortError') ? '探测超时' :
        ((err && err.message) || '未启动');
      setStatus('在线检测未完成：本地 Agent 不可用');
      toast('在线检测由本机 Agent 执行，未取到结果（' + reason +
        '）。请启动/更新 start-agent.bat 后重试；服务端不会代为探测。', true);
    } finally {
      clearTimeout(timer);
    }
  }

  // ------------------------------------------------------------ system settings
  // Mirrors the original MFC "设置" dialog: GROUPBOX sections and, for each
  // client, a PUSHBUTTON on the left plus an ES_AUTOHSCROLL EDITTEXT on the right.
  var PATH_FIELDS = [
    ['radmin_path', 'RADMIN 路径', 'radmin.exe'],
    ['ssh_path', 'SSH 路径', 'putty.exe'],
    ['vnc_path', 'VNC 路径', 'vncviewer.exe / tvnviewer.exe'],
    ['flashfxp_path', 'FLASHFXP 路径', 'flashfxp.exe'],
    ['winscp_path', 'WINSCP 路径', 'WinSCP.exe'],
    ['browser_path', '浏览器路径', 'chrome.exe / msedge.exe / firefox.exe']
  ];

  function agentOrigin() {
    return 'http://127.0.0.1:' + (state.settings.agent_port || 17860);
  }

  function agentJson(path, timeoutMs) {
    var ctrl = new AbortController();
    var timer = setTimeout(function () { ctrl.abort(); }, timeoutMs || 5000);
    return fetch(agentOrigin() + path, {signal: ctrl.signal, cache: 'no-store'})
      .then(function (res) {
        if (!res.ok) throw new Error('HTTP ' + res.status);
        return res.json();
      })
      .finally(function () { clearTimeout(timer); });
  }

  function refreshPathStates(body) {
    PATH_FIELDS.forEach(function (f) {
      var input = body.querySelector('#s_' + f[0]);
      var badge = body.querySelector('[data-state="' + f[0] + '"]');
      if (!input || !badge) return;
      var value = input.value.trim();
      badge.textContent = value ? '已配置' : '留空 · 自动查找';
      badge.className = 'path-state ' + (value ? 'ok' : 'empty');
    });
  }

  function fillPath(body, key, value, prefix) {
    // Settings inputs are s_*, host-form inputs are f_* (SSH private key).
    var input = body.querySelector('#' + (prefix || 's_') + key);
    if (input) input.value = value;
    if (!prefix) refreshPathStates(body);
  }

  async function probeClient(body, only) {
    try {
      var data = await agentJson('/clients', 9000);
      var found = 0;
      PATH_FIELDS.forEach(function (f) {
        if (only && f[0] !== only) return;
        var path = ((data.clients || {})[f[0]] || {}).path;
        if (path) { fillPath(body, f[0], path); found++; }
      });
      if (found) {
        toast('已从本机 Agent 自动填入 ' + found + ' 个客户端路径，记得点「保存」');
      } else {
        toast('本机常见目录里没找到' + (only ? '这个客户端' : '客户端') +
          '，请点「浏览…」选择文件，或直接粘贴绝对路径', true);
      }
    } catch (err) {
      toast('本地 Agent 未启动或不在线（运行 start-agent.bat），也可以直接粘贴绝对路径', true);
    }
  }

  async function browseClient(body, key, prefix) {
    var btn = body.querySelector('[data-browse="' + key + '"]');
    var label = btn ? btn.textContent : '浏览…';
    if (btn) { btn.disabled = true; btn.textContent = '选择中…'; }
    // The picker opens on the machine running the Agent, not inside the
    // browser tab, so tell the user where to look instead of looking dead.
    toast('已请求本机文件选择框：若没弹出，请切到桌面或看任务栏（Agent 那个窗口）');
    try {
      var data = await agentJson('/browse?kind=' + encodeURIComponent(key), 100000);
      if (data.path) {
        fillPath(body, key, data.path, prefix);
        toast('已选择：' + data.path + '，记得点「保存」');
      } else if (data.error) {
        toast('本机文件选择框不可用：' + data.error + '；可直接粘贴绝对路径', true);
      } else {
        toast('已取消选择，可直接粘贴绝对路径');
      }
    } catch (err) {
      toast('无法打开本机文件选择框：' + err.message +
        '；请确认 Agent 已用新版本重启，或直接粘贴绝对路径', true);
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = label; }
    }
  }

  function showSettings() {
    var S = state.settings || {};
    function select(id, current, options) {
      return '<select id="s_' + id + '">' + options.map(function (o) {
        return '<option value="' + o[0] + '"' +
          (String(current) === o[0] ? ' selected' : '') + '>' + esc(o[1]) + '</option>';
      }).join('') + '</select>';
    }
    function field(id, label, hint) {
      return '<label>' + esc(label) + '<input id="s_' + id + '" value="' +
        esc(S[id] || '') + '">' +
        (hint ? '<span class="field-hint">' + esc(hint) + '</span>' : '') + '</label>';
    }

    var general = '<div class="form-grid">' +
      field('probe_timeout_ms', '在线检测超时（毫秒）', '由 WebUI 传给本机 Agent，服务端不参与探测') +
      field('wol_broadcast', 'WOL 广播地址') +
      field('agent_port', '本地 Agent 端口', '一键连接时浏览器回访的 127.0.0.1 端口') +
      '<label>Radmin 自动填登录窗' +
        select('radmin_autologin', S.radmin_autologin || '1', [['1', '是'], ['0', '否']]) + '</label>' +
      '</div>';

    var paths = '<div class="path-rows">' + PATH_FIELDS.map(function (f) {
      return '<div class="path-row">' +
        '<button type="button" class="path-pick" data-probe="' + f[0] +
          '" title="点击自动探测本机安装位置">' + esc(f[1]) + '</button>' +
        '<input id="s_' + f[0] + '" class="path-input mono" spellcheck="false" ' +
          'placeholder="留空则自动查找 ' + esc(f[2]) + '" value="' + esc(S[f[0]] || '') + '">' +
        '<button type="button" class="btn sm path-browse" data-browse="' + f[0] + '">浏览…</button>' +
        '<span class="path-state empty" data-state="' + f[0] + '">…</span>' +
      '</div>';
    }).join('') + '</div>' +
      '<div class="path-actions">' +
        '<button type="button" class="btn sm" data-probe-all>全部自动探测</button>' +
        '<span class="hint">路径是<b>运行 Agent 那台机器</b>上的绝对路径；点左侧名称自动探测，' +
        '点「浏览…」从本机选择文件，保存后即时生效、无需重启 Agent。' +
        '浏览器路径留空则 Web 记录用<b>系统默认浏览器</b>打开（自动探测会填入找到的浏览器）。</span></div>';

    // Connection parameters (RDP / Radmin / SSH) now live on each host record;
    // there is deliberately no "connection behaviour" section left here.

    // Legacy fallbacks: everything here has a per-record equivalent, so keep
    // it out of the way instead of duplicating the host editor's controls.
    var legacyFields = [
      ['rdp_width', 'RDP 默认宽度'], ['rdp_height', 'RDP 默认高度'],
      ['rdp_color', 'RDP 默认色深（16/24/32）'], ['rdp_fullscreen', 'RDP 默认全屏（1/0）'],
      ['radmin_fullscreen', 'Radmin 默认全屏（1/0）'],
      ['radmin_ctrl_mode', 'Radmin 默认控制模式（0 完全 / 1 仅查看 / 2 文件 / 3 关机）']
    ];
    var legacy = '<details class="legacy-opts"><summary>旧记录兼容默认值' +
      '<span>未单独配置的主机才会用到</span></summary>' +
      '<div class="hint">RDP / Radmin 的分辨率、色深、全屏与控制方式，以及 SSH / FTP / Web 的' +
      '认证与命令行参数格式，已在「编辑主机」里逐条设置。下面这些值只给还没配置过的' +
      '旧记录兜底，不影响新配置。</div>' +
      '<div class="form-grid">' + legacyFields.map(function (f) {
        return field(f[0], f[1]);
      }).join('') + '</div></details>';

    var html =
      '<fieldset class="opt-group"><legend>常规</legend>' + general + '</fieldset>' +
      '<fieldset class="opt-group"><legend>客户端程序路径</legend>' + paths + '</fieldset>' +
      legacy +
      '<div class="hint">RDP / Radmin / SSH / FTP / Web 的连接参数、控制颜色与命令行参数格式，' +
      '请到每台主机的「编辑」里单独设置。建议配合 HTTPS 反向代理对外提供访问。</div>' +
      '<div class="modal-foot"><button class="btn" data-role="cancel">取消</button>' +
      (isAdmin() ? '<button class="btn primary" data-role="save">保存</button>' : '') + '</div>';

    var body = showModal('系统设置', html, true);
    refreshPathStates(body);
    body.querySelector('[data-role=cancel]').addEventListener('click', hideModal);
    body.querySelectorAll('[data-probe]').forEach(function (btn) {
      btn.addEventListener('click', function () { probeClient(body, btn.dataset.probe); });
    });
    body.querySelectorAll('[data-browse]').forEach(function (btn) {
      btn.addEventListener('click', function () { browseClient(body, btn.dataset.browse); });
    });
    body.querySelector('[data-probe-all]').addEventListener('click', function () {
      probeClient(body, null);
    });
    body.querySelectorAll('.path-input').forEach(function (input) {
      input.addEventListener('input', function () { refreshPathStates(body); });
    });
    var save = body.querySelector('[data-role=save]');
    if (save) save.addEventListener('click', async function () {
      var payload = {};
      body.querySelectorAll('input[id^=s_], select[id^=s_]').forEach(function (el) {
        payload[el.id.slice(2)] = el.type === 'checkbox' ? (el.checked ? '1' : '0') : el.value;
      });
      try {
        await api('/api/settings', {method: 'PUT', body: payload});
        hideModal(); toast('设置已保存'); loadSettings();
      } catch (err) { toast(err.message, true); }
    });
  }

  async function showUsers() {
    try {
      var users = await api('/api/users');
      var rows = users.map(function (u) {
        return '<tr><td>' + u.id + '</td><td>' + esc(u.username) + '</td><td>' + u.role +
          '</td><td>' + (u.enabled ? '启用' : '停用') + '</td><td>' +
          (u.username === state.user.username ? '—' :
            '<button class="btn sm danger-text" data-act="user-del" data-id="' + u.id + '">删除</button>') +
          '</td></tr>';
      }).join('');
      var body = showModal('用户管理',
        '<table class="list-table"><thead><tr><th>ID</th><th>账号</th><th>角色</th><th>状态</th><th></th></tr></thead>' +
        '<tbody>' + rows + '</tbody></table>' +
        '<div class="form-grid" style="margin-top:16px">' +
        '<label>新账号<input id="u_name"></label><label>密码（≥8 位）<input id="u_pass" type="password"></label>' +
        '<label>角色<select id="u_role"><option value="editor">editor · 可编辑主机</option>' +
        '<option value="viewer">viewer · 只读</option><option value="admin">admin · 全部权限</option></select></label>' +
        '</div><div class="modal-foot"><button class="btn" data-role="cancel">关闭</button>' +
        (isAdmin() ? '<button class="btn primary" data-role="add">新增用户</button>' : '') + '</div>');
      body.querySelector('[data-role=cancel]').addEventListener('click', hideModal);
      var add = body.querySelector('[data-role=add]');
      if (add) add.addEventListener('click', async function () {
        try {
          await api('/api/users', {method: 'POST', body: {
            username: body.querySelector('#u_name').value.trim(),
            password: body.querySelector('#u_pass').value,
            role: body.querySelector('#u_role').value}});
          hideModal(); toast('用户已创建'); showUsers();
        } catch (err) { toast(err.message, true); }
      });
    } catch (err) { toast(err.message, true); }
  }

  async function showAudit() {
    try {
      var rows = await api('/api/audit?limit=300');
      var html = '<table class="list-table"><thead><tr><th>时间</th><th>账号</th><th>动作</th>' +
        '<th>对象</th><th>详情</th><th>IP</th></tr></thead><tbody>' +
        rows.map(function (r) {
          return '<tr><td class="mono">' + esc(r.created_at) + '</td><td>' + esc(r.username) +
            '</td><td>' + esc(r.action) + '</td><td>' + esc(r.target) + '</td><td>' +
            esc(r.detail) + '</td><td class="mono">' + esc(r.ip) + '</td></tr>';
        }).join('') + '</tbody></table>' +
        '<div class="modal-foot"><button class="btn" data-role="cancel">关闭</button></div>';
      var body = showModal('审计日志（最近 ' + rows.length + ' 条）', html);
      body.querySelector('[data-role=cancel]').addEventListener('click', hideModal);
    } catch (err) { toast(err.message, true); }
  }

  function showPassword() {
    var body = showModal('修改登录密码',
      '<div class="form-grid">' +
      '<label class="full">原密码<input id="p_old" type="password"></label>' +
      '<label class="full">新密码（≥8 位）<input id="p_new" type="password"></label></div>' +
      '<div class="modal-foot"><button class="btn" data-role="cancel">取消</button>' +
      '<button class="btn primary" data-role="save">确认修改</button></div>');
    body.querySelector('[data-role=cancel]').addEventListener('click', hideModal);
    body.querySelector('[data-role=save]').addEventListener('click', async function () {
      try {
        await api('/api/change-password', {method: 'POST', body: {
          old_password: body.querySelector('#p_old').value,
          new_password: body.querySelector('#p_new').value}});
        hideModal(); toast('密码已修改，下次登录生效');
      } catch (err) { toast(err.message, true); }
    });
  }

  async function exportBackup() {
    try {
      var response = await fetch('/api/export', {headers: {'Authorization': 'Bearer ' + state.token}});
      if (!response.ok) throw new Error('导出失败');
      var blob = await response.blob();
      var link = document.createElement('a');
      link.href = URL.createObjectURL(blob);
      link.download = 'remotemgr-backup-' + new Date().toISOString().slice(0, 10) + '.json';
      link.click();
      setTimeout(function () { URL.revokeObjectURL(link.href); }, 3000);
      toast('备份已导出');
    } catch (err) { toast(err.message, true); }
  }

  // ------------------------------------------------------------------ events
  document.addEventListener('click', async function (event) {
    var node = event.target.closest('[data-act]');
    if (node) {
      var act = node.dataset.act;
      var id = Number(node.dataset.id);
      var host = findHost(id);
      if (act === 'refresh') { refresh().catch(function (e) { toast(e.message, true); }); return; }
      if (act === 'search') { state.keyword = $('#search').value.trim(); loadHosts().catch(function (e) { toast(e.message, true); }); return; }
      if (act === 'probe') { probe(); return; }
      if (act === 'host-add') { if (canWrite()) hostForm(null); else toast('只读账号无法编辑', true); return; }
      if (act === 'host-edit') { if (canWrite() && host) hostForm(host); return; }
      if (act === 'host-del') {
        if (!canWrite() || !host) return;
        if (confirm('确认删除主机「' + host.name + '」？')) {
          try { await api('/api/hosts/' + id, {method: 'DELETE'}); toast('已删除'); refresh(); }
          catch (err) { toast(err.message, true); }
        }
        return;
      }
      if (act === 'connect') {
        // Every protocol goes straight through the local Agent. RDP used to
        // offer a "download .rdp" fallback, but mstsc is launched by the Agent
        // with a temporary .rdp that already carries the saved password and
        // all per-record options — downloading a separate file is redundant.
        if (host) oneClick(host);
        return;
      }
      if (act === 'cmd') { if (host) copyCommand(host); return; }
      if (act === 'wol') {
        if (!host) return;
        try { await api('/api/hosts/' + id + '/wol', {method: 'POST'}); toast('已发送网络唤醒包'); }
        catch (err) { toast(err.message, true); }
        return;
      }
      if (act === 'group-add' || act === 'group-root') {
        if (!canWrite()) { toast('只读账号无法编辑', true); return; }
        var parent = (act === 'group-add' && state.selected) ? state.selected : 0;
        var name = prompt('新分组名称：');
        if (!name) return;
        try { await api('/api/groups', {method: 'POST', body: {name: name, parent_id: parent}});
          toast('分组已创建'); loadGroups().catch(function () {}); }
        catch (err) { toast(err.message, true); }
        return;
      }
      if (act === 'group-rename') {
        if (!canWrite() || !state.selected) { toast('请先选中一个分组', true); return; }
        var group = state.groups.find(function (g) { return g.id === state.selected; });
        var newName = prompt('重命名分组：', group ? group.name : '');
        if (!newName) return;
        try { await api('/api/groups/' + state.selected, {method: 'PUT', body: {name: newName}});
          toast('已重命名'); loadGroups().catch(function () {}); }
        catch (err) { toast(err.message, true); }
        return;
      }
      if (act === 'group-del') {
        if (!canWrite() || !state.selected) { toast('请先选中一个分组', true); return; }
        if (!confirm('删除该分组？若含子分组或主机，将一并删除。')) return;
        try { await api('/api/groups/' + state.selected + '?force=1', {method: 'DELETE'});
          state.selected = 0; toast('分组已删除'); refresh().catch(function () {}); }
        catch (err) { toast(err.message, true); }
        return;
      }
      if (act === 'settings') { showSettings(); return; }
      if (act === 'users') { showUsers(); return; }
      if (act === 'audit') { showAudit(); return; }
      if (act === 'passwd') { showPassword(); return; }
      if (act === 'export') { exportBackup(); return; }
      if (act === 'import') { $('#fileInput').click(); return; }
      if (act === 'logout') { logout(); return; }
      if (act === 'user-del') {
        if (!confirm('确认删除该用户？')) return;
        try { await api('/api/users/' + id, {method: 'DELETE'}); hideModal(); toast('用户已删除'); showUsers(); }
        catch (err) { toast(err.message, true); }
        return;
      }
    }
    var groupNode = event.target.closest('[data-group]');
    if (groupNode) {
      state.selected = Number(groupNode.dataset.group);
      state.keyword = ''; $('#search').value = '';
      renderTree(); loadHosts().catch(function (e) { toast(e.message, true); });
    }
  });

  // Hover over any host row: preview the connection parameters without
  // opening the editor. pointer-events:none on the card keeps it from
  // stealing the mouse and causing flicker.
  document.addEventListener('mouseover', function (event) {
    var row = (event.target && event.target.closest) ?
      event.target.closest('tr[data-host]') : null;
    if (!row) { hideHostTip(); return; }
    var host = findHost(row.dataset.host);
    if (host) showHostTip(host, event.clientX || 0, event.clientY || 0);
    else hideHostTip();
  });
  document.addEventListener('mousemove', function (event) {
    if (tipVisibleFor !== null) positionHostTip(event.clientX || 0, event.clientY || 0);
  });
  document.addEventListener('mouseleave', hideHostTip);
  document.addEventListener('scroll', hideHostTip, true);
  document.addEventListener('dragstart', hideHostTip);
  document.addEventListener('click', hideHostTip);

  $('#search').addEventListener('keydown', function (event) {
    if (event.key === 'Enter') { state.keyword = $('#search').value.trim(); loadHosts().catch(function (e) { toast(e.message, true); }); }
  });

  $('#fileInput').addEventListener('change', async function (event) {
    var file = event.target.files[0];
    if (!file) return;
    try {
      var payload = JSON.parse(await file.text());
      var result = await api('/api/import', {method: 'POST', body: payload});
      toast('导入完成：' + result.hosts + ' 台主机、' + result.groups + ' 个分组');
      refresh().catch(function () {});
    } catch (err) { toast('导入失败：' + err.message, true); }
    event.target.value = '';
  });

  // drag a host row onto a tree node to move it into that group
  var dragIds = [];
  document.addEventListener('dragstart', function (event) {
    var row = event.target.closest('tr[data-host]');
    if (!row) return;
    var selected = state.hosts.filter(function (h) { return h.id === Number(row.dataset.host); });
    dragIds = selected.map(function (h) { return h.id; });
    event.dataTransfer.setData('text/plain', dragIds.join(','));
    event.dataTransfer.effectAllowed = 'move';
  });
  document.addEventListener('dragover', function (event) {
    var node = event.target.closest('[data-drop]');
    if (node) { event.preventDefault(); node.classList.add('dragover'); }
  });
  document.addEventListener('dragleave', function (event) {
    var node = event.target.closest('[data-drop]');
    if (node) node.classList.remove('dragover');
  });
  document.addEventListener('drop', async function (event) {
    var node = event.target.closest('[data-drop]');
    if (!node) return;
    event.preventDefault();
    node.classList.remove('dragover');
    if (!canWrite() || !dragIds.length) return;
    try {
      await api('/api/hosts/move', {method: 'POST',
        body: {ids: dragIds, group_id: Number(node.dataset.drop)}});
      toast('已移动到分组'); loadHosts().catch(function () {});
    } catch (err) { toast(err.message, true); }
    dragIds = [];
  });

  // boot
  (async function () {
    if (state.token) {
      try { state.user = await api('/api/me'); showApp(); return; } catch (err) { logout(false); }
    }
    $('#login').classList.remove('hidden');
  })();
})();
