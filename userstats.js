/* ============================================================
   userstats.js ― 教採ナビ ユーザー＆学習実績（ローカル試作版）
   --------------------------------------------------------------
   将来 Firebase（Authentication + Firestore）へ差し替える前提の
   薄いラッパ。現状はブラウザの localStorage に保存する。

   公開API（window.KyosaiUser）:
     register({username,password,name,area,schoolType,subject}) -> Promise<{ok,error?}>
     login(username,password)                                   -> Promise<{ok,error?}>
     logout()
     getCurrentUser()      -> {username,name,area,schoolType,subject,createdAt} | null
     getCurrentUsername()  -> string | null
     updateProfile({name,area,schoolType,subject})              -> bool
     changePassword(newPw)                                      -> Promise<bool>
     recordUserAnswer(content, category, isCorrect[, dateISO])  // content: 'quiz5' | 'mondai'
     getStats(content[, username]) -> {total,byCategory,byMonth}
     rate(bucket)          -> number(0-100) | null

   ※ パスワードは平文保存せず SHA-256 でハッシュ化して保持する。
     （試作段階でも実運用に近い扱いにし、Firebase移行を容易にする）
   ============================================================ */
(function (global) {
  'use strict';

  // クラウド同期の状態（Firebase設定済みのときのみ有効化）
  var _cloud = { enabled: false, started: false, db: null, auth: null, uid: null, onChange: null, pushTimer: null };

  var USERS_KEY   = 'kyosai_users';         // { [username]: {username,name,area,schoolType,subject,pwHash,createdAt,updatedAt} }
  var CURRENT_KEY = 'kyosai_current_user';  // 現在ログイン中の username（文字列）
  var STATS_KEY   = 'kyosai_user_stats';    // { [username]: { quiz5:Content, mondai:Content } }
  //  Content = { total:{answered,correct}, byCategory:{[cat]:{answered,correct}}, byMonth:{['YYYY-MM']:{answered,correct}} }

  function readJSON(k, def) {
    try { var s = localStorage.getItem(k); return s ? JSON.parse(s) : def; }
    catch (e) { return def; }
  }
  function writeJSON(k, v) {
    try { localStorage.setItem(k, JSON.stringify(v)); return true; }
    catch (e) { return false; }
  }

  /* ---- パスワードのハッシュ化 ---- */
  function hashPassword(pw) {
    return new Promise(function (resolve) {
      try {
        if (global.crypto && global.crypto.subtle && global.TextEncoder) {
          var data = new TextEncoder().encode(String(pw));
          global.crypto.subtle.digest('SHA-256', data).then(function (buf) {
            var hex = Array.prototype.map.call(new Uint8Array(buf), function (b) {
              return ('0' + b.toString(16)).slice(-2);
            }).join('');
            resolve('s:' + hex);
          }).catch(function () { resolve(fallbackHash(pw)); });
          return;
        }
      } catch (e) {}
      resolve(fallbackHash(pw));
    });
  }
  function fallbackHash(pw) {
    // crypto.subtle が使えない環境向けの簡易ハッシュ（djb2）
    var h = 5381, i; pw = String(pw);
    for (i = 0; i < pw.length; i++) { h = ((h << 5) + h + pw.charCodeAt(i)) | 0; }
    return 'f:' + (h >>> 0).toString(16);
  }

  /* ---- ユーザー管理 ---- */
  function getUsers() { return readJSON(USERS_KEY, {}); }
  function saveUsers(u) { writeJSON(USERS_KEY, u); }

  function getCurrentUsername() {
    if (_cloud.enabled) return _cloud.uid;   // クラウド有効時はFirebase認証が真実
    try { return localStorage.getItem(CURRENT_KEY) || null; } catch (e) { return null; }
  }
  function setCurrentUsername(name) {
    try { if (name) localStorage.setItem(CURRENT_KEY, name); else localStorage.removeItem(CURRENT_KEY); } catch (e) {}
  }

  function publicProfile(u) {
    if (!u) return null;
    return {
      username: u.username,
      name: u.name || '',
      area: u.area || '',
      schoolType: u.schoolType || '',
      subject: u.subject || '',
      dailyTargetMin: u.dailyTargetMin || 0,
      createdAt: u.createdAt || ''
    };
  }

  function getCurrentUser() {
    var name = getCurrentUsername();
    if (!name) return null;
    return publicProfile(getUsers()[name]);
  }

  function register(opts) {
    opts = opts || {};
    if (cloudEnabled()) return _registerCloud(opts);
    var username = String(opts.username || '').trim();
    var password = String(opts.password || '');
    return new Promise(function (resolve) {
      if (!username) return resolve({ ok: false, error: 'ユーザー名を入力してください。' });
      if (!/^[A-Za-z0-9_.\-]{3,50}$/.test(username)) {
        return resolve({ ok: false, error: 'ユーザー名は半角英数字・記号(_ . -)3〜50文字にしてください。' });
      }
      if (password.length < 4) return resolve({ ok: false, error: 'パスワードは4文字以上にしてください。' });
      var users = getUsers();
      if (users[username]) return resolve({ ok: false, error: 'そのユーザー名は既に使われています。' });
      hashPassword(password).then(function (pwHash) {
        users[username] = {
          username: username,
          name: String(opts.name || '').trim(),
          area: opts.area || '',
          schoolType: opts.schoolType || '',
          subject: opts.subject || '',
          pwHash: pwHash,
          createdAt: new Date().toISOString()
        };
        saveUsers(users);
        setCurrentUsername(username);
        resolve({ ok: true });
      });
    });
  }

  function login(username, password) {
    if (cloudEnabled()) {
      return _cloud.auth.signInWithEmailAndPassword(String(username || '').trim(), password)
        .then(function () { return { ok: true }; })
        .catch(function (e) { return { ok: false, error: _fbErr(e) }; });
    }
    username = String(username || '').trim();
    return new Promise(function (resolve) {
      var u = getUsers()[username];
      if (!u) return resolve({ ok: false, error: 'ユーザー名またはパスワードが違います。' });
      hashPassword(password).then(function (pwHash) {
        if (pwHash !== u.pwHash) return resolve({ ok: false, error: 'ユーザー名またはパスワードが違います。' });
        setCurrentUsername(username);
        resolve({ ok: true });
      });
    });
  }

  function logout() {
    if (cloudEnabled() && _cloud.auth) { _cloud.auth.signOut(); return; }
    setCurrentUsername(null);
  }

  function updateProfile(partial) {
    var name = getCurrentUsername();
    if (!name) return false;
    var users = getUsers();
    if (!users[name]) return false;
    ['name', 'area', 'schoolType', 'subject', 'dailyTargetMin'].forEach(function (k) {
      if (partial && partial[k] != null) users[name][k] = partial[k];
    });
    users[name].updatedAt = new Date().toISOString();
    saveUsers(users);
    _schedulePush();
    return true;
  }

  function changePassword(newPw) {
    if (cloudEnabled()) {
      return new Promise(function (resolve) {
        var u = _cloud.auth.currentUser;
        if (!u || !newPw || String(newPw).length < 6) return resolve(false);
        u.updatePassword(newPw).then(function () { resolve(true); }).catch(function () { resolve(false); });
      });
    }
    var name = getCurrentUsername();
    return new Promise(function (resolve) {
      if (!name) return resolve(false);
      if (!newPw || String(newPw).length < 4) return resolve(false);
      hashPassword(newPw).then(function (h) {
        var users = getUsers();
        if (!users[name]) return resolve(false);
        users[name].pwHash = h;
        users[name].updatedAt = new Date().toISOString();
        saveUsers(users);
        resolve(true);
      });
    });
  }

  /* ---- 学習実績 ---- */
  function getAllStats() { return readJSON(STATS_KEY, {}); }
  function saveAllStats(s) { writeJSON(STATS_KEY, s); }
  function emptyContent() { return { total: { answered: 0, correct: 0 }, byCategory: {}, byMonth: {} }; }

  function bump(parent, key, isCorrect) {
    if (!parent[key]) parent[key] = { answered: 0, correct: 0 };
    parent[key].answered++;
    if (isCorrect) parent[key].correct++;
  }

  function recordUserAnswer(content, category, isCorrect, dateISO) {
    var name = getCurrentUsername();
    if (!name) return;                                   // 未ログインなら記録しない
    if (content !== 'quiz5' && content !== 'mondai' && content !== 'kakomon') return;
    var cat = (category && String(category).trim()) ? String(category).trim() : '未分類';
    var month = String(dateISO || new Date().toISOString()).slice(0, 7); // YYYY-MM
    var all = getAllStats();
    if (!all[name]) all[name] = {};
    if (!all[name][content]) all[name][content] = emptyContent();
    var c = all[name][content];
    c.total.answered++; if (isCorrect) c.total.correct++;
    bump(c.byCategory, cat, !!isCorrect);
    bump(c.byMonth, month, !!isCorrect);
    saveAllStats(all);
    _schedulePush();
  }

  function getStats(content, username) {
    var name = username || getCurrentUsername();
    if (!name) return emptyContent();
    var all = getAllStats();
    var c = all[name] && all[name][content];
    return c ? c : emptyContent();
  }

  function rate(bucket) {
    if (!bucket || !bucket.answered) return null;
    return Math.round((bucket.correct / bucket.answered) * 100);
  }

  /* ---- 学習時間 ---- */
  var STUDY_KEY = 'kyosai_study_time';   // { [username]: { 'YYYY-MM-DD': seconds } }

  function pad2(n) { return ('0' + n).slice(-2); }
  function localDateKey(d) { d = d || new Date(); return d.getFullYear() + '-' + pad2(d.getMonth() + 1) + '-' + pad2(d.getDate()); }

  function addStudySeconds(sec) {
    var name = getCurrentUsername();
    if (!name || !sec) return;
    var all = readJSON(STUDY_KEY, {});
    if (!all[name]) all[name] = {};
    var day = localDateKey();
    all[name][day] = (all[name][day] || 0) + sec;
    writeJSON(STUDY_KEY, all);
    _schedulePush();
  }

  function getStudyMap(username) {
    var name = username || getCurrentUsername();
    if (!name) return {};
    var all = readJSON(STUDY_KEY, {});
    return all[name] || {};
  }

  function getStudyTotal(username) {
    var m = getStudyMap(username), t = 0, k;
    for (k in m) { if (m.hasOwnProperty(k)) t += m[k] || 0; }
    return t;
  }

  function getStudyActiveDays(username) {
    var m = getStudyMap(username), n = 0, k;
    for (k in m) { if (m.hasOwnProperty(k) && m[k] > 0) n++; }
    return n;
  }

  // 直近 days 日分（古い順）-> [{date,label,seconds}]
  function getStudyByDay(days, username) {
    days = days || 14;
    var m = getStudyMap(username), out = [], i;
    var base = new Date();
    for (i = days - 1; i >= 0; i--) {
      var d = new Date(base.getFullYear(), base.getMonth(), base.getDate() - i);
      var key = localDateKey(d);
      out.push({ date: key, label: (d.getMonth() + 1) + '/' + d.getDate(), seconds: m[key] || 0 });
    }
    return out;
  }

  // 直近 weeks 週（月曜始まり・古い順）-> [{label,seconds}]
  function getStudyByWeek(weeks, username) {
    weeks = weeks || 8;
    var m = getStudyMap(username), out = [], w, i;
    var base = new Date();
    var dow = (base.getDay() + 6) % 7; // 月曜=0
    var thisMon = new Date(base.getFullYear(), base.getMonth(), base.getDate() - dow);
    for (w = weeks - 1; w >= 0; w--) {
      var monday = new Date(thisMon.getFullYear(), thisMon.getMonth(), thisMon.getDate() - w * 7);
      var sec = 0;
      for (i = 0; i < 7; i++) {
        var d = new Date(monday.getFullYear(), monday.getMonth(), monday.getDate() + i);
        sec += m[localDateKey(d)] || 0;
      }
      out.push({ label: (monday.getMonth() + 1) + '/' + monday.getDate() + '〜', seconds: sec });
    }
    return out;
  }

  // 直近 months ヶ月（古い順）-> [{label,month,seconds}]
  function getStudyByMonth(months, username) {
    months = months || 6;
    var m = getStudyMap(username), out = [], i, k;
    var base = new Date();
    for (i = months - 1; i >= 0; i--) {
      var d = new Date(base.getFullYear(), base.getMonth() - i, 1);
      var ym = d.getFullYear() + '-' + pad2(d.getMonth() + 1);
      var sec = 0;
      for (k in m) { if (m.hasOwnProperty(k) && k.indexOf(ym) === 0) sec += m[k] || 0; }
      out.push({ label: (d.getMonth() + 1) + '月', month: ym, seconds: sec });
    }
    return out;
  }

  // 曜日別の傾向（直近 weeks 週・月曜始まり）-> [{label,total,days,avg}]
  function getStudyByWeekday(weeks, username) {
    weeks = weeks || 8;
    var m = getStudyMap(username);
    var labels = ['月', '火', '水', '木', '金', '土', '日'];
    var buckets = labels.map(function (l) { return { label: l, total: 0, days: 0, avg: 0 }; });
    var base = new Date(), totalDays = weeks * 7, i;
    for (i = 0; i < totalDays; i++) {
      var d = new Date(base.getFullYear(), base.getMonth(), base.getDate() - i);
      var idx = (d.getDay() + 6) % 7; // 月=0
      buckets[idx].total += m[localDateKey(d)] || 0;
      buckets[idx].days += 1;
    }
    buckets.forEach(function (b) { b.avg = b.days ? Math.round(b.total / b.days) : 0; });
    return buckets;
  }

  // 1日の目標学習時間（分）
  function getDailyTargetMin(username) {
    var name = username || getCurrentUsername();
    if (!name) return 0;
    var u = getUsers()[name];
    return (u && u.dailyTargetMin) ? u.dailyTargetMin : 0;
  }

  /* ---- 学習時間の自動計測 ---- */
  var _studyStarted = false;
  function startStudySession(opts) {
    if (_studyStarted) return;
    _studyStarted = true;
    opts = opts || {};
    var TICK = opts.tickSec || 15;   // 計測間隔（秒）
    var IDLE = opts.idleSec || 90;   // 無操作で計測停止（秒）
    var lastActivity = Date.now();
    function touch() { lastActivity = Date.now(); }
    ['mousemove', 'mousedown', 'keydown', 'touchstart', 'scroll', 'click'].forEach(function (ev) {
      global.addEventListener(ev, touch, { passive: true });
    });
    setInterval(function () {
      if (global.document && global.document.hidden) return;   // 非表示タブは計測しない
      if (Date.now() - lastActivity > IDLE * 1000) return;     // 無操作は計測しない
      addStudySeconds(TICK);
    }, TICK * 1000);
  }

  /* ============================================================
     クラウド同期（Firebase）― firebase-config.js が設定済みのときのみ有効
     localStorage を手元キャッシュ、Firestore を正データとして双方向同期。
     ============================================================ */
  function cloudConfigured() { return !!(global.FIREBASE_READY && global.FIREBASE_CONFIG); }
  function cloudEnabled() { return _cloud.enabled; }

  function _loadScript(src) {
    return new Promise(function (resolve, reject) {
      var s = global.document.createElement('script');
      s.src = src; s.async = false;
      s.onload = function () { resolve(); };
      s.onerror = function () { reject(new Error('script load failed: ' + src)); };
      global.document.head.appendChild(s);
    });
  }

  var _FB_VER = '10.12.2';
  function _ensureSdk() {
    if (global.firebase && global.firebase.firestore) return Promise.resolve();
    var base = 'https://www.gstatic.com/firebasejs/' + _FB_VER + '/';
    return _loadScript(base + 'firebase-app-compat.js')
      .then(function () { return _loadScript(base + 'firebase-auth-compat.js'); })
      .then(function () { return _loadScript(base + 'firebase-firestore-compat.js'); });
  }

  function _fbErr(e) {
    var code = (e && e.code) || '';
    var map = {
      'auth/email-already-in-use': 'このメールアドレスは既に登録されています。',
      'auth/invalid-email': 'メールアドレスの形式が正しくありません。',
      'auth/weak-password': 'パスワードは6文字以上にしてください。',
      'auth/user-not-found': 'メールアドレスまたはパスワードが違います。',
      'auth/wrong-password': 'メールアドレスまたはパスワードが違います。',
      'auth/invalid-credential': 'メールアドレスまたはパスワードが違います。',
      'auth/network-request-failed': '通信エラーが発生しました。接続をご確認ください。',
      'auth/too-many-requests': '試行回数が多すぎます。しばらくしてから再度お試しください。'
    };
    return map[code] || ('エラーが発生しました（' + (code || (e && e.message) || 'unknown') + '）');
  }

  function initCloud(onChange) {
    if (onChange) _cloud.onChange = onChange;
    if (!cloudConfigured()) return;     // 未設定なら localStorage のみで動作
    if (_cloud.started) return;
    _cloud.started = true;
    _ensureSdk().then(function () {
      if (!global.firebase.apps.length) global.firebase.initializeApp(global.FIREBASE_CONFIG);
      _cloud.auth = global.firebase.auth();
      _cloud.db = global.firebase.firestore();
      _cloud.enabled = true;
      _cloud.auth.onAuthStateChanged(function (u) {
        if (u) {
          _cloud.uid = 'fb:' + u.uid;
          _hydrateFromCloud(u.uid).then(function () { if (_cloud.onChange) _cloud.onChange(); })
            .catch(function () { if (_cloud.onChange) _cloud.onChange(); });
        } else {
          _cloud.uid = null;
          if (_cloud.onChange) _cloud.onChange();
        }
      });
    }).catch(function () { _cloud.started = false; });
  }

  function _registerCloud(opts) {
    var email = String(opts.email || '').trim();
    var password = String(opts.password || '');
    if (!email) return Promise.resolve({ ok: false, error: 'メールアドレスを入力してください。' });
    if (password.length < 6) return Promise.resolve({ ok: false, error: 'パスワードは6文字以上にしてください。' });
    return _cloud.auth.createUserWithEmailAndPassword(email, password).then(function (cred) {
      var uid = cred.user.uid, key = 'fb:' + uid;
      var profile = {
        username: String(opts.username || '').trim(),
        name: String(opts.name || '').trim(),
        email: email,
        area: opts.area || '', schoolType: opts.schoolType || '', subject: opts.subject || '',
        dailyTargetMin: opts.dailyTargetMin || 0,
        createdAt: new Date().toISOString()
      };
      var users = getUsers(); users[key] = profile; saveUsers(users);
      _cloud.uid = key;
      return _cloud.db.collection('users').doc(uid).set({ profile: profile, stats: {}, studyTime: {} }, { merge: true })
        .then(function () { return { ok: true }; });
    }).catch(function (e) { return { ok: false, error: _fbErr(e) }; });
  }

  function _hydrateFromCloud(uid) {
    var key = 'fb:' + uid;
    return _cloud.db.collection('users').doc(uid).get().then(function (doc) {
      var d = doc.exists ? (doc.data() || {}) : {};
      var users = getUsers(); users[key] = d.profile || { username: '' }; saveUsers(users);
      var allStats = getAllStats(); allStats[key] = d.stats || {}; saveAllStats(allStats);
      var allStudy = readJSON(STUDY_KEY, {}); allStudy[key] = d.studyTime || {}; writeJSON(STUDY_KEY, allStudy);
    });
  }

  function _schedulePush() {
    if (!_cloud.enabled || !_cloud.uid) return;
    if (_cloud.pushTimer) clearTimeout(_cloud.pushTimer);
    _cloud.pushTimer = setTimeout(_pushCloud, 2000);
  }
  function _pushCloud() {
    if (!_cloud.enabled || !_cloud.uid) return;
    var key = _cloud.uid, uid = key.slice(3);
    var profile = getUsers()[key] || {};
    var stats = getAllStats()[key] || {};
    var studyTime = readJSON(STUDY_KEY, {})[key] || {};
    _cloud.db.collection('users').doc(uid).set({ profile: profile, stats: stats, studyTime: studyTime }, { merge: true }).catch(function () {});
  }

  global.KyosaiUser = {
    register: register,
    login: login,
    logout: logout,
    getCurrentUser: getCurrentUser,
    getCurrentUsername: getCurrentUsername,
    updateProfile: updateProfile,
    changePassword: changePassword,
    recordUserAnswer: recordUserAnswer,
    getStats: getStats,
    rate: rate,
    addStudySeconds: addStudySeconds,
    startStudySession: startStudySession,
    getStudyTotal: getStudyTotal,
    getStudyActiveDays: getStudyActiveDays,
    getStudyByDay: getStudyByDay,
    getStudyByWeek: getStudyByWeek,
    getStudyByMonth: getStudyByMonth,
    getStudyByWeekday: getStudyByWeekday,
    getDailyTargetMin: getDailyTargetMin,
    initCloud: initCloud,
    cloudEnabled: cloudEnabled,
    cloudConfigured: cloudConfigured
  };

  // Firebase が設定済みなら自動的にクラウド同期を開始（各ページで書き込み同期が有効に）
  if (cloudConfigured()) { initCloud(); }

  // 学習ページでは自動で学習時間を計測（無効化するには読み込み前に window.KYOSAI_TRACK_STUDY=false）
  if (global.KYOSAI_TRACK_STUDY !== false) {
    if (global.document && global.document.readyState === 'loading') {
      global.document.addEventListener('DOMContentLoaded', function () { startStudySession(); });
    } else {
      startStudySession();
    }
  }
})(window);
