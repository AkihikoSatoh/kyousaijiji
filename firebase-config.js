/* ============================================================
   firebase-config.js ― Firebase 接続設定
   --------------------------------------------------------------
   Firebase コンソールで取得した「ウェブアプリの構成」を
   下の FIREBASE_CONFIG に貼り付けてください。
   （apiKey 等はクライアントに公開されても問題ありません。
     データ保護は Firestore のセキュリティルールで行います）

   未設定（プレースホルダのまま）の場合、アプリは従来どおり
   localStorage のみで動作します（クラウド同期は無効）。
   ============================================================ */
window.FIREBASE_CONFIG = {
  apiKey: "ここにあなたの apiKey",
  authDomain: "ここにあなたの authDomain",        // 例: kyosai-navi.firebaseapp.com
  projectId: "ここにあなたの projectId",           // 例: kyosai-navi
  storageBucket: "ここにあなたの storageBucket",    // 例: kyosai-navi.appspot.com
  messagingSenderId: "ここにあなたの messagingSenderId",
  appId: "ここにあなたの appId"
};

// 設定が実際に入力済みかどうかの簡易フラグ（アプリ側で参照）
window.FIREBASE_READY = !/ここにあなたの/.test(JSON.stringify(window.FIREBASE_CONFIG));
