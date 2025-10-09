const functions = require("firebase-functions");
const admin = require("firebase-admin");
const cors = require("cors")({origin: true});

admin.initializeApp();

const ensureAdmin = async (context) => {
  if (!context.auth) {
    throw new functions.https.HttpsError("unauthenticated", "此操作需要權限，請先登入。");
  }
  const adminDoc = await admin.firestore().collection("users").doc(context.auth.uid).get();
  if (!adminDoc.exists || adminDoc.data().role !== "管理員") {
    throw new functions.https.HttpsError("permission-denied", "權限不足，只有管理員可以執行此操作。");
  }
};

// 以 Authorization Bearer Token 驗證並檢查管理員權限（HTTP 端點用）
const ensureAdminFromRequest = async (req) => {
  const authHeader = req.headers.authorization || "";
  const match = authHeader.match(/^Bearer\s+(.*)$/i);
  if (!match) {
    const err = new Error("缺少 Authorization Bearer Token");
    err.code = "unauthenticated";
    throw err;
  }
  const idToken = match[1];
  let decoded;
  try {
    decoded = await admin.auth().verifyIdToken(idToken);
  } catch (e) {
    const err = new Error("Token 驗證失敗");
    err.code = "unauthenticated";
    throw err;
  }
  const adminDoc = await admin.firestore().collection("users").doc(decoded.uid).get();
  if (!adminDoc.exists || adminDoc.data().role !== "管理員") {
    const err = new Error("權限不足，只有管理員可以執行此操作。");
    err.code = "permission-denied";
    throw err;
  }
  return decoded.uid;
};

exports.createUser = functions.region('us-central1').https.onCall(async (data, context) => {
    await ensureAdmin(context);

    const {email, password, name, role, title, communities} = data;
    if (!email || !password || !name || !role || !title) {
        throw new functions.https.HttpsError("invalid-argument", "缺少必要欄位。");
    }

    try {
        const userRecord = await admin.auth().createUser({
            email: email,
            password: password,
            displayName: name,
        });

        await admin.firestore().collection("users").doc(userRecord.uid).set({
            email: email, name: name, role: role, title: title, communities: communities || [],
        });

        return { success: true, uid: userRecord.uid };
    } catch (error) {
        if (error.code === "auth/email-already-exists") {
            throw new functions.https.HttpsError("already-exists", "此電子郵件已被註冊。");
        }
        throw new functions.https.HttpsError("internal", "建立使用者時發生錯誤。");
    }
});


exports.updateUser = functions.region('us-central1').https.onCall(async (data, context) => {
    await ensureAdmin(context);

    const {uid, name, role, title, communities, password} = data;
    if (!uid || !name || !role || !title) {
        throw new functions.https.HttpsError("invalid-argument", "缺少必要欄位 (uid, name, role, title)。");
    }

    try {
        await admin.firestore().collection("users").doc(uid).update({
            name: name, role: role, title: title, communities: communities || [],
        });

        const authUpdates = {displayName: name};
        if (password) {
            authUpdates.password = password;
        }
        await admin.auth().updateUser(uid, authUpdates);

        return { success: true };
    } catch (error) {
        console.error("Error updating user:", error);
        if (error && error.code === "auth/user-not-found") {
            throw new functions.https.HttpsError("not-found", "找不到該使用者。");
        }
        if (error && (error.code === "auth/invalid-password" || error.code === "auth/weak-password")) {
            throw new functions.https.HttpsError("invalid-argument", "密碼格式不符合要求。");
        }
        throw new functions.https.HttpsError("internal", error?.message || "更新使用者時發生錯誤。");
    }
});


exports.deleteUser = functions.region('us-central1').https.onCall(async (data, context) => {
    await ensureAdmin(context);

    const {uid} = data;
    if (!uid) {
        throw new functions.https.HttpsError("invalid-argument", "缺少使用者 UID。");
    }

    try {
        await admin.auth().deleteUser(uid);
        await admin.firestore().collection("users").doc(uid).delete();
        return { success: true };
    } catch (error) {
        console.error("Error deleting user:", error);
        throw new functions.https.HttpsError("internal", "刪除使用者時發生錯誤。");
    }
});

// ---- 具備 CORS 的 HTTP 端點：建立/更新/刪除使用者 ----
const sendError = (res, error) => {
  const code = error.code || "internal";
  const statusMap = {
    "unauthenticated": 401,
    "permission-denied": 403,
    "invalid-argument": 400,
    "already-exists": 409,
    "not-found": 404,
    "internal": 500,
  };
  const status = statusMap[code] || 500;
  res.status(status).json({ error: { code, message: error.message || "發生錯誤" } });
};

exports.httpCreateUser = functions.region('us-central1').https.onRequest((req, res) => {
  cors(req, res, async () => {
    if (req.method === 'OPTIONS') { res.status(204).send(''); return; }
    if (req.method !== 'POST') { res.status(405).json({ error: { message: 'Method Not Allowed' } }); return; }
    try {
      await ensureAdminFromRequest(req);
      const { email, password, name, role, title, communities } = (req.body && req.body.data) || {};
      if (!email || !password || !name || !role || !title) {
        const err = new Error("缺少必要欄位。"); err.code = "invalid-argument"; throw err;
      }
      const userRecord = await admin.auth().createUser({ email, password, displayName: name });
      await admin.firestore().collection('users').doc(userRecord.uid).set({ email, name, role, title, communities: communities || [] });
      res.json({ success: true, uid: userRecord.uid });
    } catch (error) {
      if (error.code === 'auth/email-already-exists') { error = Object.assign(new Error('此電子郵件已被註冊。'), { code: 'already-exists' }); }
      sendError(res, error);
    }
  });
});

exports.httpUpdateUser = functions.region('us-central1').https.onRequest((req, res) => {
  cors(req, res, async () => {
    if (req.method === 'OPTIONS') { res.status(204).send(''); return; }
    if (req.method !== 'POST') { res.status(405).json({ error: { message: 'Method Not Allowed' } }); return; }
    try {
      await ensureAdminFromRequest(req);
      const { uid, name, role, title, communities, password } = (req.body && req.body.data) || {};
      if (!uid || !name || !role || !title) { const err = new Error("缺少必要欄位 (uid, name, role, title)。"); err.code = 'invalid-argument'; throw err; }
      await admin.firestore().collection('users').doc(uid).update({ name, role, title, communities: communities || [] });
      const authUpdates = { displayName: name };
      if (password) authUpdates.password = password;
      await admin.auth().updateUser(uid, authUpdates);
      res.json({ success: true });
    } catch (error) {
      if (error && error.code === 'auth/user-not-found') { error = Object.assign(new Error('找不到該使用者。'), { code: 'not-found' }); }
      if (error && (error.code === 'auth/invalid-password' || error.code === 'auth/weak-password')) { error = Object.assign(new Error('密碼格式不符合要求。'), { code: 'invalid-argument' }); }
      sendError(res, error);
    }
  });
});

exports.httpDeleteUser = functions.region('us-central1').https.onRequest((req, res) => {
  cors(req, res, async () => {
    if (req.method === 'OPTIONS') { res.status(204).send(''); return; }
    if (req.method !== 'POST') { res.status(405).json({ error: { message: 'Method Not Allowed' } }); return; }
    try {
      await ensureAdminFromRequest(req);
      const { uid } = (req.body && req.body.data) || {};
      if (!uid) { const err = new Error('缺少使用者 UID。'); err.code = 'invalid-argument'; throw err; }
      await admin.auth().deleteUser(uid);
      await admin.firestore().collection('users').doc(uid).delete();
      res.json({ success: true });
    } catch (error) {
      sendError(res, error);
    }
  });
});

