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

exports.createUser = functions.region('us-central1').https.onRequest((req, res) => {
    cors(req, res, async () => {
        try {
            // Manually verify token
            const idToken = req.headers.authorization.split('Bearer ')[1];
            const decodedToken = await admin.auth().verifyIdToken(idToken);
            
            // Re-create context for ensureAdmin
            const context = { auth: { uid: decodedToken.uid } };
            await ensureAdmin(context);

            const {email, password, name, role, title, communities} = req.body.data;
            if (!email || !password || !name || !role || !title) {
                return res.status(400).json({ error: { message: "缺少必要欄位。" } });
            }

            const userRecord = await admin.auth().createUser({
                email: email,
                password: password,
                displayName: name,
            });

            await admin.firestore().collection("users").doc(userRecord.uid).set({
                email: email, name: name, role: role, title: title, communities: communities || [],
            });

            res.json({ data: { success: true, uid: userRecord.uid } });
        } catch (error) {
            console.error("Error creating user:", error);
            const errorMessage = error.code === 'auth/email-already-exists' ? '此電子郵件已被註冊。' : '建立使用者時發生錯誤。';
            res.status(500).json({ error: { message: errorMessage } });
        }
    });
});

exports.updateUser = functions.region('us-central1').https.onRequest((req, res) => {
    cors(req, res, async () => {
        try {
            const idToken = req.headers.authorization.split('Bearer ')[1];
            const decodedToken = await admin.auth().verifyIdToken(idToken);
            const context = { auth: { uid: decodedToken.uid } };
            await ensureAdmin(context);

            const {uid, name, role, title, communities, password} = req.body.data;
            if (!uid || !name || !role || !title) {
                return res.status(400).json({ error: { message: "缺少必要欄位 (uid, name, role, title)。" } });
            }

            await admin.firestore().collection("users").doc(uid).update({
                name: name, role: role, title: title, communities: communities || [],
            });

            const authUpdates = {displayName: name};
            if (password) {
                authUpdates.password = password;
            }
            await admin.auth().updateUser(uid, authUpdates);

            res.json({ data: { success: true } });
        } catch (error) {
            console.error("Error updating user:", error);
            res.status(500).json({ error: { message: "更新使用者時發生錯誤。" } });
        }
    });
});

exports.deleteUser = functions.region('us-central1').https.onRequest((req, res) => {
    cors(req, res, async () => {
        try {
            const idToken = req.headers.authorization.split('Bearer ')[1];
            const decodedToken = await admin.auth().verifyIdToken(idToken);
            const context = { auth: { uid: decodedToken.uid } };
            await ensureAdmin(context);

            const {uid} = req.body.data;
            if (!uid) {
                return res.status(400).json({ error: { message: "缺少使用者 UID。" } });
            }
            
            await admin.auth().deleteUser(uid);
            await admin.firestore().collection("users").doc(uid).delete();

            res.json({ data: { success: true } });
        } catch (error) {
            console.error("Error deleting user:", error);
            res.status(500).json({ error: { message: "刪除使用者時發生錯誤。" } });
        }
    });
});
