const functions = require("firebase-functions");
const admin = require("firebase-admin");

admin.initializeApp();

/**
 * Checks if the calling user is an admin.
 * @param {object} context - The function context.
 * @throws {HttpsError} If the user is not an authenticated admin.
 */
const ensureAdmin = async (context) => {
  if (!context.auth) {
    throw new functions.https.HttpsError(
      "unauthenticated",
      "此操作需要權限，請先登入。",
    );
  }
  const adminDoc = await admin.firestore().collection("users").doc(context.auth.uid).get();
  if (!adminDoc.exists || adminDoc.data().role !== "管理員") {
    throw new functions.https.HttpsError(
      "permission-denied",
      "權限不足，只有管理員可以執行此操作。",
    );
  }
};

/**
 * Creates a new user in Firebase Auth and a corresponding profile in Firestore.
 */
exports.createUser = functions.https.onCall(async (data, context) => {
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
      email: email,
      name: name,
      role: role,
      title: title,
      communities: communities || [],
    });

    return {success: true, uid: userRecord.uid};
  } catch (error) {
    if (error.code === "auth/email-already-exists") {
      throw new functions.https.HttpsError("already-exists", "此電子郵件已被註冊。");
    }
    throw new functions.https.HttpsError("internal", "建立使用者時發生錯誤。");
  }
});


/**
 * Updates an existing user's profile in Firestore and optionally their auth details.
 */
exports.updateUser = functions.https.onCall(async (data, context) => {
    await ensureAdmin(context);

    const {uid, name, role, title, communities, password} = data;
    if (!uid || !name || !role || !title) {
        throw new functions.https.HttpsError("invalid-argument", "缺少必要欄位 (uid, name, role, title)。");
    }

    try {
        // Update Firestore document
        await admin.firestore().collection("users").doc(uid).update({
            name: name,
            role: role,
            title: title,
            communities: communities || [],
        });

        // Update Auth if password is provided
        const authUpdates = {displayName: name};
        if (password) {
            authUpdates.password = password;
        }
        await admin.auth().updateUser(uid, authUpdates);

        return {success: true};
    } catch (error) {
        console.error("Error updating user:", error);
        throw new functions.https.HttpsError("internal", "更新使用者時發生錯誤。");
    }
});


/**
 * Deletes a user from Firebase Auth and their profile from Firestore.
 */
exports.deleteUser = functions.https.onCall(async (data, context) => {
  await ensureAdmin(context);

  const {uid} = data;
  if (!uid) {
    throw new functions.https.HttpsError("invalid-argument", "缺少使用者 UID。");
  }

  try {
    // Delete from Auth first
    await admin.auth().deleteUser(uid);
    // Then delete from Firestore
    await admin.firestore().collection("users").doc(uid).delete();
    return {success: true};
  } catch (error) {
    console.error("Error deleting user:", error);
    throw new functions.https.HttpsError("internal", "刪除使用者時發生錯誤。");
  }
});
