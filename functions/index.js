const functions = require("firebase-functions");
const admin = require("firebase-admin");

admin.initializeApp();

/**
 * Cloud Function to create a new user with Authentication and Firestore profile.
 * - This function must be called by an authenticated user.
 * - The calling user must have the '管理員' role in their Firestore profile.
 */
exports.createUser = functions.https.onCall(async (data, context) => {
  // 1. Authorization Check: Ensure the caller is an authenticated admin.
  if (!context.auth) {
    throw new functions.https.HttpsError(
      "unauthenticated",
      "此操作需要管理員權限，請先登入。",
    );
  }

  const adminUid = context.auth.uid;
  const adminDocRef = admin.firestore().collection("users").doc(adminUid);

  try {
    const adminDoc = await adminDocRef.get();
    if (!adminDoc.exists || adminDoc.data().role !== "管理員") {
      throw new functions.https.HttpsError(
        "permission-denied",
        "權限不足，只有管理員可以建立新帳號。",
      );
    }
  } catch (error) {
    throw new functions.https.HttpsError(
      "internal",
      "驗證管理員身份時發生錯誤。",
    );
  }

  // 2. Data Validation: Ensure all required fields are present.
  const {email, password, name, role, title, communities} = data;
  if (!email || !password || !name || !role || !title) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "請求中缺少必要欄位 (姓名、信箱、密碼、角色、職稱)。",
    );
  }

  // 3. Create User in Firebase Authentication.
  let userRecord;
  try {
    userRecord = await admin.auth().createUser({
      email: email,
      password: password,
      displayName: name,
    });
  } catch (error) {
    // Handle common auth errors
    if (error.code === "auth/email-already-exists") {
      throw new functions.https.HttpsError(
        "already-exists",
        "此電子郵件已被註冊。",
      );
    }
    if (error.code === "auth/invalid-password") {
      throw new functions.https.HttpsError(
        "invalid-argument",
        "密碼格式無效，長度至少需6個字元。",
      );
    }
    // For other errors
    throw new functions.https.HttpsError("internal", "建立認證用戶時發生錯誤。");
  }

  // 4. Create User Profile in Firestore.
  const newUserProfile = {
    email: email,
    name: name,
    role: role,
    title: title,
    communities: communities || [], // Ensure communities is an array
  };

  try {
    await admin
      .firestore()
      .collection("users")
      .doc(userRecord.uid)
      .set(newUserProfile);
  } catch (error) {
    // This is a critical error, might need manual cleanup if it fails
    throw new functions.https.HttpsError(
      "internal",
      "儲存使用者設定檔至資料庫時發生錯誤。",
    );
  }

  // 5. Return Success.
  return {success: true, uid: userRecord.uid};
});
