const admin = require('firebase-admin');

// 使用應用程式預設憑證（需設定 GOOGLE_APPLICATION_CREDENTIALS 指向 service account JSON）
admin.initializeApp({
  credential: admin.credential.applicationDefault(),
});

function parseArgs() {
  const args = process.argv.slice(2);
  const map = {};
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a.startsWith('--')) {
      const key = a.replace(/^--/, '');
      const val = args[i + 1] && !args[i + 1].startsWith('--') ? args[++i] : 'true';
      map[key] = val;
    }
  }
  return map;
}

(async () => {
  try {
    const { email, password, name, role, title, communities } = parseArgs();
    if (!email || !password || !name || !role || !title) {
      console.error('缺少必要參數：--email --password --name --role --title');
      process.exit(1);
    }

    const communitiesArr = communities
      ? communities.split(',').map((s) => s.trim()).filter(Boolean)
      : [];

    const userRecord = await admin.auth().createUser({
      email,
      password,
      displayName: name,
    });

    await admin.firestore().collection('users').doc(userRecord.uid).set({
      email,
      name,
      role,
      title,
      communities: communitiesArr,
    });

    console.log('成功建立使用者：', userRecord.uid);
    process.exit(0);
  } catch (error) {
    if (error.code === 'auth/email-already-exists') {
      console.error('此電子郵件已被註冊。');
    } else {
      console.error('建立使用者時發生錯誤：', error.message || error);
    }
    process.exit(2);
  }
})();