# رنة (Ranna)

نموذج أولي لتطبيق مراسلة بالعربي.

## إيه الموجود هنا

**1. النسخة التجريبية الثابتة (`index.html`)**: واجهة التطبيق (دردشات، مكالمات، إعدادات، وضع داكن). الردود فيها تلقائية ومحاكاة، مفيش ناس حقيقية ومفيش رسايل بتتبعت لحد. دي اللي بتفتح من رابط GitHub Pages.

**2. سيرفر المراسلة الحقيقية (`server/`)**: كود Node.js (من غير مكتبات خارجية) فيه تسجيل حسابات، مراسلة حقيقية بين مستخدمين، علامات القراءة، وحالة الاتصال. اتجرّب محليا بين متصفحين. **مش شغال على GitHub Pages** لأنه محتاج سيرفر شغال طول الوقت، ولسه ما اتنشرش على استضافة.

- كود الدخول بالموبايل (OTP) في وضع تطوير فقط، من غير إرسال SMS حقيقي.
- تسجيل الدخول بجوجل مكتوب بس لسه ما اتجرّبش (محتاج بيانات OAuth).
- التفاصيل الأمنية في `server/SECURITY.md`.

تشغيل السيرفر محليا: `node server/server.mjs` (Node 22 أو أحدث).

---

Arabic messaging app prototype. `index.html` is a static demo with simulated auto-replies (no real people, no real messages). `server/` is a working real-messaging backend that has only been tested locally and is not deployed; GitHub Pages cannot run it.
