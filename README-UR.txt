LoanDesk — چلنے کے قابل MVP اور API پیکج
========================================

اس پیک میں کیا ہے؟
------------------
1) frontend/customer.html — صارف کی موبائل فرینڈلی ایپ اسکرین
2) frontend/admin.html — لاگ اِن کے ساتھ کام کرنے والا ایڈمن پورٹل
3) backend/main.py — FastAPI بیک اینڈ، OTP تصدیق، درخواستوں اور ایڈمن APIs
4) android-app/ — Android Studio میں کھولنے کے لیے اینڈرائیڈ ایپ شیل
5) docs/API.md — APIs، نمونہ درخواستیں اور SMS سیٹنگز
6) run-local.sh / run-local.bat — مقامی سرور چلانے کے طریقے

کیا کام کرتا ہے؟
----------------
- موبائل نمبر پر چھ ہندسوں کا OTP سرور پر بنتا ہے۔
- OTP پانچ منٹ میں ختم ہوتا ہے، صرف ایک بار استعمال ہوتا ہے، اور غلط کوششیں محدود ہیں۔
- مقامی Development mode میں OTP صرف سرور کے ٹرمینل پر دکھایا جاتا ہے تاکہ ٹیسٹ ہو سکے۔
- درست OTP کے بعد صارف کا سیشن بنتا ہے؛ ایپ میں الگ Register بٹن نہیں ہے۔
- صارف PAN/شناختی نمبر، سیلفی اور کارڈ کی تصویر رضامندی کے ساتھ جمع کر سکتا ہے۔
- تصاویر ڈسک پر انکرپٹڈ محفوظ ہوتی ہیں اور صرف مجاز ایڈمن API سے دیکھی جا سکتی ہیں۔
- اکاؤنٹ ہولڈر، بینک اور اکاؤنٹ نمبر ڈیٹا بیس میں انکرپٹڈ رکھے جاتے ہیں۔
- ایڈمن درخواستوں کو Under review، Needs information، Approved یا Rejected کر سکتا ہے۔
- ایڈمن پورٹل OTP requests، درست/غلط کوششوں، وقت اور masked فون نمبر کا audit دیکھتا ہے۔
- درخواستوں اور audit کی CSV فائلیں نکالی جا سکتی ہیں؛ حساس نمبرز mask ہوتے ہیں۔
- Admin پورٹل سے دکھائی جانے والی زیادہ سے زیادہ رقم تبدیل ہو سکتی ہے۔ یہ صرف ceiling ہے، منظوری کی ضمانت نہیں۔
- OpenAPI docs `/docs` پر موجود ہیں۔

OTP کے متعلق اہم حفاظتی فیصلہ
-----------------------------
ایڈمن پورٹل سے ایک مستقل OTP چن کر تمام صارفین کے لیے استعمال نہیں کیا جاتا، اور صارف کا اصل درج کیا گیا OTP بھی ڈیٹا بیس، پورٹل یا Excel میں محفوظ نہیں ہوتا۔ اس کے بجائے ہر درخواست کے لیے سرور نیا OTP بناتا ہے، تصدیق کرتا ہے، اور audit میں صرف یہ درج کرتا ہے کہ کوشش درست تھی یا غلط، کس وقت ہوئی اور کون سا challenge استعمال ہوا۔ اس سے صارفین کے لاگ اِن راز محفوظ رہتے ہیں۔ OTP کو raw form میں محفوظ کرنا یا ایڈمن کو دکھانا محفوظ ڈیزائن نہیں ہے۔

مقامی طور پر کیسے چلائیں؟
-------------------------
Windows:
  1. Python 3.11 یا نیا ورژن انسٹال کریں۔
  2. run-local.bat چلائیں۔
  3. پہلی دفعہ dependencies انسٹال ہوں گی اور مقامی ڈیٹا/چابیاں بنیں گی۔
  4. صارف ایپ: http://127.0.0.1:8000/app
  5. ایڈمن پورٹل: http://127.0.0.1:8000/admin
  6. API docs: http://127.0.0.1:8000/docs
  7. پہلی بار ایڈمن کا username `admin` ہے؛ password `data/admin-initial-credentials.txt` میں ملے گا۔ اس فائل کو محفوظ رکھیں۔

macOS/Linux:
  chmod +x run-local.sh
  ./run-local.sh

مقامی ٹیسٹ میں OTP کہاں ملے گا؟
------------------------------
جب صارف Get OTP دبائے گا تو چھ ہندسوں کا کوڈ اسی terminal/console میں آئے گا جس میں سرور چل رہا ہے۔ کوڈ API response، ایپ یا Admin portal میں نہیں دکھایا جاتا، اور audit میں بھی محفوظ نہیں ہوتا۔ یہ console طریقہ صرف development میں ہے۔

حقیقی SMS کیسے آن ہوگا؟
-----------------------
`.env.example` کو `.env` میں کاپی کر کے `SMS_PROVIDER=twilio` اور SMS provider کے credentials سرور پر سیٹ کریں: `SMS_TWILIO_ACCOUNT_SID`، `SMS_TWILIO_AUTH_TOKEN`، `SMS_TWILIO_FROM`۔ اپنے ملک کے لیے provider کی اجازت، sender configuration، قانونی ضروریات اور message templates کی تصدیق کریں۔ SMS کی credentials کبھی Android app یا browser code میں نہ رکھیں۔

Android APK:
-----------
`android-app` فولڈر کو Android Studio میں کھولیں، Gradle Sync کریں اور debug build چلائیں۔ اس workspace میں Android SDK موجود نہیں، اس لیے compiled APK شامل نہیں ہے۔ Android project اس سرور پر موجود `/app` صفحے کو کھولتا ہے۔ ریلیز سے پہلے `APP_URL` کو اپنے HTTPS domain پر تبدیل کریں۔

اہم حدود — لائیو کاروباری استعمال سے پہلے
---------------------------------------
- یہ پیک آپ کے سرور، domain، SMS provider account یا موجودہ کمپنی پورٹل سے خودبخود منسلک نہیں ہے۔ اس کے لیے آپ کے credentials اور deployment درکار ہیں۔
- سیلفی/کارڈ upload کام کرتا ہے، لیکن حقیقی automated facial liveness verification شامل نہیں۔ ابھی status `manual_review_required` ہے؛ liveness کے لیے منظور شدہ provider کا SDK/API یا باقاعدہ انسانی جائزہ شامل کرنا ہوگا۔
- PAN/کارڈ اور بینک کی معلومات بہت حساس ہیں۔ production سے پہلے hosting security، HTTPS، backups، key management، admin MFA، audit retention، privacy notice، صارف کی رضامندی، deletion policy اور متعلقہ قرض/ڈیٹا قوانین کا جائزہ لازمی کروائیں۔
- currency ابھی واضح طور پر set نہیں کی گئی؛ UI میں رقم صرف `Up to 50,000` کی صورت میں دکھائی جاتی ہے۔ اپنے ملک اور کاروباری ماڈل کے مطابق currency اور مکمل loan terms ظاہر کریں۔
- Admin کے پاس حساس معلومات دیکھنے کی اجازت ہے، مگر full details دیکھنے کے لیے reason درج ہوتا ہے اور اس access کا audit event محفوظ ہوتا ہے۔

یہ پیک API، حقیقی server-side OTP flow، encrypted submissions اور manual review portal کا قابلِ اجرا پہلا نظام ہے۔ Live public launch سے پہلے اوپر درج provider، deployment اور compliance کام مکمل ہونا ضروری ہے۔
