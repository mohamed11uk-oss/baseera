cues = [
(1.00,3.85,"السلام عليكم... معاكم فريق بصيرة.","Hello, we are team Baseera."),
(3.90,8.92,"كل يوم، توصل الناس رسايل تقول: \"عليك مخالفة... ادفع الحين!\"","Every day, people get messages saying: \"You have a fine... pay now!\""),
(8.92,11.18,"أو: \"حسابك البنكي موقوف!\"","Or: \"Your bank account is suspended!\""),
(11.18,15.70,"كبسة وحدة... ويروح رقم البطاقة... ورمز التحقق.","One tap... and your card number and OTP are gone."),
(15.70,21.78,"وإذا شكّيت في شي، بلّغ أمان على 8002626","If something looks wrong, report it to Aman on 8002626"),
(21.78,25.50,"أو أرسل رسالة على 2828","or send an SMS to 2828."),
(26.00,29.90,"بصيرة... يكشف لك الاحتيال، قبل ما تضغط.","Baseera exposes the scam before you click."),
(31.45,34.48,"خلونا نجرب رابط مخالفات... مزيف.","Let's try a fake traffic-fines link."),
(34.48,36.34,"شوفوا! خطر عالي.","Look: high risk."),
(36.34,41.58,"والسبب واضح بالعربي: يستخدم اسم جهة رسمية، وفيه كلمات إغراء،","The reasons are clear, in Arabic: it uses an official entity's name, has lure words,"),
(41.58,43.96,"ومربوط بحملة احتيال ثانية.","and it is linked to another scam campaign."),
(43.96,47.42,"الحين... الموقع الرسمي لشرطة أبوظبي.","Now, the official Abu Dhabi Police website."),
(47.42,50.82,"آمن... لأنه موجود في سجل المواقع الرسمية.","Safe, because it is in the official registry."),
(50.82,52.74,"وهذي رسالة نصية:","And this is a text message:"),
(52.74,58.40,"استعجال... طلب رمز تحقق... رقم جوال غير موثّق... ورابط شبيه.","urgency, an OTP request, an unverified mobile number, and a look-alike link."),
(58.40,59.70,"خطر عالي.","High risk."),
(62.90,65.70,"المحتالين... ما يكتفون بالرسايل.","Scammers don't stop at messages."),
(65.70,70.10,"أحياناً يدفعون إعلان في البحث... أو يغيّرون رقم الهاتف في الخرائط.","Sometimes they pay for search ads, or change the phone number on Maps."),
(70.10,72.02,"نبحث عن بنك معروف...","We search for a well-known bank..."),
(72.02,73.80,"الرسمي يطلع بالأخضر.","The official results show in green."),
(73.80,78.12,"والإعلان الشبيه، والموقع المسروق في الخرائط... ينكشفون على طول.","The look-alike ad and the hijacked Maps listing are exposed right away."),
(78.12,82.45,"وللأمانة... البيانات في هذا العرض تجريبية، ومكتوب عليها كذا.","To be clear: the data in this demo is synthetic, and it is labelled as such."),
(90.20,94.56,"وللجهات المختصة... بصيرة يجمع البلاغات في حملات.","For the authorities, Baseera groups reports into campaigns."),
(94.56,99.06,"هني تشوفون الروابط اللي تشترك في نفس الخادم، أو نفس رقم الهاتف...","Here you see links that share the same server or the same phone number..."),
(99.06,100.62,"والخط الزمني للحملة.","and the campaign timeline."),
(100.62,102.94,"والأدلة تنصدر بملف جاهز...","Evidence is exported as a ready-made pack..."),
(102.94,106.15,"ومعاها بصمة رقمية، تثبت إنها ما تعدّلت.","with a digital fingerprint (SHA-256) proving it was not altered."),
(113.50,116.78,"كل حكم نعطيه... نوضح مصدره،","Every verdict shows its source,"),
(116.78,119.20,"ونقول بصراحة وين حدود النظام.","and we are upfront about the system's limits."),
(119.20,123.28,"يشتغل بالعربي والإنجليزي... وفيه إضافة للمتصفح.","It works in Arabic and English, and there is a browser extension."),
(123.28,126.52,"بصيرة... افحص... قبل ما تضغط.","Baseera: check before you click."),
(126.52,127.70,"شكراً لكم.","Thank you."),
]
def ts(t):
    ms=int(round(t*1000)); h,ms=divmod(ms,3600000); m,ms=divmod(ms,60000); s,ms=divmod(ms,1000)
    return f"{h:02d}:{m:02d}:{s:02d},{ms:03d}"
for lang,i in (("ar",2),("en",3)):
    with open(f"/workspace/baseera/docs/baseera_demo.{lang}.srt","w",encoding="utf-8") as f:
        for n,c in enumerate(cues,1):
            f.write(f"{n}\n{ts(c[0])} --> {ts(c[1])}\n{c[i]}\n\n")
print("ok")
