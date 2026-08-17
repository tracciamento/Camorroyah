# WebForge — Web Application Security Toolkit

مجموعة 27 أداة هجومية على تطبيقات الويب في ملف واحد — متخصصة بحمايات **Laravel/PHP**
وتعمل على **Termux و Linux** بـ Python فقط (بدون مكتبات خارجية).

## الوحدات (27)

| الوحدة | الوظيفة | الوحدة | الوظيفة |
|---|---|---|---|
| detect | كشف التقنيات/Laravel | sqli | حقن SQL (خطأ/منطقي/زمني) |
| laravel | حزمة هجمات Laravel (env, debug, CVE-2021-3129, Telescope...) | xss | XSS منعكسة |
| headers | فحص ترويسات الأمان | ssti | حقن القوالب (Blade/Twig) |
| robots | robots.txt + sitemap | cmd | حقن الأوامر |
| cookies | خصائص الكوكيز | lfi | تضمين الملفات (php://filter) |
| waf | كشف جدار الحماية | ssrf | SSRF (مع --callback) |
| ports | فحص المنافذ | open-redirect | تحويل مفتوح |
| tls | إصدارات TLS + الشهادة | cors | سوء إعداد CORS |
| dns | سجلات DNS + Zone Transfer | jwt | none-alg + كسر المفتاح |
| subdomains | استكشاف نطاقات فرعية | brute | كلمات المرور (Basic/نموذج) |
| takeover | استيلاء النطاقات | phpinfo | صفحات phpinfo |
| dirs | تخمين المسارات | admin | لوحات التحكم |
| backup | ملفات النسخ الاحتياطي | api | API + GraphQL |
| report | تقرير HTML/Markdown | | |

## الاستخدام

```bash
python3 webforge.py --list
python3 webforge.py --all https://target.com          # الحزمة الكاملة + تقرير
python3 webforge.py laravel https://target.com       # هجمات Laravel فقط
python3 webforge.py sqli "https://target.com/item?id=1"
python3 webforge.py brute https://target.com --user admin --passlist words.txt
python3 webforge.py ssrf https://target.com --callback http://10.0.0.5:8000
python3 webforge.py jwt https://target.com --token eyJ...
