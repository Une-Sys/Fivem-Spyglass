# FiveM OSINT — منصة استخبارات سيرفرات FiveM

أدوات Python (بدون أي مكتبات خارجية — Python 3.8+) لتحليل سيرفرات FiveM عبر الواجهات **العامة الرسمية** من Cfx.re.

## الأدوات

| الملف | الوصف |
|---|---|
| `fivem-osint.py` | النواة + منيو تفاعلي (14 وحدة) + CLI كامل |
| `fivem-osint-gui.py` | واجهة رسومية (Tkinter) بتبويبات |
| `fivem-stream-dump.py` | منيو + CLI لسحب **كل** السيرفرات الحية (protobuf رسمي) |

## التشغيل

```bash
# المنيو التفاعلي (أوصى به)
python fivem-osint.py
python fivem-stream-dump.py

# CLI — ملف OSINT كامل لسيرفر
python fivem-osint.py profile j4r9zmk
python fivem-osint.py deep 194.50.0.77
python fivem-osint.py stream --subnet 162.222.16.0/24

# CLI — سحب كامل (33 ألف سيرفر + إحصائيات)
python fivem-stream-dump.py --out fivem-stream-full.csv
python fivem-stream-dump.py --top 50 --out top50.csv
python fivem-stream-dump.py --framework QBCore --min-players 10 --out qb.csv
python fivem-stream-dump.py --deep          # مزارع الشبكات / IP مكرر / إحصائيات عميقة
python fivem-stream-dump.py --dashboard dashboard.html
python fivem-stream-dump.py --geo --geo-limit 500   # دولة/مزود/ASN (cache في SQLite)
python fivem-stream-dump.py --history       # سجل snapshots وفرق اللاعبين
```

## وحدات fivem-osint.py

`profile` ملف كامل · `players` اللاعبون · `resources` الموارد والإطارات · `scan` فحص أمني
`owner` حساب المالك · `discord` حل دعوات ديسكورد · `media` أيقونات وبانرات
`history` التاريخ (SQLite) · `raw` JSON خام · `deep` DNS/TLS/CDN/reverse-IP/CT/GitHub
`stream` السيرفرات الحية · `batch` ملف دفعات

## فك الستريم (protobuf رسمي)

`https://frontend.cfx-services.net/api/servers/stream/{ts}/` ليس JSON — بل **إطارات**:
4 بايت little-endian للطول (≤65535) ثم رسالة `Server` protobuf
`{1: code, 2: ServerData}`. الحقول الكاملة (من schema الرسمي):

```
svMaxclients=1  clients=2  protocol=3  hostname=4  gametype=5  mapname=6
resources=8  server=9  players=10  iconVersion=11  vars=12(key=1,value=2)
enhanced=16  upvotePower=17  connectEndPoints=18  burstPower=19
```

المرجع الكامل في `docs/reference/` (من مستودع citizenfx/fivem الرسمي، MIT).

## أعمدة التصدير (35)

`code, hostname, gametype, map, version, clients, maxclients, fill, upvote, burst,
protocol, enhanced, framework, scriptHook, allowlisted, onesync, txAdmin, gamebuild,
private, endpoint, ip, port, locale, gamename, premium, tags, desc, mastodon, discord,
banner, resources, player_count, country, isp, asn`

## ملاحظات تقنية

- `root-AQ` في عمود locale = القيمة الافتراضية الرسمية من Cfx (سيرفر بلا locale).
- الستريم لا يحمل قوائم اللاعبين — تُجلب من API الفردي لأفضل السيرفرات (المعرفات
  مخفية عند السيرفرات المحمية).
- السيرفرات الخاصة: endpoint الأول هو `private-placeholder.cfx.re`.
- `--geo` يستخدم ip-api.com (مجاني، طلب تسلسلي مع pause — بحد يومي احتراماً للمصدر).

## الأمان والأخلاق

بيانات عامة فقط (API رسمية). الرفض: استخراج تراخيص/توكنات، مسح لوحات التحكم،
حصاد معرفات اللاعبين بالجملة.

## الترخيص

MIT — يُنسب الكود المرجعي إلى Cfx.re (citizenfx/fivem).

## المؤلف

**Une-Sys** — مطور ومستقّل (Cyber Security & OSINT)

- الموقع: https://une-sys.netlify.app/
- Telegram: https://t.me/unezelsys
- GitHub: https://github.com/Une-Sys
