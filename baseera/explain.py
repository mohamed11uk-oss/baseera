"""Deterministic Arabic-first explanations built ONLY from signal evidence/data (no free text, no LLM)."""
from __future__ import annotations

from .registry import Registry
from .schemas import Signal

AMAN_AR = "إذا تعرضت لاحتيال أو شكيت في رابط، بلّغ خدمة أمان (Aman) من شرطة أبوظبي: اتصال 8002626 أو رسالة نصية 2828."
AMAN_EN = "If you were targeted, report to Abu Dhabi Police Aman service: call 8002626 or SMS 2828."

TECH_AR = {
    "tld_swap": "ينسخ اسم الموقع الرسمي لـ{ent} لكن بنهاية مختلفة: {dom} بدل {off}",
    "homoglyph": "يشبه موقع {ent} الرسمي ({off}) باستخدام حروف متشابهة الشكل (Homoglyph): {host}",
    "typosquat": "اسمه قريب جداً من موقع {ent} الرسمي ({off}) مع اختلاف حرف أو حرفين (Typosquatting): {dom}",
    "brand_keyword": "يستخدم اسم {ent} ({term}) داخل نطاق مو رسمي: {dom}",
    "brand_in_subdomain": "يستخدم اسم {ent} ({term}) كجزء فرعي (Subdomain) من موقع غريب: {dom}",
}


def _ar(s: Signal, reg: Registry) -> str:
    d = s.data
    ent = reg.by_id.get(d.get("entity_id", "")) if d.get("entity_id") else None
    ent_ar = ent.entity_name_ar if ent else "الجهة"
    if s.id == "lookalike":
        return "الرابط " + TECH_AR[d["technique"]].format(ent=ent_ar, dom=d.get("domain", ""), off=d.get("official_domain", ""),
                                                         host=d.get("host", ""), term=d.get("term", ""))
    m = {
        "blocklist_hit": f"الرابط موجود في قائمة روابط احتيال معروفة (Blocklist): {d.get('feed', '')}",
        "gov_impersonation": f"الموقع {d.get('host', '')} يستخدم كلمات حكومية أو شرطية لكنه مو تحت النطاق الحكومي ‎.gov.ae",
        "official_domain_in_url": (f"الرابط يكتب اسم الموقع الرسمي {d.get('official_domain', '')} داخل العنوان عشان يطمّنك، "
                                   f"لكن الموقع الحقيقي هو {d.get('host', '')} ومو رسمي"),
        "ip_host": f"الرابط يستخدم رقم IP بدل اسم موقع: {d.get('host', '')}",
        "punycode": f"اسم الموقع فيه حروف دولية مموّهة (Punycode): {d.get('host_unicode', '')}",
        "suspicious_tld": f"نهاية الموقع .{d.get('suffix', '')} تُستخدم كثير في المواقع المؤقتة والمشبوهة",
        "free_hosting": f"الموقع مستضاف على منصة مجانية ({d.get('platform', '')}) والجهات الرسمية ما تستخدمها",
        "at_symbol": "الرابط فيه علامة @ قبل اسم الموقع، وهذي حيلة معروفة لإخفاء الوجهة الحقيقية",
        "sensitive_path": f"الرابط فيه كلمة استدراج «{d.get('word', '')}» (مثل الدفع أو التحقق أو المخالفات)",
        "url_shortener": f"رابط مختصر ({d.get('domain', '')}) يخفي الوجهة الحقيقية",
        "many_subdomains": f"الرابط فيه {d.get('depth', '')} مستويات فرعية، وهذا أسلوب تمويه",
        "long_url": f"الرابط طويل بشكل غير طبيعي ({d.get('length', '')} حرف)",
        "hyphen_digits": f"اسم الموقع ({d.get('label', '')}) فيه شرطات أو أرقام كثيرة",
        "no_tls": "الرابط يستخدم http بدون تشفير",
        "new_domain": (f"أول شهادة أمان للموقع ظهرت قبل {d.get('age_days', '')} يوم فقط حسب سجل الشهادات (crt.sh)، "
                       "وهذا مؤشر تقريبي على إن الموقع جديد"
                       if d.get("proxy") else
                       f"الموقع مسجّل من {d.get('age_days', '')} يوم فقط حسب سجل النطاقات "
                       f"({'WHOIS' if d.get('path') == 'rdap>whois_ae' else 'RDAP'})"),
        "gsb_match": (f"خدمة التصفح الآمن من Google (Safe Browsing) تصنّف الرابط كـ{d.get('threats_ar', '')}. "
                      f"{d.get('attribution_ar', '')}، والنتيجة غير مضمونة (not guaranteed)"),
        "urlhaus_match": ("الرابط مسجّل في قاعدة URLhaus (abuse.ch) لروابط البرمجيات الخبيثة (Malware) كتطابق كامل للرابط"
                          if d.get("match") == "exact URL" else
                          f"قاعدة URLhaus (abuse.ch) فيها {d.get('url_count', '')} رابط برمجيات خبيثة (Malware) على نفس الموقع، "
                          f"منها {d.get('online', '')} شغّال"),
        "new_certificate": f"شهادة الأمان (TLS) صادرة قبل {d.get('age_days', '')} يوم فقط",
        "gov_suffix": f"النطاق {d.get('domain', '')} تحت ‎.gov.ae وهو مخصص للجهات الحكومية",
        "text_urgency": f"الرسالة فيها ضغط واستعجال: «{d.get('word', '')}»",
        "text_sensitive_request": f"الرسالة تطلب بيانات حساسة: «{d.get('word', '')}» والجهات الرسمية ما تطلبها بهالطريقة",
        "phone_unverified": f"الرقم {d.get('phone', '')} مو موجود في أرقام {ent_ar} الرسمية في سجلنا. هذا ما يعني أكيد إنه مزيّف لأن السجل ممكن يكون ناقص، بس لا تتصل فيه قبل تتأكد من الموقع الرسمي",
        "phone_mobile_for_brand": f"الرقم {d.get('phone', '')} رقم موبايل، و{ent_ar} ما تستخدم أرقام موبايل لخدمة العملاء حسب سجلنا",
        "phone_other_entity": f"الرقم {d.get('phone', '')} تابع لجهة ثانية في السجل ({d.get('other_ar', '')})",
        "listing_unofficial_site": f"النتيجة تدّعي إنها {ent_ar} لكن موقعها ({d.get('domain', '')}) مو من المواقع الرسمية",
        "sensitive_form": f"الصفحة تطلب {d.get('kinds_ar', '')}، والجهات الرسمية ما تطلب هالبيانات من رابط وصلك" + (f" (النموذج يرسل البيانات إلى {'، '.join(d.get('form_domains') or [])})" if d.get("form_domains") else ""),
        "brand_in_page": f"الصفحة تستخدم اسم {ent_ar} («{d.get('term', '')}») لكن الموقع {d.get('host', '')} مو من مواقعها الرسمية",
        "listing_sponsored_unofficial": f"إعلان ممول (Sponsored) باسم {ent_ar} يودّي لموقع مو رسمي ({d.get('domain', '')})",
    }
    return m.get(s.id, s.evidence)


def top_signals(signals: list[Signal], n: int = 3) -> list[Signal]:
    return sorted([s for s in signals if s.available and s.contribution > 0], key=lambda s: -s.contribution)[:n]


def explain(signals: list[Signal], level: str, reg: Registry, official_entity=None, domain: str = "") -> tuple[str, str]:
    lvl_ar = {"low": "منخفض", "medium": "متوسط", "high": "عالٍ"}[level]
    if official_entity is not None and level == "low":
        ar = (f"الخطر {lvl_ar}: {domain} من المواقع الرسمية لـ{official_entity.entity_name_ar} حسب سجل الجهات الرسمية "
              f"(تم التحقق {official_entity.verified_on}). تأكد دايماً إنك كتبت العنوان بنفسك.")
        en = (f"Risk LOW: {domain} is an official domain of {official_entity.entity_name_en} per the official registry "
              f"(verified {official_entity.verified_on}).")
        return ar, en
    tops = top_signals(signals)
    if not tops:
        return (f"الخطر {lvl_ar}: ما لقينا مؤشرات خطر واضحة. هذا ما يعني إن الرابط آمن 100٪، تأكد من المصدر قبل تدخل أي بيانات.",
                "Risk LOW: no clear risk indicators found. This is not a guarantee of safety.")
    ar_lines = [f"الخطر {lvl_ar}. الأسباب:"] + [f"{i}. {_ar(s, reg)}." for i, s in enumerate(tops, 1)]
    en_lines = [f"Risk {level.upper()}. Reasons:"] + [f"{i}. {s.evidence}." for i, s in enumerate(tops, 1)]
    if level != "low":
        ar_lines.append(AMAN_AR)
        en_lines.append(AMAN_EN)
    return "\n".join(ar_lines), "\n".join(en_lines)
