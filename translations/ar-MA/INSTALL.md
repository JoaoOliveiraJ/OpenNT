<div dir="rtl" lang="ar">

# تثبيت OpenNT

> [English](../../INSTALL.md) | [中文](../zh-CN/INSTALL.md) | [Français](../fr-FR/INSTALL.md) | [Español](../es-ES/INSTALL.md) | [日本語](../ja-JP/INSTALL.md) | **العربية**

## بناء الصور

جهّز بيئة البناء واضبط عملية بناء كما هو موضّح في [بناء OpenNT بنفسك](README.md#بناء-opennt-بنفسك). ثم ابنِ الصورة التي تحتاجها من مجلد الإخراج، مثلًا ‎`output-Clang-amd64-debug`‎:

| الأمر | ينشئ | استخدمه من أجل |
|---|---|---|
| ‎`ninja bootcd`‎ | ‎`bootcd.iso`‎ | تشغيل OpenNT من صورة قرص مضغوط، أو بدء برنامج إعداد OpenNT منها وتثبيت OpenNT على قرص. |
| ‎`ninja openntimg`‎ | ‎`OpenNT.img`‎ | إقلاع قرص مثبّت عليه OpenNT مسبقًا. يقلع عبر UEFI أو BIOS. |
| ‎`ninja openntvhd`‎ | ‎`OpenNT.vhd`‎، ‎`OpenNT.vhdx`‎ | استخدام القرص المثبّت مسبقًا نفسه في الآلات الافتراضية: VHD في VirtualBox وHyper-V من الجيل الأول، وVHDX في Hyper-V من الجيل الثاني الذي لا يقبل أقراص VHD. |

يبني كل هدف أولًا كل ما يحتاجه، وتُكتب الملفات في مجلد الإخراج.

## التثبيت من قرص الإعداد

أقلع ‎`bootcd.iso`‎ في آلة افتراضية أو على حاسوب، واتبع تعليمات برنامج إعداد OpenNT. يعرض برنامج الإعداد الأقراص كما يفعل برنامج إعداد Windows، ويستطيع إنشاء الأقسام وحذفها وتهيئتها وتقليصها وتوسيعها. ويثبّت OpenNT على NTFS وينشئ قسم نظام EFI الذي يحتاجه.

## استخدام القرص المثبّت مسبقًا

لا يحتاج ‎`OpenNT.img`‎ إلى أي إعداد. شغّله في آلة افتراضية مثل QEMU، أو اكتبه على وحدة USB أو بطاقة SD وأقلع الجهاز منها. استخدم ‎`OpenNT.vhd`‎ للآلات الافتراضية التي تقبل أقراص VHD، و‎`OpenNT.vhdx`‎ للآلات الافتراضية Hyper-V من الجيل الثاني، مع تعطيل الإقلاع الآمن.

يحمل القرص المثبّت مسبقًا أيضًا برنامج إعداد OpenNT. شغّل ‎`C:\<المعمارية>\opennt.exe`‎، مثلًا ‎`C:\arm64\opennt.exe`‎، لتثبيت OpenNT على قرص آخر من النظام قيد التشغيل.

## المساعدة

إذا حدث خطأ ما، فأبلغ عنه في [GitHub Issues](https://github.com/JoaoOliveiraJ/OpenNT/issues) مع ذكر المعمارية ونوع البناء والإيداع الذي بنيته والخطوات التي تؤدي إلى المشكلة. توجد الأدلة والملاحظات في [التوثيق](https://github.com/JoaoOliveiraJ/OpenNT/tree/main/doc)، ويمكنك سؤال الفريق على [GitHub Issues](https://github.com/JoaoOliveiraJ/OpenNT/issues).

</div>
