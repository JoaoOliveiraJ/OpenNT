# OpenNT

**نظام تشغيل NT حر يركز على التوافق مع Windows 10 والإصدارات الأحدث، بما في ذلك برامج تشغيل الأجهزة.**

يطور OpenNT النواة وخدمات النظام وبيئة Win32 والواجهات التي تحتاجها التطبيقات وبرامج التشغيل الحديثة. منصة التطوير الأساسية هي AMD64 ‏(x86-64)، مع الاحتفاظ بمنافذ ARM64 وRISC-V64 والمعماريات الأخرى الموروثة.

دعم برامج تشغيل Windows 10+ هدف قيد التطوير، وليس ضماناً بأن جميع برامج التشغيل تعمل حالياً. يجب اختبار كل برنامج تشغيل على الجهاز الحقيقي وإصدار Windows المستهدف. نجاح الإقلاع في QEMU لا يثبت التوافق مع أجهزة فعلية.

![OpenNT](../../media/graphics/branding/opennt-banner.svg)

## Build / Compilation

```sh
git clone https://github.com/JoaoOliveiraJ/OpenNT.git
cd OpenNT
./configure.sh -a amd64
ninja -C output-Clang-amd64-debug openntimg
```

- [README / current project status](../../README.md)
- [Native Windows build guide](../../doc/build-windows.md)
- [Installation](../../INSTALL.md)
- [Issues](https://github.com/JoaoOliveiraJ/OpenNT/issues)
- [License](../../COPYING) · [Credits and upstream authors](../../CREDITS.md)

OpenNT is derived from LiberNT and ReactOS. Original copyright notices and component licenses are retained.
