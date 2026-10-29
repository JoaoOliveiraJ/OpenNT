# OpenNT branding resources

The SVG sources define the OpenNT wordmarks. The System Properties source is
`dll/cpl/sysdm/resources/reactos-banner.svg`; the About and boot sources are in
this directory. The classic Start menu source is `media/graphics/start_menu_banner.svg`.
The renderer uses the Arial fonts already included in the tree.

To regenerate the eleven bitmap resources from the repository root on Windows:

```bat
npm install --prefix .cache/branding-tools --no-save @resvg/resvg-js pngjs
set "NODE_PATH=%CD%/.cache/branding-tools/node_modules"
node dll/cpl/sysdm/resources/render-banner.js
```

The renderer preserves each resource's dimensions, bitmap format and palette,
including the VGA boot logo's 4-bit RLE encoding and the System Properties alpha
mask. Original copyright attribution remains in the About banner. The VGA
encoding follows Microsoft's [bitmap compression specification](https://learn.microsoft.com/en-us/windows/win32/gdi/bitmap-compression).
