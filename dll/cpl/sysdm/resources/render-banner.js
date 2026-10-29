const fs = require('fs');
const path = require('path');
const { Resvg } = require('@resvg/resvg-js');
const { PNG } = require('pngjs');

const root = path.resolve(__dirname, '../../../..');
const font = {
    loadSystemFonts: false,
    fontFiles: ['arial.ttf', 'arialbd.ttf'].map(name => path.join(root, 'media/fonts', name)),
    defaultFontFamily: 'Arial'
};

function bitmap(template, image, mask)
{
    const { width, height, data } = image;
    const offset = template.readUInt32LE(10);
    const depth = template.readUInt16LE(28);
    const compression = template.readUInt32LE(30);
    if (template.readInt32LE(18) !== width || template.readInt32LE(22) !== height)
        throw new Error('Resource dimensions must remain unchanged');
    if (!((depth === 4 && compression === 2) ||
          (depth === 8 && compression === 0 && mask) ||
          (depth === 24 && compression === 0) ||
          (depth === 32 && compression === 3)))
        throw new Error('Unsupported bitmap resource format');
    if (depth === 32 && (template.readUInt32LE(54) !== 0x00ff0000 ||
                        template.readUInt32LE(58) !== 0x0000ff00 ||
                        template.readUInt32LE(62) !== 0x000000ff ||
                        template.readUInt32LE(66) !== 0xff000000))
        throw new Error('Unexpected bitmap channel masks');

    let pixels;
    if (depth === 4)
    {
        if (width < 3 || width > 254)
            throw new Error('VGA logo width cannot be encoded in one RLE4 literal run');
        const paletteOffset = 14 + template.readUInt32LE(14);
        const palette = Array.from({ length: 16 }, (_, i) => [
            template[paletteOffset + i * 4 + 2],
            template[paletteOffset + i * 4 + 1],
            template[paletteOffset + i * 4]
        ]);
        const rows = [];
        for (let y = height - 1; y >= 0; --y)
        {
            const packed = Buffer.alloc(Math.ceil(width / 4) * 2);
            for (let x = 0; x < width; ++x)
            {
                const src = (y * width + x) * 4;
                let nearest = 0;
                let distance = Infinity;
                for (let i = 0; i < palette.length; ++i)
                {
                    const error = palette[i].reduce((sum, value, channel) =>
                        sum + (value - data[src + channel]) ** 2, 0);
                    if (error < distance)
                    {
                        nearest = i;
                        distance = error;
                    }
                }
                packed[x >> 1] |= nearest << ((x & 1) ? 0 : 4);
            }
            rows.push(Buffer.from([0, width]), packed, Buffer.from([0, 0]));
        }
        rows.push(Buffer.from([0, 1]));
        pixels = Buffer.concat(rows);
    }
    else
    {
        const stride = Math.ceil(width * depth / 32) * 4;
        pixels = Buffer.alloc(stride * height);
        for (let y = 0; y < height; ++y)
        {
            const row = (height - 1 - y) * stride;
            for (let x = 0; x < width; ++x)
            {
                const src = (y * width + x) * 4;
                const dst = row + x * depth / 8;
                if (mask)
                    pixels[dst] = data[src + 3];
                else
                {
                    pixels[dst] = data[src + 2];
                    pixels[dst + 1] = data[src + 1];
                    pixels[dst + 2] = data[src];
                    if (depth === 32)
                        pixels[dst + 3] = data[src + 3];
                }
            }
        }
    }
    const result = Buffer.concat([template.subarray(0, offset), pixels]);
    result.writeUInt32LE(result.length, 2);
    result.writeUInt32LE(pixels.length, 34);
    return result;
}

const assets = [
    ['dll/cpl/sysdm/resources/reactos-banner.svg', [
        ['dll/cpl/sysdm/resources/rosbitmap.bmp', false],
        ['dll/cpl/sysdm/resources/rosbitmap_mask.bmp', true],
        ['base/system/userinit/res/rosbitmap.bmp', false],
        ['base/system/userinit/res/rosbitmap_mask.bmp', true]]],
    ['media/graphics/branding/about.svg', [
        ['dll/win32/shell32/res/bitmaps/reactos.bmp', false],
        ['dll/win32/syssetup/resources/reactos.bmp', false]]],
    ['media/graphics/branding/boot.svg', [['ntoskrnl/inbv/resources/reactos_logo.bmp', false]]],
    ['media/graphics/branding/boot-vga.svg', [['ntoskrnl/inbv/resources/logo.bmp', false]]],
    ['media/graphics/start_menu_banner.svg', [['base/shell/explorer/res/bmp/158.bmp', false]]],
    ['media/graphics/branding/screensaver.svg', [['base/applications/screensavers/logon/res/0.bmp', false]]],
    ['media/graphics/branding/logon.svg', [['base/system/logonui/res/123.bmp', false]]]
];

const outputs = [];
for (const [source, destinations] of assets)
{
    const firstTemplate = fs.readFileSync(path.join(root, destinations[0][0]));
    const svg = fs.readFileSync(path.join(root, source), 'utf8').replace(/<svg\b[^>]*>/, tag => tag
        .replace(/\bwidth="[^"]*"/, `width="${firstTemplate.readInt32LE(18)}"`)
        .replace(/\bheight="[^"]*"/, `height="${firstTemplate.readInt32LE(22)}"`));
    const image = PNG.sync.read(new Resvg(svg, { font }).render().asPng());
    for (const [destination, mask] of destinations)
    {
        const filename = path.join(root, destination);
        outputs.push([filename, bitmap(fs.readFileSync(filename), image, mask)]);
    }
}
for (const [filename, data] of outputs)
{
    fs.writeFileSync(filename, data);
    console.log(path.relative(root, filename));
}
