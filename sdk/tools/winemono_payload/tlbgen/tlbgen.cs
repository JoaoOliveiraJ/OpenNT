/*
 * PROJECT:     OpenNT Wine Mono payload
 * LICENSE:     MIT (https://spdx.org/licenses/MIT)
 * PURPOSE:     Exports a type library from an assembly with the .NET Framework type library export rules
 * COPYRIGHT:   Copyright 2026 Ahmed ARIF <arif.ing@outlook.com>
 */

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Mono.Cecil;

static class TlbGen
{
    static readonly byte[] NameSpace = { 0x69, 0xf9, 0xcb, 0xc9, 0xda, 0x05, 0x11, 0xd1, 0x94, 0x08, 0x00, 0x00, 0xf8, 0x08, 0x34, 0x60 };

    static ModuleDefinition Module;
    static List<string> PtrAliases = new List<string>();
    static Dictionary<string, string> PtrAliasByTarget = new Dictionary<string, string>();
    static bool UnicodeField;
    static bool AssemblyComVisible = true;
    static ushort[] CompatVersion;
    static ushort CompatMinor;

    static CustomAttribute Attr(ICustomAttributeProvider p, string name)
    {
        return p.HasCustomAttributes ? p.CustomAttributes.FirstOrDefault(a => a.AttributeType.FullName == name) : null;
    }

    static Guid FromHash(byte[] data)
    {
        byte[] hash;
        using (var md5 = MD5.Create())
            hash = md5.ComputeHash(NameSpace.Concat(data).ToArray());
        hash[6] = (byte)((hash[6] & 0x0f) | 0x30);
        hash[8] = (byte)((hash[8] & 0x3f) | 0x80);
        Array.Reverse(hash, 0, 4);
        Array.Reverse(hash, 4, 2);
        Array.Reverse(hash, 6, 2);
        return new Guid(hash.Take(16).ToArray());
    }

    static byte[] Even(List<byte> data)
    {
        if (((NameSpace.Length + data.Count) & 1) != 0)
            data.Add(0);
        return data.ToArray();
    }

    static string ClassName(TypeReference t)
    {
        if (t.DeclaringType != null)
            return ClassName(t.DeclaringType) + "+" + t.Name;
        return string.IsNullOrEmpty(t.Namespace) ? t.Name : t.Namespace + "." + t.Name;
    }

    static string SigClass(TypeReference t)
    {
        return string.IsNullOrEmpty(t.Namespace) ? t.Name : t.Namespace + "." + t.Name;
    }

    static string SigType(TypeReference t)
    {
        if (t is ByReferenceType br)
            return SigType(br.ElementType) + "&";
        if (t is RequiredModifierType rm)
            return "required_modifier " + SigClass(rm.ModifierType) + " " + SigType(rm.ElementType);
        if (t is OptionalModifierType om)
            return "optional_modifier " + SigClass(om.ModifierType) + " " + SigType(om.ElementType);
        if (t is PointerType pt)
            return SigType(pt.ElementType) + "*";
        if (t is ArrayType at)
        {
            if (at.IsVector)
                return SigType(at.ElementType) + "[]";
            if (at.Rank == 0)
                return SigType(at.ElementType) + "[??]";
            return SigType(at.ElementType) + "[" + string.Join(",", at.Dimensions.Select(d => d.LowerBound.HasValue && d.UpperBound.HasValue && d.LowerBound.Value != 0 ? d.LowerBound.Value + "..." + (d.UpperBound.Value + 2) : "")) + "]";
        }
        if (t is GenericInstanceType gi)
            return SigType(gi.ElementType) + "<" + string.Join(",", gi.GenericArguments.Select(SigType)) + ">";
        if (t is GenericParameter gp)
            return (gp.Type == GenericParameterType.Type ? "!" : "!!") + gp.Position;
        switch (t.MetadataType)
        {
        case MetadataType.Void: return "void";
        case MetadataType.Boolean: return "bool";
        case MetadataType.Char: return "wchar";
        case MetadataType.SByte: return "int8";
        case MetadataType.Byte: return "unsigned int8";
        case MetadataType.Int16: return "int16";
        case MetadataType.UInt16: return "unsigned int16";
        case MetadataType.Int32: return "int32";
        case MetadataType.UInt32: return "unsigned int32";
        case MetadataType.Int64: return "int64";
        case MetadataType.UInt64: return "unsigned int64";
        case MetadataType.Single: return "float32";
        case MetadataType.Double: return "float64";
        case MetadataType.UIntPtr: return "unsigned int";
        case MetadataType.IntPtr: return "int";
        case MetadataType.Object: return "class System.Object";
        case MetadataType.String: return "class System.String";
        case MetadataType.TypedByReference: return "refany";
        case MetadataType.ValueType: return "value class " + SigClass(t);
        default:
            var r = t.Resolve();
            return (r != null && r.IsValueType ? "value class " : "class ") + SigClass(t);
        }
    }

    static string SigMethod(MethodDefinition m)
    {
        var s = new StringBuilder();
        if (m.HasThis)
            s.Append("instance ");
        if (m.HasGenericParameters)
            s.Append("generic ");
        s.Append(SigType(m.ReturnType));
        s.Append('(');
        s.Append(string.Join(",", m.Parameters.Select(p => SigType(p.ParameterType))));
        s.Append(')');
        return s.ToString();
    }

    static bool MemberComVisible(ICustomAttributeProvider p)
    {
        var a = Attr(p, "System.Runtime.InteropServices.ComVisibleAttribute");
        return a == null || (bool)a.ConstructorArguments[0].Value;
    }

    static Guid? GuidAttr(TypeDefinition t)
    {
        var a = Attr(t, "System.Runtime.InteropServices.GuidAttribute");
        return a == null ? (Guid?)null : new Guid((string)a.ConstructorArguments[0].Value);
    }

    static Guid InterfaceGuid(TypeDefinition t)
    {
        var g = GuidAttr(t);
        if (g.HasValue)
            return g.Value;
        var data = new List<byte>(Encoding.Unicode.GetBytes(ClassName(t)));
        foreach (var m in t.Methods)
        {
            if (!MemberComVisible(m))
                continue;
            data.AddRange(Encoding.UTF8.GetBytes(SigMethod(m)));
            foreach (var p in m.Parameters)
                data.Add((byte)p.Attributes);
        }
        return FromHash(Even(data));
    }

    static Guid ClassGuid(TypeDefinition t)
    {
        var g = GuidAttr(t);
        if (g.HasValue)
            return g.Value;
        var name = Module.Assembly.Name;
        var data = new List<byte>(Encoding.Unicode.GetBytes(ClassName(t)));
        var asm = name.Name.ToLowerInvariant().Replace('.', '_').Replace(' ', '_');
        data.AddRange(Encoding.Unicode.GetBytes(asm));
        data.AddRange(Encoding.ASCII.GetBytes("TypeLib"));
        ushort major, build, revision, minor;
        if (CompatVersion != null)
        {
            major = CompatVersion[0]; build = CompatVersion[2]; revision = CompatVersion[3]; minor = CompatMinor;
        }
        else
        {
            major = (ushort)name.Version.Major; build = (ushort)name.Version.Build; revision = (ushort)name.Version.Revision; minor = (ushort)name.Version.Minor;
        }
        foreach (var v in new[] { major, major, build, revision })
            data.AddRange(BitConverter.GetBytes(v));
        if (minor != 0)
            data.AddRange(BitConverter.GetBytes(minor));
        if (name.PublicKey != null && name.PublicKey.Length > 0)
            data.AddRange(name.PublicKey);
        return FromHash(Even(data));
    }

    static Guid ClassInterfaceGuid(TypeDefinition t)
    {
        var data = new List<byte>(Encoding.Unicode.GetBytes(ClassName(t)));
        return FromHash(Even(data));
    }

    static bool IsPublic(TypeDefinition t)
    {
        for (; t != null; t = t.DeclaringType)
        {
            if (t.DeclaringType == null ? !t.IsPublic : !t.IsNestedPublic)
                return false;
        }
        return true;
    }

    static bool TypeComVisible(TypeDefinition t)
    {
        var a = Attr(t, "System.Runtime.InteropServices.ComVisibleAttribute");
        if (a != null)
            return (bool)a.ConstructorArguments[0].Value;
        return t.DeclaringType != null ? TypeComVisible(t.DeclaringType) : AssemblyComVisible;
    }

    static bool Exported(TypeDefinition t)
    {
        if (!IsPublic(t) || !TypeComVisible(t))
            return false;
        for (var d = t; d != null; d = d.DeclaringType)
            if (d.HasGenericParameters)
                return false;
        if (t.IsImport)
            return false;
        return t.IsInterface || t.IsClass || t.IsValueType;
    }

    static int ClassInterfaceType(TypeDefinition t)
    {
        var a = Attr(t, "System.Runtime.InteropServices.ClassInterfaceAttribute");
        if (a != null)
            return Convert.ToInt32(a.ConstructorArguments[0].Value);
        var aa = Attr(Module.Assembly, "System.Runtime.InteropServices.ClassInterfaceAttribute");
        return aa != null ? Convert.ToInt32(aa.ConstructorArguments[0].Value) : 1;
    }

    static bool Win64;
    static Dictionary<string, string[]> MemberOrder = new Dictionary<string, string[]>();

    class TDesc
    {
        public int Vt;
        public TDesc Inner;
        public string Lib;
        public string Name;
        public int Kind;

        public static TDesc V(int vt) { return new TDesc { Vt = vt }; }
        public static TDesc Ptr(TDesc t) { return new TDesc { Vt = 26, Inner = t }; }
        public static TDesc Sa(TDesc t) { return new TDesc { Vt = 27, Inner = t }; }
        public static TDesc User(string lib, string name, int kind) { return new TDesc { Vt = 29, Lib = lib, Name = name, Kind = kind }; }

        public string Dump()
        {
            switch (Vt)
            {
            case 26: return Inner.Dump() + "*";
            case 27: return "SAFEARRAY(" + Inner.Dump() + ")";
            case 29: return Lib + "." + Name;
            default: return "vt" + Vt;
            }
        }

        public string Idl()
        {
            switch (Vt)
            {
            case 26: return Inner.Idl() + "*";
            case 27:
                if (Inner.Vt == 26)
                {
                    var alias = "tlbgen_ptr_" + PtrAliases.Count;
                    var target = Inner.Idl();
                    if (!PtrAliasByTarget.TryGetValue(target, out alias))
                    {
                        alias = "tlbgen_ptr_" + PtrAliasByTarget.Count;
                        PtrAliasByTarget[target] = alias;
                        PtrAliases.Add("    typedef " + target + " " + alias + ";");
                    }
                    return "SAFEARRAY(" + alias + ")";
                }
                return "SAFEARRAY(" + Inner.Idl() + ")";
            case 29:
                if (Lib == "stdole")
                    return Name;
                return Kind == 0 ? "enum " + Name : Kind == 1 ? "struct " + Name : Name;
            }
            switch (Vt)
            {
            case 2: return "short";
            case 3: return "long";
            case 4: return "float";
            case 5: return "double";
            case 6: return "CURRENCY";
            case 7: return "DATE";
            case 8: return "BSTR";
            case 9: return "IDispatch*";
            case 10: return "SCODE";
            case 11: return "VARIANT_BOOL";
            case 12: return "VARIANT";
            case 13: return "IUnknown*";
            case 14: return "DECIMAL";
            case 16: return "char";
            case 17: return "unsigned char";
            case 18: return "unsigned short";
            case 19: return "unsigned long";
            case 20: return "__int64";
            case 21: return "unsigned __int64";
            case 22: return "int";
            case 23: return "unsigned int";
            case 24: return "void";
            case 25: return "HRESULT";
            case 30: return "LPSTR";
            case 31: return "LPWSTR";
            }
            throw new Exception("vt " + Vt);
        }
    }

    class Param
    {
        public string Name;
        public int Flags;
        public TDesc Type;
    }

    class Func
    {
        public string Name;
        public int Id;
        public int Inv;
        public TDesc Ret;
        public List<Param> Params = new List<Param>();
        public bool NoValueName;
    }

    class Var
    {
        public string Name;
        public TDesc Type;
        public long Value;
        public bool Const;
    }

    class Entry
    {
        public int Kind;
        public string Name;
        public Guid Guid;
        public int Flags;
        public string FullName;
        public TypeDefinition Type;
        public string Base;
        public List<Func> Funcs = new List<Func>();
        public List<Var> Vars = new List<Var>();
        public List<KeyValuePair<string, int>> Impls = new List<KeyValuePair<string, int>>();
        public bool Dual;
        public bool ClassItf;
    }

    static Dictionary<string, Entry> ByFull = new Dictionary<string, Entry>();
    static Dictionary<string, Entry> ClassItfByFull = new Dictionary<string, Entry>();
    static List<Entry> Entries = new List<Entry>();

    static bool ExportedVisible(TypeDefinition t)
    {
        return t != null && ByFull.ContainsKey(t.FullName);
    }

    static TypeDefinition Res(TypeReference t)
    {
        try { return t.Resolve(); } catch { return null; }
    }

    static int MarshalVt(MarshalInfo mi)
    {
        switch (mi.NativeType)
        {
        case NativeType.Boolean: return 3;
        case NativeType.I1: return 16;
        case NativeType.U1: return 17;
        case NativeType.I2: return 2;
        case NativeType.U2: return 18;
        case NativeType.I4: return 3;
        case NativeType.U4: return 19;
        case NativeType.I8: return 20;
        case NativeType.U8: return 21;
        case NativeType.R4: return 4;
        case NativeType.R8: return 5;
        case NativeType.Currency: return 6;
        case NativeType.BStr: return 8;
        case NativeType.LPStr: return 30;
        case NativeType.LPWStr: return 31;
        case NativeType.IUnknown: return 13;
        case NativeType.IDispatch: return 9;
        case NativeType.Struct: return 12;
        case NativeType.Error: return 25;
        case NativeType.VariantBool: return 11;
        case NativeType.Int: return Win64 ? 20 : 3;
        case NativeType.UInt: return Win64 ? 21 : 19;
        case NativeType.Func: return Win64 ? 20 : 3;
        }
        return -1;
    }

    static TDesc DefaultInterface(TypeDefinition t)
    {
        for (var c = t; c != null; c = c.BaseType == null ? null : Res(c.BaseType))
        {
            if (ClassItfByFull.TryGetValue(c.FullName, out var ci))
                return TDesc.Ptr(TDesc.User("mscorlib", ci.Name, 4));
            var di = Attr(c, "System.Runtime.InteropServices.ComDefaultInterfaceAttribute");
            if (di != null)
            {
                var it = Res((TypeReference)di.ConstructorArguments[0].Value);
                if (ExportedVisible(it))
                    return TDesc.Ptr(TDesc.User("mscorlib", ByFull[it.FullName].Name, ByFull[it.FullName].Kind));
            }
            if (ByFull.ContainsKey(c.FullName))
            {
                foreach (var ii in c.Interfaces)
                {
                    var it = Res(ii.InterfaceType);
                    if (ExportedVisible(it))
                        return TDesc.Ptr(TDesc.User("mscorlib", ByFull[it.FullName].Name, ByFull[it.FullName].Kind));
                }
            }
        }
        return TDesc.V(13);
    }

    static TDesc Map(TypeReference t, MarshalInfo mi, bool field)
    {
        if (t is RequiredModifierType rm)
            return Map(rm.ElementType, mi, field);
        if (t is OptionalModifierType om)
            return Map(om.ElementType, mi, field);
        if (t is ByReferenceType br)
            return TDesc.Ptr(Map(br.ElementType, mi, field));
        if (t is PointerType pt)
            return TDesc.Ptr(Map(pt.ElementType, null, field));
        if (mi != null)
        {
            if (mi is SafeArrayMarshalInfo sa && t is ArrayType sat)
                return TDesc.Sa(sa.ElementType != VariantType.None ? TDesc.V((int)sa.ElementType) : Map(sat.ElementType, null, false));
            if (mi.NativeType == NativeType.IntF)
            {
                if (t.MetadataType == MetadataType.Object)
                    return TDesc.V(13);
            }
            else if (mi.NativeType == NativeType.Array && t is ArrayType lat)
                return TDesc.Ptr(Map(lat.ElementType, null, false));
            else
            {
                int mvt = MarshalVt(mi);
                if (mvt >= 0)
                    return TDesc.V(mvt);
            }
        }
        if (t is ArrayType at)
            return TDesc.Sa(Map(at.ElementType, null, false));
        if (t is GenericInstanceType || t is GenericParameter)
            return TDesc.V(13);
        switch (t.MetadataType)
        {
        case MetadataType.Void: return TDesc.V(24);
        case MetadataType.Boolean: return TDesc.V(field ? 3 : 11);
        case MetadataType.Char: return TDesc.V(field && !UnicodeField ? 17 : 18);
        case MetadataType.SByte: return TDesc.V(16);
        case MetadataType.Byte: return TDesc.V(17);
        case MetadataType.Int16: return TDesc.V(2);
        case MetadataType.UInt16: return TDesc.V(18);
        case MetadataType.Int32: return TDesc.V(3);
        case MetadataType.UInt32: return TDesc.V(19);
        case MetadataType.Int64: return TDesc.V(20);
        case MetadataType.UInt64: return TDesc.V(21);
        case MetadataType.Single: return TDesc.V(4);
        case MetadataType.Double: return TDesc.V(5);
        case MetadataType.String: return TDesc.V(field ? (UnicodeField ? 31 : 30) : 8);
        case MetadataType.Object: return TDesc.V(field ? 13 : 12);
        case MetadataType.IntPtr: return TDesc.V(Win64 ? 20 : 3);
        case MetadataType.UIntPtr: return TDesc.V(Win64 ? 21 : 19);
        }
        var r = Res(t);
        if (r == null)
            return TDesc.V(13);
        switch (r.FullName)
        {
        case "System.Decimal": return TDesc.V(14);
        case "System.DateTime": return TDesc.V(7);
        case "System.Guid": return TDesc.User("stdole", "GUID", 1);
        case "System.Drawing.Color": return TDesc.V(19);
        case "System.Array": return TDesc.Ptr(TDesc.User("mscorlib", "_Array", 4));
        case "System.Collections.IEnumerator": return TDesc.Ptr(TDesc.User("stdole", "IEnumVARIANT", 3));
        }
        if (r.IsEnum)
        {
            if (ExportedVisible(r))
                return TDesc.User("mscorlib", ByFull[r.FullName].Name, 0);
            return Map(r.Fields.First(f => !f.IsStatic).FieldType, null, field);
        }
        if (r.IsValueType)
        {
            if (ExportedVisible(r))
                return TDesc.User("mscorlib", ByFull[r.FullName].Name, 1);
            return TDesc.V(13);
        }
        if (r.IsInterface)
        {
            if (ExportedVisible(r))
                return TDesc.Ptr(TDesc.User("mscorlib", ByFull[r.FullName].Name, ByFull[r.FullName].Kind));
            return TDesc.V(13);
        }
        return DefaultInterface(r);
    }

    static string IdlGuid(Guid g)
    {
        return g.ToString().ToUpperInvariant();
    }

    static bool IsPutRef(TDesc t)
    {
        return t.Vt == 12 || t.Vt == 13 || t.Vt == 9 || (t.Vt == 26 && t.Inner.Vt == 29 && t.Inner.Kind >= 3);
    }

    static int? DispIdOf(ICustomAttributeProvider p)
    {
        var a = Attr(p, "System.Runtime.InteropServices.DispIdAttribute");
        return a == null ? (int?)null : (int)a.ConstructorArguments[0].Value;
    }

    static string ParamName(ParameterDefinition p)
    {
        return string.IsNullOrEmpty(p.Name) ? "param" + (p.Index + 1) : p.Name;
    }

    static void AddMembers(Entry e, IEnumerable<MethodDefinition> methods, string defaultMember)
    {
        var props = new Dictionary<MethodDefinition, PropertyDefinition>();
        foreach (var m in methods)
            foreach (var pr in m.DeclaringType.Properties)
                if (pr.GetMethod == m || pr.SetMethod == m)
                    props[m] = pr;
        var used = new Dictionary<string, int>();
        var propIds = new Dictionary<PropertyDefinition, int>();
        int slot = 0;
        int dispBase = e.Kind == 3 ? 0x60010000 : 0x60020000;
        foreach (var m in methods)
        {
            if (m.HasGenericParameters || !MemberComVisible(m))
                continue;
            props.TryGetValue(m, out var prop);
            if (prop != null && !MemberComVisible(prop))
                continue;
            var f = new Func();
            string name = prop != null ? prop.Name : m.Name;
            var ps = m.Parameters.ToList();
            if (prop != null && m == prop.GetMethod)
                f.Inv = 2;
            else if (prop != null)
            {
                var vt = Map(ps.Last().ParameterType, ps.Last().HasMarshalInfo ? ps.Last().MarshalInfo : null, false);
                f.Inv = IsPutRef(vt) ? 8 : 4;
                f.NoValueName = true;
            }
            else
                f.Inv = m.Name == "ToString" ? 2 : 1;
            if (prop == null || m == prop.GetMethod || !used.ContainsKey(name))
            {
                if (used.TryGetValue(name, out int n) && (prop == null || m == prop.GetMethod))
                {
                    used[name] = n + 1;
                    name = name + "_" + (n + 1);
                }
                else if (!used.ContainsKey(name))
                    used[name] = 1;
            }
            f.Name = name;
            int? id = DispIdOf(m) ?? (prop != null ? DispIdOf(prop) : null);
            if (id.HasValue)
                f.Id = id.Value;
            else if (prop != null && prop.Name == defaultMember)
                f.Id = 0;
            else if (prop != null && propIds.TryGetValue(prop, out int pid))
                f.Id = pid;
            else
                f.Id = dispBase + slot;
            if (prop != null && !propIds.ContainsKey(prop))
                propIds[prop] = f.Id;
            foreach (var p in ps)
            {
                var t = Map(p.ParameterType, p.HasMarshalInfo ? p.MarshalInfo : null, false);
                int flags = p.ParameterType is ByReferenceType ? (p.IsOut && !p.IsIn ? 2 : 3) : 1;
                if (p.IsOut && !(p.ParameterType is ByReferenceType))
                    flags = 2;
                f.Params.Add(new Param { Name = f.NoValueName && p == ps.Last() ? "pRetVal" : ParamName(p), Flags = flags, Type = t });
            }
            f.Ret = Map(m.ReturnType, m.MethodReturnType.HasMarshalInfo ? m.MethodReturnType.MarshalInfo : null, false);
            e.Funcs.Add(f);
            slot++;
        }
        if (!e.Funcs.Any(x => x.Id == 0))
        {
            var ts = e.Funcs.FirstOrDefault(x => x.Name == "ToString" && x.Params.Count == 0 && x.Inv == 2 && !x.NoValueName);
            if (ts != null)
            {
                ts.Id = 0;
                ts.Inv = 2;
            }
        }
        var ge = e.Funcs.FirstOrDefault(x => x.Name == "GetEnumerator" && x.Params.Count == 0 && x.Inv == 1 && !e.Funcs.Any(y => y.Id == -4));
        if (ge != null && ge.Ret.Vt == 26 && ge.Ret.Inner.Vt == 29 && ge.Ret.Inner.Name == "IEnumerator")
            ge.Id = -4;
    }

    static string MemberKey(MethodDefinition m)
    {
        return m.IsSpecialName && (m.Name.StartsWith("get_") || m.Name.StartsWith("set_")) ? m.Name.Substring(4) : m.Name;
    }

    static IEnumerable<MethodDefinition> Ordered(TypeDefinition t, IEnumerable<MethodDefinition> methods)
    {
        string[] order;
        if (!MemberOrder.TryGetValue(t.FullName, out order))
            return methods;
        return methods.Select((m, i) => new { m, i, o = Array.IndexOf(order, MemberKey(m)) })
                      .OrderBy(x => x.o < 0 ? order.Length : x.o).ThenBy(x => x.i).Select(x => x.m);
    }

    static void Build()
    {
        foreach (var t in Module.GetTypes().Where(Exported))
        {
            var e = new Entry { Type = t, Name = t.Name, FullName = t.FullName };
            if (t.IsEnum) { e.Kind = 0; e.Guid = ClassGuid(t); }
            else if (t.IsValueType) { e.Kind = 1; e.Guid = ClassGuid(t); }
            else if (t.IsInterface)
            {
                var it = Attr(t, "System.Runtime.InteropServices.InterfaceTypeAttribute");
                int kind = it == null ? 0 : Convert.ToInt32(it.ConstructorArguments[0].Value);
                e.Kind = kind == 1 ? 3 : 4;
                e.Dual = kind == 0;
                e.Guid = InterfaceGuid(t);
                e.Flags = kind == 1 ? 0x100 : 0x1040;
            }
            else
            {
                e.Kind = 5;
                e.Guid = ClassGuid(t);
                int ci = ClassInterfaceType(t);
                if (ci != 0)
                {
                    var c = new Entry { Kind = 4, Name = "_" + t.Name, FullName = t.FullName, Type = t, Dual = true, ClassItf = true };
                    c.Guid = ClassInterfaceGuid(t);
                    c.Flags = ci == 2 ? 0x10d0 : 0x1050;
                    c.Base = ci == 2 ? "auto-dual" : "auto-dispatch";
                    ClassItfByFull[t.FullName] = c;
                }
            }
            ByFull[t.FullName] = e;
            Entries.Add(e);
        }
        Entries.AddRange(ClassItfByFull.Values);
        foreach (var e in Entries)
        {
            var t = e.Type;
            if (e.Kind == 0)
            {
                foreach (var f in t.Fields.Where(f => f.IsStatic && f.HasConstant))
                    e.Vars.Add(new Var { Name = t.Name + "_" + f.Name, Const = true, Value = Convert.ToInt64(f.Constant), Type = TDesc.V(3) });
            }
            else if (e.Kind == 1)
            {
                UnicodeField = (t.Attributes & TypeAttributes.StringFormatMask) == TypeAttributes.UnicodeClass;
                foreach (var f in t.Fields.Where(f => !f.IsStatic))
                    e.Vars.Add(new Var { Name = f.Name, Type = Map(f.FieldType, f.HasMarshalInfo ? f.MarshalInfo : null, true) });
            }
            if (e.Kind == 3)
                e.Impls.Add(new KeyValuePair<string, int>("IUnknown", 0));
            else if (e.Kind == 4)
                e.Impls.Add(new KeyValuePair<string, int>("IDispatch", 0));
            if (e.Kind == 3 || (e.Kind == 4 && !e.ClassItf))
            {
                var dm = Attr(t, "System.Reflection.DefaultMemberAttribute");
                AddMembers(e, t.Methods, dm == null ? null : (string)dm.ConstructorArguments[0].Value);
            }
            else if (e.ClassItf && e.Base == "auto-dual")
            {
                var chain = new List<TypeDefinition>();
                for (var c = t; c != null; c = c.BaseType == null ? null : Res(c.BaseType))
                    chain.Insert(0, c);
                var methods = chain.SelectMany(c => Ordered(c, c.Methods.Where(m => m.IsPublic && !m.IsStatic && !m.IsConstructor && !(m.IsVirtual && !m.IsNewSlot && c != chain[0])))).ToList();
                AddMembers(e, methods, null);
                var data = new List<byte>(Encoding.Unicode.GetBytes(ClassName(t)));
                foreach (var m in methods.Where(m => !m.HasGenericParameters && MemberComVisible(m)))
                {
                    data.AddRange(Encoding.UTF8.GetBytes(SigMethod(m)));
                    foreach (var p in m.Parameters)
                        data.Add((byte)p.Attributes);
                }
                e.Guid = FromHash(Even(data));
            }
            else if (e.Kind == 5)
            {
                bool create = !t.IsAbstract && t.Methods.Any(m => m.IsConstructor && !m.IsStatic && m.IsPublic && m.Parameters.Count == 0);
                e.Flags = create ? 2 : 0;
                var seen = new HashSet<string>();
                if (ClassItfByFull.TryGetValue(t.FullName, out var own))
                {
                    e.Impls.Add(new KeyValuePair<string, int>(own.Name, 1));
                    seen.Add(own.Name);
                }
                var di = Attr(t, "System.Runtime.InteropServices.ComDefaultInterfaceAttribute");
                for (var c = t; c != null; c = c.BaseType == null ? null : Res(c.BaseType))
                {
                    if (c != t && ClassItfByFull.TryGetValue(c.FullName, out var bi) && bi.Base == "auto-dual" && seen.Add(bi.Name))
                        e.Impls.Add(new KeyValuePair<string, int>(bi.Name, 0));
                }
                for (var c = t; c != null; c = c.BaseType == null ? null : Res(c.BaseType))
                {
                    foreach (var ii in c.Interfaces)
                    {
                        var it = Res(ii.InterfaceType);
                        if (ExportedVisible(it) && seen.Add(ByFull[it.FullName].Name))
                            e.Impls.Add(new KeyValuePair<string, int>(ByFull[it.FullName].Name, 0));
                    }
                }
                if (!e.Impls.Any(x => x.Value == 1) && e.Impls.Count > 0)
                {
                    int idx = e.Impls.FindIndex(x => !ClassItfByFull.Values.Any(c => c.Name == x.Key));
                    if (idx < 0)
                        idx = 0;
                    if (di != null)
                    {
                        var dt = Res((TypeReference)di.ConstructorArguments[0].Value);
                        if (dt != null && ByFull.ContainsKey(dt.FullName) && e.Impls.FindIndex(x => x.Key == ByFull[dt.FullName].Name) >= 0)
                            idx = e.Impls.FindIndex(x => x.Key == ByFull[dt.FullName].Name);
                    }
                    e.Impls[idx] = new KeyValuePair<string, int>(e.Impls[idx].Key, 1);
                }
            }
        }
    }

    static void WriteDump(TextWriter w)
    {
        foreach (var e in Entries)
        {
            w.WriteLine("T {0} {1} {2} funcs={3} vars={4} impl={5} flags={6:x} full={7}", e.Kind, e.Name, e.Guid, e.Funcs.Count + (e.Dual ? 7 : 0), e.Vars.Count, e.Impls.Count, e.Flags, e.FullName);
            foreach (var kv in e.Impls)
                w.WriteLine("  {0} impl flags={1:x} {2}", e.Name, kv.Value, kv.Key);
            int i = e.Dual ? 7 : 0;
            foreach (var f in e.Funcs)
            {
                if (e.Dual)
                {
                    w.WriteLine("  {0} func {1} {2} id={3:x} inv={4} ret={5}", e.Name, i, f.Name, f.Id, f.Inv, f.Inv == 4 || f.Inv == 8 ? "vt24" : f.Ret.Dump());
                    int pi = 0;
                    foreach (var p in f.Params)
                    {
                        w.WriteLine("  {0} func {1} param {2} {3} flags={4:x} type={5}", e.Name, i, pi, f.NoValueName && pi == f.Params.Count - 1 ? "-" : p.Name, p.Flags, p.Type.Dump());
                        pi++;
                    }
                }
                else
                {
                    w.WriteLine("  {0} func {1} {2} id={3:x} inv={4} ret=vt25", e.Name, i, f.Name, f.Id, f.Inv);
                    int pi = 0;
                    foreach (var p in f.Params)
                    {
                        w.WriteLine("  {0} func {1} param {2} {3} flags={4:x} type={5}", e.Name, i, pi, f.NoValueName && pi == f.Params.Count - 1 ? "-" : p.Name, p.Flags, p.Type.Dump());
                        pi++;
                    }
                    if (f.Ret.Vt != 24 && f.Inv != 4 && f.Inv != 8)
                        w.WriteLine("  {0} func {1} param {2} pRetVal flags=a type={3}*", e.Name, i, pi, f.Ret.Dump());
                }
                i++;
            }
            int vi = 0;
            foreach (var v in e.Vars)
            {
                w.WriteLine("  {0} var {1} {2} value={3} type={4}", e.Name, vi, v.Name, v.Const ? v.Value : 0, v.Type.Dump());
                vi++;
            }
        }
    }

    static string IdlName(string name)
    {
        var s = new string(name.Select(c => char.IsLetterOrDigit(c) && c < 128 ? c : '_').ToArray());
        return char.IsDigit(s[0]) ? "_" + s : s;
    }

    static string Custom(Entry e)
    {
        return "custom(0F21F359-AB84-41E8-9A78-36D110E6D2F9, \"" + e.FullName + "\")";
    }

    static string IdlParam(Param p)
    {
        var dir = p.Flags == 2 ? "[out]" : p.Flags == 3 ? "[in, out]" : "[in]";
        return dir + " " + p.Type.Idl() + " " + IdlName(p.Name);
    }

    static void WriteFuncs(TextWriter w, Entry e)
    {
        foreach (var f in e.Funcs)
        {
            var attrs = new List<string> { string.Format("id(0x{0:x8})", f.Id) };
            if (f.Inv == 2) attrs.Add("propget");
            if (f.Inv == 4) attrs.Add("propput");
            if (f.Inv == 8) attrs.Add("propputref");
            var ps = f.Params.Select(IdlParam).ToList();
            if (f.Ret.Vt != 24 && f.Inv != 4 && f.Inv != 8)
                ps.Add("[out, retval] " + f.Ret.Idl() + "* pRetVal");
            w.WriteLine("        [{0}] HRESULT {1}({2});", string.Join(", ", attrs), f.Name, string.Join(", ", ps));
        }
    }

    static IEnumerable<string> Deps(Entry e)
    {
        foreach (var v in e.Vars)
            for (var t = v.Type; t != null; t = t.Inner)
                if (t.Vt == 29 && t.Lib == "mscorlib" && t.Kind <= 1)
                    yield return t.Name;
    }

    static void WriteIdl(TextWriter output, string libName)
    {
        var w = new StringWriter();
        var asm = Module.Assembly.Name;
        var libGuid = new Guid((string)Attr(Module.Assembly, "System.Runtime.InteropServices.GuidAttribute").ConstructorArguments[0].Value);
        var tv = Attr(Module.Assembly, "System.Runtime.InteropServices.TypeLibVersionAttribute");
        string ver = tv != null ? tv.ConstructorArguments[0].Value + "." + tv.ConstructorArguments[1].Value : asm.Version.Major + "." + asm.Version.Minor;
        w.WriteLine("import \"unknwn.idl\";");
        w.WriteLine();
        w.WriteLine("typedef struct tagVARIANT { __int64 v0; __int64 v1; } VARIANT;");
        w.WriteLine("[object, uuid(00020400-0000-0000-C000-000000000046)]");
        w.WriteLine("interface IDispatch : IUnknown { HRESULT GetTypeInfoCount(); HRESULT GetTypeInfo(); HRESULT GetIDsOfNames(); HRESULT Invoke(); }");
        w.WriteLine("[object, uuid(00020404-0000-0000-C000-000000000046)]");
        w.WriteLine("interface IEnumVARIANT : IUnknown { HRESULT Next(); HRESULT Skip(); HRESULT Reset(); HRESULT Clone(); }");
        w.WriteLine();
        w.WriteLine("[uuid({0}), version({1}), custom(90883F05-3D28-11D2-8F17-00A0C9A6186D, \"{2}\")]", IdlGuid(libGuid), ver, asm.FullName);
        w.WriteLine("library {0}", libName);
        w.WriteLine("{");
        w.WriteLine("    importlib(\"stdole2.tlb\");");
        w.WriteLine();
        foreach (var e in Entries.Where(x => x.Kind == 3 || x.Kind == 4))
            w.WriteLine("    interface {0};", e.Name);
        w.WriteLine();
        w.WriteLine("@ALIASES@");
        var done = new HashSet<string>();
        var values = Entries.Where(x => x.Kind <= 1).ToList();
        while (values.Count > 0)
        {
            var next = values.FirstOrDefault(x => Deps(x).All(d => done.Contains(d) || d == x.Name)) ?? values[0];
            values.Remove(next);
            done.Add(next.Name);
            if (next.Kind == 0)
            {
                w.WriteLine("    [uuid({0}), {1}]", IdlGuid(next.Guid), Custom(next));
                w.WriteLine("    enum {0} {{", next.Name);
                w.WriteLine(string.Join(",\n", next.Vars.Select(v => "        " + v.Name + " = " + unchecked((int)v.Value))));
                w.WriteLine("    };");
            }
            else
            {
                w.WriteLine("    [uuid({0}), {1}]", IdlGuid(next.Guid), Custom(next));
                w.WriteLine("    struct {0} {{", next.Name);
                foreach (var v in next.Vars)
                    w.WriteLine("        {0} {1};", v.Type.Idl(), IdlName(v.Name));
                w.WriteLine("    };");
            }
            w.WriteLine();
        }
        foreach (var e in Entries.Where(x => x.Kind == 3 || x.Kind == 4))
        {
            var attrs = new List<string> { "odl", "uuid(" + IdlGuid(e.Guid) + ")" };
            if ((e.Flags & 0x10) != 0) attrs.Add("hidden");
            if (e.Dual) attrs.Add("dual");
            if ((e.Flags & 0x80) != 0) attrs.Add("nonextensible");
            attrs.Add("oleautomation");
            attrs.Add(Custom(e));
            w.WriteLine("    [{0}]", string.Join(", ", attrs));
            w.WriteLine("    interface {0} : {1} {{", e.Name, e.Kind == 3 ? "IUnknown" : "IDispatch");
            WriteFuncs(w, e);
            w.WriteLine("    };");
            w.WriteLine();
        }
        foreach (var e in Entries.Where(x => x.Kind == 5))
        {
            var attrs = new List<string> { "uuid(" + IdlGuid(e.Guid) + ")" };
            if ((e.Flags & 2) == 0) attrs.Add("noncreatable");
            w.WriteLine("    [{0}]", string.Join(", ", attrs));
            w.WriteLine("    coclass {0} {{", e.Name);
            foreach (var kv in e.Impls)
                w.WriteLine("        {0}interface {1};", kv.Value == 1 ? "[default] " : "", kv.Key);
            w.WriteLine("    };");
            w.WriteLine();
        }
        w.WriteLine("};");
        output.Write(w.ToString().Replace("@ALIASES@", string.Join("\n", PtrAliases) + "\n"));
    }

    static void Main(string[] args)
    {
        Module = ModuleDefinition.ReadModule(args[0]);
        Win64 = args[1] == "win64";
        var cv = Attr(Module.Assembly, "System.Runtime.InteropServices.ComVisibleAttribute");
        if (cv != null)
            AssemblyComVisible = (bool)cv.ConstructorArguments[0].Value;
        var cc = Attr(Module.Assembly, "System.Runtime.InteropServices.ComCompatibleVersionAttribute");
        if (cc != null)
        {
            CompatVersion = cc.ConstructorArguments.Select(x => (ushort)(int)x.Value).ToArray();
            CompatMinor = CompatVersion[1];
        }
        foreach (var line in File.ReadAllLines(args[3]).Where(l => l.StartsWith("MemberOrder ")))
            {
                var f = line.Split(' ');
                MemberOrder[f[1]] = f.Skip(2).ToArray();
            }
        Build();
        using (var w = new StreamWriter(args[2]))
            WriteIdl(w, Module.Assembly.Name.Name);
        if (args.Length > 4)
            using (var w = new StreamWriter(args[4]))
                WriteDump(w);
    }
}
