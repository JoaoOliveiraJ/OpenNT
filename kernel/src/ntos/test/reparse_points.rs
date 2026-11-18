//! Autotestes dos reparse points do volume de boot (o NTFS do kernel,
//! `drivers/fs/ntfs_reparse.rs`) e do STATUS_REPARSE na abertura
//! (`io/reparse.rs`), pelos serviços de modo usuário no D: (o mesmo volume
//! do C: no boot do smss), contra o ntfs.sys e o ntoskrnl 19041:
//!
//! - FSCTL_SET_REPARSE_POINT de uma junção (IO_REPARSE_TAG_MOUNT_POINT) num
//!   diretório vazio aberto com FILE_OPEN_REPARSE_POINT; as recusas do
//!   NtfsSetReparsePoint: OutputBufferLength, acesso sem FILE_WRITE_DATA nem
//!   FILE_WRITE_ATTRIBUTES, MOUNT_POINT num arquivo, diretório não vazio e
//!   outra tag sobre o reparse point existente; o SYMLINK pede o
//!   SeCreateSymbolicLinkPrivilege do token;
//! - o atributo $REPARSE_POINT, a FILE_ATTRIBUTE_REPARSE_POINT e a entrada
//!   (tag, referência) do índice $R do `$Extend/$Reparse`;
//! - FSCTL_GET_REPARSE_POINT: o buffer inteiro, STATUS_BUFFER_TOO_SMALL
//!   abaixo de 0x1C bytes e STATUS_BUFFER_OVERFLOW cortado;
//! - FileAttributeTagInformation e a listagem (FileIdBothDirectoryInformation
//!   com a tag no EaSize);
//! - a abertura através da junção (componente intermediário) e da junção
//!   no último componente (o diretório alvo), o NtQueryAttributesFile (que
//!   não segue o último componente), OBJ_DONT_REPARSE
//!   (STATUS_REPARSE_POINT_ENCOUNTERED), uma junção que aponta para si mesma
//!   (as 0x40 voltas do ObpLookupObjectName acabam em
//!   STATUS_OBJECT_NAME_NOT_FOUND), o link simbólico relativo resolvido no
//!   nome aberto através da junção, a política SymlinkEvaluation do
//!   Control\FileSystem e a abertura de modo kernel (ZwCreateFile);
//! - FSCTL_DELETE_REPARSE_POINT (tag errada, ReparseDataLength, a remoção)
//!   e a exclusão de uma junção pelo DELETE_ON_CLOSE, que tira a entrada do $R.

use alloc::string::String;
use alloc::vec::Vec;

use crate::drivers::fs::ntfs::{self, Ntfs};
use crate::drivers::fs::volume_files;
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types as nt;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ps::user::{memory, state};

type Assert = fn(bool, &str);

const MOUNT_POINT: u32 = 0xA000_0003;
const SYMLINK: u32 = 0xA000_000C;
const FSCTL_SET: u32 = 0x0009_00A4;
const FSCTL_GET: u32 = 0x0009_00A8;
const FSCTL_DELETE: u32 = 0x0009_00AC;
const TARGET: &str = "/OPENNTJT";
const JUNCTION: &str = "/OPENNTJL";
const CYCLE: &str = "/OPENNTJC";
const DATA: &[u8] = b"Lido atraves da juncao do OpenNT.\r\n";

/// Os nomes UTF-16 de um REPARSE_DATA_BUFFER.
fn wide(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

/// REPARSE_DATA_BUFFER de uma junção: SubstituteName e PrintName com os
/// NULs, ReparseDataLength = os dois nomes + 12.
fn mount_point(substitute: &str, print: &str) -> Vec<u8> {
    let (substitute, print) = (wide(substitute), wide(print));
    let mut buffer = Vec::new();
    buffer.extend_from_slice(&MOUNT_POINT.to_le_bytes());
    buffer.extend_from_slice(&((substitute.len() + print.len() + 12) as u16).to_le_bytes());
    buffer.extend_from_slice(&[0, 0, 0, 0]);
    buffer.extend_from_slice(&(substitute.len() as u16).to_le_bytes());
    buffer.extend_from_slice(&((substitute.len() + 2) as u16).to_le_bytes());
    buffer.extend_from_slice(&(print.len() as u16).to_le_bytes());
    buffer.extend_from_slice(&substitute);
    buffer.extend_from_slice(&[0, 0]);
    buffer.extend_from_slice(&print);
    buffer.extend_from_slice(&[0, 0]);
    buffer
}

/// REPARSE_DATA_BUFFER de um link simbólico (Flags 1 = relativo).
fn symbolic_link(substitute: &str, print: &str, flags: u32) -> Vec<u8> {
    let (substitute, print) = (wide(substitute), wide(print));
    let mut buffer = Vec::new();
    buffer.extend_from_slice(&SYMLINK.to_le_bytes());
    buffer.extend_from_slice(&((substitute.len() + print.len() + 12) as u16).to_le_bytes());
    buffer.extend_from_slice(&[0, 0, 0, 0]);
    buffer.extend_from_slice(&(substitute.len() as u16).to_le_bytes());
    buffer.extend_from_slice(&(substitute.len() as u16).to_le_bytes());
    buffer.extend_from_slice(&(print.len() as u16).to_le_bytes());
    buffer.extend_from_slice(&flags.to_le_bytes());
    buffer.extend_from_slice(&substitute);
    buffer.extend_from_slice(&print);
    buffer
}

/// As entradas (tag, referência) do índice $R do volume.
fn reparse_index(volume: &Ntfs) -> Vec<(u32, u64)> {
    let mut keys = Vec::new();
    let Ok(Some(entry)) = volume.find("/$Extend/$Reparse") else { return keys };
    let Ok(record) = volume.read_record(entry.reference) else { return keys };
    let Ok(Some(root)) = ntfs::find_attribute(&record, 0x90) else { return keys };
    let value = root.value;
    let end = (16 + ntfs::u32_at(&value, 20) as usize).min(value.len());
    let mut offset = 16 + ntfs::u32_at(&value, 16) as usize;
    while offset + 28 <= end && ntfs::u16_at(&value, offset + 12) & 2 == 0 {
        keys.push((ntfs::u32_at(&value, offset + 16), ntfs::u64_at(&value, offset + 20)));
        offset += (ntfs::u16_at(&value, offset + 8) as usize).max(16);
    }
    keys
}

/// A referência com a sequência de um arquivo do volume.
fn file_reference(volume: &Ntfs, path: &str) -> u64 {
    volume.stat(path).ok().flatten().map_or(0, |stat| stat.reference | (stat.sequence as u64) << 48)
}

/// O bloco de usuário do teste: handle, IOSB, OBJECT_ATTRIBUTES, os
/// argumentos de pilha e os buffers.
struct Harness {
    block: u64,
}

impl Harness {
    const HANDLE: u64 = 0;
    const IOSB: u64 = 0x10;
    const ATTRIBUTES: u64 = 0x100;
    const STRING: u64 = 0x140;
    const TEXT: u64 = 0x180;
    const STACK: u64 = 0x1000;
    const INPUT: u64 = 0x2000;
    const OUTPUT: u64 = 0x2800;
    const LIST: u64 = 0x3000;

    fn at(&self, offset: u64) -> u64 {
        self.block + offset
    }

    fn call(&self, name: &str, a1: u64, a2: u64, a3: u64, a4: u64) -> u32 {
        state::handler(name).map(|handler| handler(a1, a2, a3, a4, self.at(Self::STACK)).unwrap_or(1)).unwrap_or(1)
    }

    fn arguments(&self, values: &[u64]) {
        for (index, value) in values.iter().enumerate() {
            guest::write64(self.at(Self::STACK) + 0x28 + index as u64 * 8, *value);
        }
    }

    fn name(&self, name: &str, flags: u32) -> u64 {
        state::write_user_wide(self.at(Self::TEXT), name);
        state::write_unicode_string(self.at(Self::STRING), self.at(Self::TEXT), name);
        // SAFETY: OBJECT_ATTRIBUTES no bloco de usuário do teste.
        let attributes = unsafe { nt::ObjectAttributes::at(self.at(Self::ATTRIBUTES)) };
        attributes.length.set(nt::ObjectAttributes::SIZE as u32);
        attributes.root_directory.set(0);
        attributes.object_name.set(self.at(Self::STRING));
        attributes.attributes.set(flags);
        attributes.security_descriptor.set(0);
        attributes.security_quality_of_service.set(0);
        self.at(Self::ATTRIBUTES)
    }

    /// NtCreateFile(FILE_OPEN) de `name` com o acesso, o compartilhamento,
    /// as opções e os OBJ_* dados: (status, handle).
    fn open(&self, name: &str, access: u32, share: u32, options: u32, flags: u32) -> (u32, u64) {
        let attributes = self.name(name, flags);
        guest::write64(self.at(Self::HANDLE), 0);
        self.arguments(&[0, 0, share as u64, 1, options as u64, 0, 0]);
        let status = self.call("NtCreateFile", self.at(Self::HANDLE), access as u64, attributes, self.at(Self::IOSB));
        (status, guest::read64(self.at(Self::HANDLE)))
    }

    fn close(&self, handle: u64) {
        let _ = self.call("NtClose", handle, 0, 0, 0);
    }

    /// NtFsControlFile: (status, Information, saída).
    fn control(&self, handle: u64, code: u32, input: &[u8], output_length: u32) -> (u32, u64, Vec<u8>) {
        guest::write_bytes(self.at(Self::INPUT), input);
        guest::write_bytes(self.at(Self::OUTPUT), &[0u8; 0x400]);
        self.arguments(&[self.at(Self::IOSB), code as u64, self.at(Self::INPUT), input.len() as u64, self.at(Self::OUTPUT), output_length as u64]);
        let status = self.call("NtFsControlFile", handle, 0, 0, 0);
        let information = guest::read64(self.at(Self::IOSB) + 8);
        (status, information, guest::read_bytes(self.at(Self::OUTPUT), (information as usize).min(0x400)))
    }

    /// FileAttributeTagInformation do handle: (status, atributos, tag).
    fn attribute_tag(&self, handle: u64) -> (u32, u32, u32) {
        self.arguments(&[35]);
        let status = self.call("NtQueryInformationFile", handle, self.at(Self::IOSB), self.at(Self::OUTPUT), 8);
        (status, guest::read32(self.at(Self::OUTPUT)), guest::read32(self.at(Self::OUTPUT) + 4))
    }

    /// FileNameInformation do handle.
    fn file_name(&self, handle: u64) -> String {
        self.arguments(&[9]);
        if self.call("NtQueryInformationFile", handle, self.at(Self::IOSB), self.at(Self::OUTPUT), 0x200) != 0 {
            return String::new();
        }
        let length = guest::read32(self.at(Self::OUTPUT)) as usize;
        let units: Vec<u16> = guest::read_bytes(self.at(Self::OUTPUT) + 4, length.min(0x1F8)).chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect();
        String::from_utf16_lossy(&units)
    }

    /// NtReadFile do começo de um arquivo síncrono.
    fn read(&self, handle: u64, length: u64) -> Option<Vec<u8>> {
        self.arguments(&[self.at(Self::IOSB), self.at(Self::OUTPUT), length, 0, 0]);
        (self.call("NtReadFile", handle, 0, 0, 0) == 0).then(|| guest::read_bytes(self.at(Self::OUTPUT), guest::read64(self.at(Self::IOSB) + 8) as usize))
    }

    /// NtQueryAttributesFile: (status, FileAttributes).
    fn query_attributes(&self, name: &str) -> (u32, u32) {
        let attributes = self.name(name, 0x40);
        let status = self.call("NtQueryAttributesFile", attributes, self.at(Self::OUTPUT), 0, 0);
        (status, guest::read32(self.at(Self::OUTPUT) + 32))
    }

    /// A primeira entrada de FileIdBothDirectoryInformation de `pattern` no
    /// diretório: (status, atributos, EaSize, nome).
    fn list(&self, directory: u64, pattern: &str) -> (u32, u32, u32, String) {
        state::write_user_wide(self.at(Self::TEXT), pattern);
        state::write_unicode_string(self.at(Self::STRING), self.at(Self::TEXT), pattern);
        self.arguments(&[self.at(Self::IOSB), self.at(Self::LIST), 0x800, 37, 1, self.at(Self::STRING), 1]);
        let status = self.call("NtQueryDirectoryFile", directory, 0, 0, 0);
        // SAFETY: a entrada que o serviço escreveu no buffer do teste.
        let entry = unsafe { nt::FileIdBothDirInformation::at(self.at(Self::LIST)) };
        let length = entry.file_name_length.get() as usize;
        let units: Vec<u16> = guest::read_bytes(self.at(Self::LIST) + 104, length.min(0x200)).chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect();
        (status, entry.file_attributes.get(), entry.ea_size.get(), String::from_utf16_lossy(&units))
    }
}

/// O caminho NT do D: de um caminho do volume.
fn dos(path: &str) -> String {
    alloc::format!("\\??\\D:{}", path.replace('/', "\\"))
}

/// ZwCreateFile de modo kernel de `name`: o caminho no volume do arquivo
/// aberto.
fn kernel_open(name: &str) -> Option<String> {
    use crate::ntos::io::file::zw;
    let block = guest::alloc_bytes(0x400);
    if block == 0 {
        return None;
    }
    let (handle, iosb, attributes, string, text) = (block, block + 0x10, block + 0x40, block + 0x80, block + 0x100);
    let units: Vec<u8> = wide(name);
    guest::write_bytes(text, &units);
    // SAFETY: UNICODE_STRING e OBJECT_ATTRIBUTES no bloco de kernel.
    let (unicode, object) = unsafe { (nt::UnicodeString::at(string), nt::ObjectAttributes::at(attributes)) };
    unicode.length.set(units.len() as u16);
    unicode.maximum_length.set(units.len() as u16);
    unicode.buffer.set(text);
    object.length.set(nt::ObjectAttributes::SIZE as u32);
    object.root_directory.set(0);
    object.object_name.set(string);
    object.attributes.set(0x240);
    object.security_descriptor.set(0);
    object.security_quality_of_service.set(0);
    let opened = zw::create_kernel_file(handle, 0x8010_0000, attributes, iosb, 1, 1, 0x60).unwrap_or(1);
    let value = guest::read64(handle);
    let path = (opened == 0).then(|| zw::file_backing(zw::file_object_of_handle(value)).map(|(_, path)| path)).flatten();
    if opened == 0 {
        zw::close_file_entry(value as u32);
    }
    guest::free_bytes(block);
    path
}

pub fn run(assert: Assert) {
    let Some(volume) = volume_files::volume() else {
        assert(false, "reparse: volume de boot");
        return;
    };
    let Ok(block) = memory::map_user_region(0x4000) else {
        assert(false, "reparse: memoria de usuario");
        return;
    };
    let test = Harness { block };
    for path in ["/OPENNTJT/REL.LNK", "/OPENNTJT/REL2.LNK", "/OPENNTJT/ALVO.TXT", TARGET, JUNCTION, CYCLE] {
        let _ = volume.store_reparse_point(path, None);
        let _ = volume.remove(path);
        volume_files::forget(path);
    }
    let prepared = volume.create(TARGET, true, 0x10, 0).is_ok() && volume.create("/OPENNTJT/ALVO.TXT", false, 0x20, 0).is_ok() && volume.write("/OPENNTJT/ALVO.TXT", 0, DATA).is_ok() && volume.create(JUNCTION, true, 0x10, 0).is_ok() && volume.create(CYCLE, true, 0x10, 0).is_ok();
    assert(prepared, "reparse: diretorios e arquivo do teste no D:");

    // FSCTL_SET_REPARSE_POINT da junção D:\OPENNTJL -> D:\OPENNTJT.
    let buffer = mount_point(&dos(TARGET), "D:\\OPENNTJT");
    let reparse_options = 0x20_4021; // DIRECTORY | SYNCHRONOUS_IO_NONALERT | BACKUP | OPEN_REPARSE_POINT
    let (opened, reader) = test.open(&dos(JUNCTION), 0x0010_0001, 7, reparse_options, 0x40);
    assert(opened == 0 && test.control(reader, FSCTL_SET, &buffer, 0).0 == 0xC000_0022, "reparse: SET sem FILE_WRITE_DATA/ATTRIBUTES -> STATUS_ACCESS_DENIED");
    test.close(reader);
    let (opened, junction) = test.open(&dos(JUNCTION), 0x0011_0103, 7, reparse_options, 0x40);
    assert(opened == 0 && test.control(junction, FSCTL_SET, &buffer, 4).0 == 0xC000_000D, "reparse: SET com OutputBufferLength -> STATUS_INVALID_PARAMETER");
    let set = test.control(junction, FSCTL_SET, &buffer, 0);
    assert(set.0 == 0 && set.1 == 0, "reparse: FSCTL_SET_REPARSE_POINT da juncao");
    assert(volume.reparse_point(JUNCTION).ok().flatten().as_deref() == Some(&buffer[..]), "reparse: $REPARSE_POINT gravado com o buffer");
    let reference = file_reference(&volume, JUNCTION);
    assert(reparse_index(&volume).contains(&(MOUNT_POINT, reference)), "reparse: entrada (tag, referencia) no indice $R do $Extend\\$Reparse");
    assert(volume.stat(JUNCTION).ok().flatten().is_some_and(|stat| stat.attributes & 0x410 == 0x410 && stat.reparse_tag == MOUNT_POINT), "reparse: FILE_ATTRIBUTE_REPARSE_POINT e a tag no stat");
    assert(test.control(junction, FSCTL_SET, &symbolic_link("x", "x", 1), 0).0 == if crate::ntos::se::privilege::single_privilege_check(35, 1) { 0xC000_0277 } else { 0xC000_0061 }, "reparse: SYMLINK sobre a juncao -> TAG_MISMATCH (ou PRIVILEGE_NOT_HELD sem o privilegio)");
    let (tag_status, attributes, tag) = test.attribute_tag(junction);
    assert(tag_status == 0 && attributes & 0x410 == 0x410 && tag == MOUNT_POINT, "reparse: FileAttributeTagInformation da juncao");
    let got = test.control(junction, FSCTL_GET, &[], 0x400);
    assert(got.0 == 0 && got.1 == buffer.len() as u64 && got.2 == buffer, "reparse: FSCTL_GET_REPARSE_POINT devolve o buffer");
    assert(test.control(junction, FSCTL_GET, &[], 0x10).0 == 0xC000_0023, "reparse: GET abaixo de 0x1C bytes -> STATUS_BUFFER_TOO_SMALL");
    let partial = test.control(junction, FSCTL_GET, &[], 0x1C);
    assert(partial.0 == 0x8000_0005 && partial.1 == 0x1C && partial.2[..] == buffer[..0x1C], "reparse: GET cortado -> STATUS_BUFFER_OVERFLOW");
    test.close(junction);
    let (opened, file) = test.open(&dos("/OPENNTJT/ALVO.TXT"), 0x0012_0116, 7, 0x60, 0x40);
    assert(opened == 0 && test.control(file, FSCTL_SET, &mount_point(&dos(TARGET), "D:\\OPENNTJT"), 0).0 == 0xC000_0103, "reparse: MOUNT_POINT num arquivo -> STATUS_NOT_A_DIRECTORY");
    test.close(file);
    let (opened, full) = test.open(&dos(TARGET), 0x0011_0103, 7, reparse_options, 0x40);
    assert(opened == 0 && test.control(full, FSCTL_SET, &mount_point(&dos(CYCLE), "D:\\OPENNTJC"), 0).0 == 0xC000_0101, "reparse: juncao em diretorio nao vazio -> STATUS_DIRECTORY_NOT_EMPTY");
    test.close(full);

    // Listagem: a FILE_ATTRIBUTE_REPARSE_POINT e a tag no EaSize.
    let (opened, root) = test.open("\\??\\D:\\", 0x0010_0001, 7, 0x21, 0x40);
    let (listed, attributes, ea_size, name) = test.list(root, "OPENNTJL");
    assert(opened == 0 && listed == 0 && name == "OPENNTJL" && attributes & 0x410 == 0x410 && ea_size == MOUNT_POINT, "reparse: listagem com FILE_ATTRIBUTE_REPARSE_POINT e a tag no EaSize");
    test.close(root);

    // Aberturas através da junção.
    let (opened, through) = test.open(&dos("/OPENNTJL/ALVO.TXT"), 0x8010_0000, 1, 0x60, 0x40);
    assert(opened == 0 && test.read(through, 0x100).as_deref() == Some(DATA) && test.file_name(through).eq_ignore_ascii_case("\\OPENNTJT\\ALVO.TXT"), "reparse: abertura pelo componente intermediario abre o arquivo do alvo");
    test.close(through);
    let (opened, target) = test.open(&dos(JUNCTION), 0x0010_0001, 7, 0x20, 0x40);
    let (listed, _, _, name) = test.list(target, "ALVO.TXT");
    assert(opened == 0 && listed == 0 && name == "ALVO.TXT", "reparse: juncao no ultimo componente abre o diretorio alvo");
    test.close(target);
    let (queried, attributes) = test.query_attributes(&dos(JUNCTION));
    let (inside, _) = test.query_attributes(&dos("/OPENNTJL/ALVO.TXT"));
    assert(queried == 0 && attributes & 0x410 == 0x410 && inside == 0, "reparse: NtQueryAttributesFile nao segue o ultimo componente e segue o intermediario");
    assert(test.open(&dos("/OPENNTJL/ALVO.TXT"), 0x8010_0000, 1, 0x60, 0x1040).0 == 0xC000_050B, "reparse: OBJ_DONT_REPARSE -> STATUS_REPARSE_POINT_ENCOUNTERED");
    assert(kernel_open(&dos("/OPENNTJL/ALVO.TXT")).is_some_and(|path| path.eq_ignore_ascii_case("/OPENNTJT/ALVO.TXT")), "reparse: ZwCreateFile atravessa a juncao");

    // Uma junção que aponta para si mesma gasta as 0x40 voltas.
    let (opened, cycle) = test.open(&dos(CYCLE), 0x0011_0103, 7, reparse_options, 0x40);
    assert(opened == 0 && test.control(cycle, FSCTL_SET, &mount_point(&dos(CYCLE), "D:\\OPENNTJC"), 0).0 == 0, "reparse: juncao circular gravada");
    test.close(cycle);
    assert(test.open(&dos("/OPENNTJC/X"), 0x8010_0000, 1, 0x60, 0x40).0 == 0xC000_0034, "reparse: o laco de reparses acaba em STATUS_OBJECT_NAME_NOT_FOUND");

    // Links simbólicos: a política, o privilégio do FSCTL e o link relativo
    // resolvido no nome aberto através da junção.
    let enabled = crate::ntos::io::reparse::refresh_enabled_types();
    assert(enabled == 3, "reparse: SymlinkEvaluation do Control\\FileSystem (L2L e L2R)");
    let created = volume.create("/OPENNTJT/REL.LNK", false, 0x20, 0).is_ok() && volume.create("/OPENNTJT/REL2.LNK", false, 0x20, 0).is_ok();
    let (opened, second) = test.open(&dos("/OPENNTJT/REL2.LNK"), 0x0012_0116, 7, 0x20_0060, 0x40);
    let privileged = crate::ntos::se::privilege::single_privilege_check(35, 1);
    assert(created && opened == 0 && test.control(second, FSCTL_SET, &symbolic_link("ALVO.TXT", "ALVO.TXT", 1), 0).0 == if privileged { 0 } else { 0xC000_0061 }, "reparse: SYMLINK de modo usuario pede o SeCreateSymbolicLinkPrivilege");
    test.close(second);
    let linked = volume.store_reparse_point("/OPENNTJT/REL.LNK", Some(&symbolic_link("ALVO.TXT", "ALVO.TXT", 1)));
    let (opened, relative) = test.open(&dos("/OPENNTJL/REL.LNK"), 0x8010_0000, 1, 0x60, 0x40);
    assert(linked.is_ok() && opened == 0 && test.read(relative, 0x100).as_deref() == Some(DATA), "reparse: link relativo pelo nome aberto atraves da juncao");
    test.close(relative);

    // FSCTL_DELETE_REPARSE_POINT e a exclusão de uma junção.
    let (opened, junction) = test.open(&dos(JUNCTION), 0x0011_0103, 7, reparse_options, 0x40);
    let header = |tag: u32, length: u16| {
        let mut bytes = Vec::from(tag.to_le_bytes());
        bytes.extend_from_slice(&length.to_le_bytes());
        bytes.extend_from_slice(&[0, 0]);
        bytes
    };
    assert(opened == 0 && test.control(junction, FSCTL_DELETE, &header(SYMLINK, 0), 0).0 == 0xC000_0277, "reparse: DELETE com outra tag -> STATUS_IO_REPARSE_TAG_MISMATCH");
    assert(test.control(junction, FSCTL_DELETE, &header(MOUNT_POINT, 4), 0).0 == 0xC000_0278, "reparse: DELETE com ReparseDataLength -> STATUS_IO_REPARSE_DATA_INVALID");
    assert(test.control(junction, FSCTL_DELETE, &header(MOUNT_POINT, 0), 0).0 == 0, "reparse: FSCTL_DELETE_REPARSE_POINT");
    let (tag_status, attributes, tag) = test.attribute_tag(junction);
    assert(tag_status == 0 && attributes & 0x400 == 0 && tag == 0 && test.control(junction, FSCTL_GET, &[], 0x400).0 == 0xC000_0275 && !reparse_index(&volume).contains(&(MOUNT_POINT, reference)), "reparse: sem reparse point depois do DELETE (atributo, GET e $R)");
    test.close(junction);
    let cycle_reference = file_reference(&volume, CYCLE);
    let (opened, removed) = test.open(&dos(CYCLE), 0x0011_0000, 7, 0x20_5021, 0x40);
    test.close(removed);
    assert(opened == 0 && matches!(volume.exists(CYCLE), Ok(false)) && !reparse_index(&volume).iter().any(|&(_, entry)| entry == cycle_reference), "reparse: DELETE_ON_CLOSE remove a juncao e a entrada do $R");

    for path in ["/OPENNTJT/REL.LNK", "/OPENNTJT/REL2.LNK", "/OPENNTJT/ALVO.TXT", TARGET, JUNCTION, CYCLE] {
        let _ = volume.remove(path);
        volume_files::forget(path);
    }
    if let Some(region) = memory::find_region(block) {
        memory::release_private_region(&region);
    }
}
