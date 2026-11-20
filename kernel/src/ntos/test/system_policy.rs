//! Self-test do SystemPolicyInformation (classe 134): a cifra, o despachante
//! e os tratadores dos códigos 0 e 5 contra vetores do ntoskrnl 19041 (o
//! despachante real executado fora da máquina com o rdtsc fixo e valores de
//! licença sintéticos), as transições do estado genuíno com relógio
//! sintético e o serviço de modo usuário.

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::ntos::ex::license::policy_cipher;
use crate::ntos::ex::license::system_policy::{self, Environment, GenuineState, LicenseValue, ReplyItems};
use crate::ntos::ke::dispatcher;
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::KernelError;

type Assert = fn(bool, &str);

/// O pedido do código 0 do lsm.dll (SLGetWindowsInformationDWORDWrapper, "Kernel-OneCore-VailGuest").
const LSM_REQUEST: &[&str] = &[
    "2001000099aa86ed104abe09ca6a33dd73ba45ed584ff5e9d185530ddd061da5428568be8c527a867fb39a62a14127b7",
    "e53f4ea6ee4bfeb23d864bdca3f81703399ce89c3a81ced509b26265ad4e282497e8ebda2cecb1bb9451399278ad93a4",
    "e7f72f48ca93adc402060a9747fb4b66090c93208ed537287ffb6f60ab0e9e1e1cf906ad65bff0be2f0c39efccc02b05",
    "ac5c6cff4c793e2f1c8055f2a5c1bc31dd3ee2bbc4866f7f73a27cddd498a62defabfc0520485688617b41047ac0bb25",
    "df0d45dce1353d63fb8fe0892931f548f875423c81527a9f4efad5663150bd02e4813ab594fe403818b0a5fb864a542c",
    "e7b9a21983be0bd9a7b02a0f1507319d2216ed405d9544e06616b80062b950856c2f9e811925f5080fe3b73e76000000",
    "00000000a0000000c998e51ba3a9632e56e1e253e065777c3e263d345fb987ce86a9e7f298088314851e83919dbd3cc3",
    "220c21be4a7805b2ce2d0e0b000000000000000000000000000000000000000000000000000000000000000000000000",
    "000000000000000000000000000000000000000000000000000000000000000000000000000000001d0e0f091b011a18",
    "1e050b19021f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f08000000584ab5b117cb1ec8",
];

/// O claro desse pedido no 19041.
const LSM_PLAIN: &[&str] = &[
    "070000000a0100000400000000000000a0000000959799c42f89c657244e896e58988d2f22d9debf116956dc39f1e644",
    "bb2eb34ca90859239a62566e7bdad3f11e22425300000000000000000000000000000000000000000000000000000000",
    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "0000000014020f0c16191c090315061d1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f080000005e6069ab7f13f107",
    "080000003282dbda4d0c0000320000004b00650072006e0065006c002d004f006e00650043006f00720065002d005600",
    "610069006c00470075006500730074000000040000000000000004000000040000009adb4d0c0000",
];

/// O claro da resposta do 19041 (o valor 1 para todo nome, o sal fixo).
const LSM_REPLY_PLAIN: &[&str] = &[
    "06000000340000000400000000000010080000003282dbda4d0c00000400000004000000040000000100000004000000",
    "04000000040000000000000067452301",
];

/// A resposta cifrada do 19041.
const LSM_OUTPUT: &[&str] = &[
    "480000004bcd3bb98b60268e60fa41915398788883637266b6de87e74fd656efab0dd0c063ac09816addfece74bcf9b0",
    "ae75041856a1c7bf9d23429751ec37b5fcca0d3cdf00000000000000a0000000959799c42f89c657244e896e58988d2f",
    "22d9debf116956dc39f1e644bb2eb34ca90859239a62566e7bdad3f11e22425300000000000000000000000000000000",
    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000014020f0c16191c090315061d1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f",
    "080000005e6069ab7f13f107",
];

/// O pedido do código 5 do trabalhador da marca d'água do explorer.exe (0x72270).
const EXPLORER_REQUEST: &[&str] = &[
    "d8000000f1fac82de033d85ff9c6226d4c42f74dfc145d135e96b501278d88cc29bb5ced53cb5d54c43e3092b0833d3f",
    "b05512cfb4d5fc3e7b626319f4f065f7664cb7042e3be404d665e6fbd65a318c4e8f773da2a04c7721e73dd5ec78cacf",
    "9f735da3f56f720446243cdc82c556ebc3595a0777901e9a479cb3da12da4c36ea04084689ffe64a5f426c2b4aa38b59",
    "b0ae2d84b12a9a348b2ca46a3e3558748f1fca1b094a5d346b5d1d9c38459e47c7397d365b74901991236ead6d1a0a43",
    "18edda3ddc5951ed029fdc70735e33e09782c83e1700000000000000a0000000c998e51ba3a9632e56e1e253e065777c",
    "3e263d345fb987ce86a9e7f298088314851e83919dbd3cc3220c21be4a7805b2ce2d0e0b000000000000000000000000",
    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "000000000000000000000000000000001d0e0f091b011a181e050b19021f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f",
    "08000000584ab5b117cb1ec8",
];

/// A resposta do 19041 com o evento já sinalizado (GenuineLocalStatus 0).
const EXPLORER_OUTPUT: &[&str] = &[
    "3000000022e864e1b609147b84a7c869f24d6cc3da9635879c798984d3761b68120d242c1199bbb5f001a45e0c000000",
    "00000000a0000000959799c42f89c657244e896e58988d2f22d9debf116956dc39f1e644bb2eb34ca90859239a62566e",
    "7bdad3f11e22425300000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000000000000000000014020f0c16191c09",
    "0315061d1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f080000005e6069ab7f13f107",
];

/// O claro do lsm sem preenchimento (2 bytes iniciais fora dos blocos).
const HEAD2_REQUEST: &[&str] = &[
    "1a010000b67a893c3eabf0c88bb3793d6d4ae371f2834d44aa52349ce621602bc4f1ae41f65bf29fe1e1a31b9c61968a",
    "dd4675c374a57cc7c048f26ce88c50b4c079aa78f08a3adbe16efba8a89d1d8f476be6cd27171479162ada586f94593f",
    "9eff6992095b0af2bbc954c8378a025b9b6ae34823b1d1eb5f5b5a0802c097cb9a59783f956b13fcfabd311061d5b824",
    "cc236a5997c4b7e754c7dd9d4df7b2f24086639c13124250273c4231f8fd69529c6264954a3b55d997f73aa7be472d2c",
    "a423398d91b860e2bdd98790685ef33c3f791b2376475530ffd6965fe2db8df11084f0e42c9758d6261a4d904120cbea",
    "85c76bc84b451855ff68218e63c8cf8cacdee082826b8f394f71384aaa8e7ec236ccceb0165f7600000000000000a000",
    "0000c998e51ba3a9632e56e1e253e065777c3e263d345fb987ce86a9e7f298088314851e83919dbd3cc3220c21be4a78",
    "05b2ce2d0e0b000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "000000000000000000000000000000000000000000000000000000000000000000001d0e0f091b011a181e050b19021f",
    "1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f08000000584ab5b117cb1ec8",
];

/// A resposta do 19041 a ele.
const HEAD2_OUTPUT: &[&str] = &[
    "480000004bcd3bb98b60268e60fa41915398788883637266b6de87e74fd656efab0dd0c063ac09816addfece74bcf9b0",
    "ae75041856a1c7bf9d23429751ec37b5fcca0d3cdf00000000000000a0000000959799c42f89c657244e896e58988d2f",
    "22d9debf116956dc39f1e644bb2eb34ca90859239a62566e7bdad3f11e22425300000000000000000000000000000000",
    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000014020f0c16191c090315061d1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f",
    "080000005e6069ab7f13f107",
];

/// O claro do lsm com 4 bytes de preenchimento (6 bytes iniciais).
const HEAD6_REQUEST: &[&str] = &[
    "1e010000b67a307a48f7c492aae52749f64a69355cd17b9bc640c3364dcebdf05a47ac3831501e1eadf4bd850a0448be",
    "7a3c0876e1f6b289eeb74836c2d17470c348efd21991469453955390a2936bdb3a1f4594b1553d9a74a0a44710e8b71a",
    "17e965cc1602567a57ee509664d9f700d24ec7ffd9f2622670556164b2ffdc1ec85a278c89237a3e482939dfde5def38",
    "c5626d8e7e1f590cff721985dc01a7b367a0ba10fa38ccbbce2746376f53065b33d0ad2b4a406ed3f41c5b1b5d94fc17",
    "7a475931b5b4433ac1c0e15fa26e3723d143cc89cd59a73d0b9f192c7825ae585ffa9cf0055e43f39a46555ffcf12c9b",
    "ba7b76b85781297d1485bb71bedb1d49df649cc7b47983a76b8dd3c87d1966ccfe386a11f5eded00baeb760000000000",
    "0000a0000000c998e51ba3a9632e56e1e253e065777c3e263d345fb987ce86a9e7f298088314851e83919dbd3cc3220c",
    "21be4a7805b2ce2d0e0b0000000000000000000000000000000000000000000000000000000000000000000000000000",
    "00000000000000000000000000000000000000000000000000000000000000000000000000001d0e0f091b011a181e05",
    "0b19021f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f08000000584ab5b117cb1ec8",
];

/// A resposta do 19041 a ele.
const HEAD6_OUTPUT: &[&str] = &[
    "480000004bcd3bb98b60268e60fa41915398788883637266b6de87e74fd656efab0dd0c063ac09816addfece74bcf9b0",
    "ae75041856a1c7bf9d23429751ec37b5fcca0d3cdf00000000000000a0000000959799c42f89c657244e896e58988d2f",
    "22d9debf116956dc39f1e644bb2eb34ca90859239a62566e7bdad3f11e22425300000000000000000000000000000000",
    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000014020f0c16191c090315061d1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f",
    "080000005e6069ab7f13f107",
];

/// Os itens do lsm com o código 3 (sem tratador no 19041).
const UNKNOWN_REQUEST: &[&str] = &[
    "1a010000b67a893c3eabf0c88bb3b21d258ddaf946e6949160c1e63a2d74a6a11d0ea24bf18ad6cc181a1d454e634b4a",
    "533f6bb703fa094af6d4680f859912ad0635a13a95182e39555210f997b010319cbbca7bf340f33740fbfc9adf2869c5",
    "2bc3f7e31ec30d2fba54fb28cbbc71f2191478784c2ede93f86ad1aaaef41a8653f811895d808d7db029ad45fe097147",
    "dd4269dbf3921c9f4bc1ec21ff1644e1c6a88646e6451d854e998f4ddd740f2cbab956652b61e18275c1c3f88d2221ba",
    "e1e524f5bb969cabd51fc4875a5ddc25620637ae23ca99e91bba2f6df7a3b57c17c26885e945c0fa3e09c5d317e2d38f",
    "05c49456b96d6cd14f29608c42153cda5c5b1c7cb8abd4f3d78e7d1a11201d97fbb77fb6f8717500000000000000a000",
    "0000c998e51ba3a9632e56e1e253e065777c3e263d345fb987ce86a9e7f298088314851e83919dbd3cc3220c21be4a78",
    "05b2ce2d0e0b000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "000000000000000000000000000000000000000000000000000000000000000000001d0e0f091b011a181e050b19021f",
    "1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f08000000584ab5b117cb1ec8",
];

/// A resposta do tratador padrão do 19041 (E_NOTIMPL).
const UNKNOWN_OUTPUT: &[&str] = &[
    "18000000740ed2fcf7ef159a647afc386d3ed867cc00000000000000a0000000959799c42f89c657244e896e58988d2f",
    "22d9debf116956dc39f1e644bb2eb34ca90859239a62566e7bdad3f11e22425300000000000000000000000000000000",
    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000014020f0c16191c090315061d1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f",
    "080000005e6069ab7f13f107",
];


/// O sal das respostas dos vetores (o rdtsc fixado na execução do 19041).
const SALT: u64 = 0x0123_4567_89AB_CDEF;
/// O OutputDataSize dos chamadores (o tamanho exato da resposta).
const LSM_CAPACITY: u32 = 0xFC;
const EXPLORER_CAPACITY: u32 = 0xE4;

fn bytes(parts: &[&str]) -> Vec<u8> {
    let text: String = parts.concat();
    let digit = |byte: u8| match byte {
        b'0'..=b'9' => byte - b'0',
        _ => byte - b'a' + 10,
    };
    text.as_bytes().chunks_exact(2).map(|pair| digit(pair[0]) << 4 | digit(pair[1])).collect()
}

fn read_u32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

/// Os três blobs `u32 tamanho, bytes` de um pedido ou resposta.
fn blobs(message: &[u8]) -> (&[u8], &[u8], &[u8]) {
    let first = read_u32(message, 0) as usize;
    let second = read_u32(message, 4 + first) as usize;
    let third = read_u32(message, 8 + first + second) as usize;
    (&message[4..4 + first], &message[8 + first..8 + first + second], &message[12 + first + second..12 + first + second + third])
}

/// Os itens do claro de um pedido.
fn plain_items(plain: &[u8]) -> Vec<Vec<u8>> {
    let mut items = Vec::new();
    let mut at = 8;
    for _ in 0..read_u32(plain, 0) {
        let length = read_u32(plain, at) as usize;
        items.push(plain[at + 4..at + 4 + length].to_vec());
        at += 4 + length;
    }
    items
}

/// Um claro com estes itens (a contagem declarada à parte) e o preenchimento.
fn plain_of(items: &[Vec<u8>], declared: u32, padding: usize) -> Vec<u8> {
    let body: Vec<u8> = items.iter().flat_map(|item| (item.len() as u32).to_le_bytes().into_iter().chain(item.iter().copied())).collect();
    let mut plain = Vec::new();
    plain.extend_from_slice(&declared.to_le_bytes());
    plain.extend_from_slice(&(body.len() as u32).to_le_bytes());
    plain.extend_from_slice(&body);
    plain.resize(plain.len() + padding, 0);
    plain
}

/// O valor de cada nome nos vetores: tipo 4, tamanho 4 e o mesmo DWORD
/// (como a consulta sintética da execução do 19041).
static UNIFORM_VALUE: AtomicU32 = AtomicU32::new(1);
/// O Security-SPP-GenuineLocalStatus das transições.
static GENUINE_LOCAL_STATUS: AtomicU32 = AtomicU32::new(0);
static UPTIME_MS: AtomicU64 = AtomicU64::new(1000);
static PUBLISHED: AtomicU32 = AtomicU32::new(0);

fn uniform_value(_name: &[u16], capacity: Option<u32>, _value_type: u32, _result_length: u32) -> Result<LicenseValue, KernelError> {
    let size = capacity.unwrap_or(0) as usize;
    let mut data = alloc::vec![0u8; size];
    let status = if size < 4 {
        0xC000_0023
    } else {
        data[..4].copy_from_slice(&UNIFORM_VALUE.load(Ordering::SeqCst).to_le_bytes());
        0
    };
    Ok(LicenseValue { status, value_type: 4, result_length: 4, data })
}

/// Os valores das transições: o status genuíno, o tipo de notificação 2 e
/// a lista de três identificadores; o resto é ausente.
fn named_value(name: &[u16], capacity: Option<u32>, value_type: u32, result_length: u32) -> Result<LicenseValue, KernelError> {
    let size = capacity.unwrap_or(0) as usize;
    let text = String::from_utf16_lossy(name);
    let found: Option<(u32, Vec<u8>)> = match text.as_str() {
        "Security-SPP-GenuineLocalStatus" => Some((4, GENUINE_LOCAL_STATUS.load(Ordering::SeqCst).to_le_bytes().to_vec())),
        "Kernel-NonGenuineNotificationType" => Some((4, 2u32.to_le_bytes().to_vec())),
        "Kernel-NonGenuineNotificationStringIds" => Some((3, [0x1111_0001u32, 0x2222_0002, 0x3333_0003].iter().flat_map(|entry| entry.to_le_bytes()).collect())),
        _ => None,
    };
    let Some((kind, value)) = found else { return Ok(LicenseValue { status: 0xC000_0034, value_type, result_length, data: alloc::vec![0; size] }) };
    let mut data = alloc::vec![0u8; size];
    let status = if size < value.len() {
        0xC000_0023
    } else {
        data[..value.len()].copy_from_slice(&value);
        0
    };
    Ok(LicenseValue { status, value_type: kind, result_length: value.len() as u32, data })
}

fn fixed_salt() -> u64 {
    SALT
}

fn uptime() -> u64 {
    UPTIME_MS.load(Ordering::SeqCst)
}

fn count_publication() {
    PUBLISHED.fetch_add(1, Ordering::SeqCst);
}

fn no_notification_key() -> bool {
    false
}

const VECTORS: Environment = Environment { query_value: uniform_value, timestamp: fixed_salt, uptime_ms: uptime, publish_non_genuine: count_publication, notification_key_present: no_notification_key };
const TRANSITIONS: Environment = Environment { query_value: named_value, timestamp: fixed_salt, uptime_ms: uptime, publish_non_genuine: count_publication, notification_key_present: no_notification_key };

fn dispatched(request: &[u8], capacity: u32, environment: &Environment, state: &GenuineState) -> Result<Vec<u8>, u32> {
    system_policy::dispatch(request, capacity, environment, state).unwrap_or(Err(0xDEAD))
}

fn plain_dispatched(plain: &[u8], environment: &Environment, state: &GenuineState) -> Result<ReplyItems, u32> {
    system_policy::dispatch_plain(plain, LSM_CAPACITY, environment, state).unwrap_or(Err(0xDEAD))
}

/// A cifra contra o 19041: a decifração do pedido do lsm e a cifração da
/// resposta dele com os parâmetros e a chave que vieram no pedido.
fn cipher_vectors(assert: Assert) {
    let request = bytes(LSM_REQUEST);
    let (data, parameters, key) = blobs(&request);
    let (Ok(parameters), Ok(key)) = (<&policy_cipher::Parameters>::try_from(parameters), <&policy_cipher::Key>::try_from(key)) else {
        assert(false, "systempolicy: blobs do pedido do lsm");
        return;
    };
    let (encrypted, stored) = data.split_at(data.len() - 8);
    let plain = policy_cipher::decrypt_request(encrypted, parameters, key);
    assert(plain == bytes(LSM_PLAIN) && policy_cipher::checksum(&plain) as u64 == u64::from_le_bytes(stored.try_into().unwrap_or([0xFF; 8])), "systempolicy: o pedido do lsm decifra como no 19041, com o conferidor");
    let reply_plain = bytes(LSM_REPLY_PLAIN);
    let output = bytes(LSM_OUTPUT);
    let (reply_data, reply_parameters, reply_key) = blobs(&output);
    let items = plain_items(&plain);
    let (Ok(item_parameters), Ok(item_key)) = (<&policy_cipher::Parameters>::try_from(&items[1][..]), <&policy_cipher::Key>::try_from(&items[2][..])) else {
        assert(false, "systempolicy: itens 1 e 2 do pedido do lsm");
        return;
    };
    let (reply_encrypted, reply_stored) = reply_data.split_at(reply_data.len() - 8);
    assert(reply_parameters == &item_parameters[..] && reply_key == &item_key[..] && policy_cipher::encrypt_reply(&reply_plain, item_parameters, item_key) == reply_encrypted && policy_cipher::checksum(&reply_plain) as u64 == u64::from_le_bytes(reply_stored.try_into().unwrap_or([0xFF; 8])), "systempolicy: a resposta cifra como no 19041");
}

/// O despachante inteiro contra o 19041: código 0 (com e sem bytes iniciais
/// fora dos blocos), código 5 com o evento já sinalizado e um código sem
/// tratador.
fn dispatch_vectors(assert: Assert, state: &GenuineState) {
    UNIFORM_VALUE.store(1, Ordering::SeqCst);
    UPTIME_MS.store(1000, Ordering::SeqCst);
    assert(dispatched(&bytes(LSM_REQUEST), LSM_CAPACITY, &VECTORS, state) == Ok(bytes(LSM_OUTPUT)), "systempolicy: código 0 do lsm igual ao 19041");
    assert(dispatched(&bytes(HEAD2_REQUEST), LSM_CAPACITY, &VECTORS, state) == Ok(bytes(HEAD2_OUTPUT)) && dispatched(&bytes(HEAD6_REQUEST), LSM_CAPACITY, &VECTORS, state) == Ok(bytes(HEAD6_OUTPUT)), "systempolicy: claros fora do múltiplo de 8 iguais ao 19041");
    assert(dispatched(&bytes(UNKNOWN_REQUEST), LSM_CAPACITY, &VECTORS, state) == Ok(bytes(UNKNOWN_OUTPUT)), "systempolicy: código sem tratador responde E_NOTIMPL como o 19041");
    // O código 5 espera o evento: sinalizado antes, com o status genuíno 0
    // (não zera o evento), a espera e o mutant voltam de imediato.
    UNIFORM_VALUE.store(0, Ordering::SeqCst);
    dispatcher::set_event(state.event());
    assert(dispatched(&bytes(EXPLORER_REQUEST), EXPLORER_CAPACITY, &VECTORS, state) == Ok(bytes(EXPLORER_OUTPUT)) && dispatcher::read_state(state.event()) == 1, "systempolicy: código 5 do explorer igual ao 19041");
    dispatcher::reset_event(state.event());
}

/// Os status de recusa, iguais aos do 19041 para os mesmos pedidos.
fn refusals(assert: Assert, state: &GenuineState) {
    UNIFORM_VALUE.store(1, Ordering::SeqCst);
    let request = bytes(LSM_REQUEST);
    let first = read_u32(&request, 0) as usize;
    let mut checksum = request.clone();
    checksum[4 + first - 8] ^= 1;
    let mut key = request[..request.len() - 12].to_vec();
    key.extend_from_slice(&7u32.to_le_bytes());
    key.extend_from_slice(&request[request.len() - 8..request.len() - 1]);
    let mut extra = request.clone();
    extra.push(0);
    assert(dispatched(&checksum, LSM_CAPACITY, &VECTORS, state) == Err(0xC000_0001) && dispatched(&key, LSM_CAPACITY, &VECTORS, state) == Err(0xC000_0001), "systempolicy: conferidor errado e chave curta são STATUS_UNSUCCESSFUL");
    assert(dispatched(&request[..request.len() - 1], LSM_CAPACITY, &VECTORS, state) == Err(0xC000_003E) && dispatched(&extra, LSM_CAPACITY, &VECTORS, state) == Err(0xC000_003E) && dispatched(&request[..3], LSM_CAPACITY, &VECTORS, state) == Err(0xC000_003E), "systempolicy: blobs que não fecham com o pedido são STATUS_DATA_ERROR");
    // Claros válidos com itens errados.
    let items = plain_items(&bytes(LSM_PLAIN));
    let count = items.len() as u32;
    let with = |index: usize, item: Vec<u8>| {
        let mut changed = items.clone();
        changed[index] = item;
        changed
    };
    let status = |plain: Vec<u8>| plain_dispatched(&plain, &VECTORS, state).err();
    assert(status(plain_of(&items, count + 1, 0)) == Some(0xC000_003E) && status(plain_of(&items, count, 8)) == Some(0xC000_003E), "systempolicy: contagem errada e preenchimento de 8 bytes");
    assert(status(plain_of(&with(0, alloc::vec![0, 0]), count, 0)) == Some(0xC000_0023) && status(plain_of(&items[..2], 2, 0)) == Some(0xC000_000D) && status(plain_of(&items[..3], 3, 0)) == Some(0xC000_000D), "systempolicy: código de 2 bytes, dois itens e o código 0 sem o item 3");
    let mut odd = items[4].clone();
    odd.push(0);
    assert(status(plain_of(&with(3, items[3][..7].to_vec()), count, 0)) == Some(0xC000_0023) && status(plain_of(&with(4, odd), count, 0)) == Some(0xC000_003E), "systempolicy: u64 de 7 bytes e nome de tamanho ímpar");
    // A resposta do código 0: status com o bit 28, o u64, o tipo, o valor, o
    // tamanho e o último item zero.
    let reply = plain_dispatched(&bytes(LSM_PLAIN), &VECTORS, state);
    assert(reply.as_ref().is_ok_and(|reply| reply.count() == 6 && reply.item(0) == Some(&0x1000_0000u32.to_le_bytes()[..]) && reply.item(1) == Some(&items[3][..]) && reply.item(2) == Some(&4u32.to_le_bytes()[..]) && reply.item(3) == Some(&1u32.to_le_bytes()[..]) && reply.item(4) == Some(&4u32.to_le_bytes()[..]) && reply.item(5) == Some(&0u32.to_le_bytes()[..])), "systempolicy: itens da resposta do código 0");
}

/// O estado não genuíno no relógio sintético: a WNF depois de 2,5 h, o
/// evento sinalizado depois de 3,17 h com quem espera (o código 5), o modo
/// de notificação pela lista de identificadores e o evento zerado quando a
/// cópia volta a genuína.
fn genuine_transitions(assert: Assert) {
    let Ok(state) = GenuineState::new() else {
        assert(false, "systempolicy: estado genuíno das transições");
        return;
    };
    let plain = bytes(LSM_PLAIN);
    let items = plain_items(&plain);
    GENUINE_LOCAL_STATUS.store(0, Ordering::SeqCst);
    PUBLISHED.store(0, Ordering::SeqCst);
    let start = 1000u64;
    // O nome do lsm não existe aqui: a consulta falha antes da verificação.
    UPTIME_MS.store(start, Ordering::SeqCst);
    assert(plain_dispatched(&plain, &TRANSITIONS, &state).err() == Some(0xC000_0034) && PUBLISHED.load(Ordering::SeqCst) == 0, "systempolicy: valor ausente volta STATUS_OBJECT_NAME_NOT_FOUND");
    let mut genuine_items = items.clone();
    genuine_items[4] = "Security-SPP-GenuineLocalStatus\0".encode_utf16().flat_map(|unit| unit.to_le_bytes()).collect();
    let probe = plain_of(&genuine_items, items.len() as u32, 0);
    let check = |uptime: u64| {
        UPTIME_MS.store(uptime, Ordering::SeqCst);
        plain_dispatched(&probe, &TRANSITIONS, &state)
    };
    let seen = check(start).is_ok() && PUBLISHED.load(Ordering::SeqCst) == 0;
    let early = check(start + 8_999_999).is_ok() && PUBLISHED.load(Ordering::SeqCst) == 0;
    let published = check(start + 9_000_000).is_ok() && PUBLISHED.load(Ordering::SeqCst) == 1 && check(start + 9_000_500).is_ok() && PUBLISHED.load(Ordering::SeqCst) == 1;
    assert(seen && early && published, "systempolicy: WNF_OLIC_OS_LICENSE_NON_GENUINE uma vez, depois de 2,5 h não genuíno");
    let without_waiter = check(start + 0xAD_F4FC).is_ok() && dispatcher::read_state(state.event()) == 0;
    assert(without_waiter, "systempolicy: sem o código 5 o evento não é sinalizado");
    // O código 5 (evento sinalizado antes para não bloquear) registra quem
    // espera; o evento volta a zero para a próxima decisão.
    let wait_plain = plain_of(&[5u32.to_le_bytes().to_vec(), items[1].clone(), items[2].clone(), items[3].clone()], 4, 0);
    dispatcher::set_event(state.event());
    let waited = plain_dispatched(&wait_plain, &TRANSITIONS, &state);
    let waited = waited.is_ok_and(|reply| reply.count() == 3 && reply.item(0) == Some(&0x1000_0000u32.to_le_bytes()[..]) && reply.item(1) == Some(&items[3][..]) && reply.item(2) == Some(&0u32.to_le_bytes()[..]));
    dispatcher::reset_event(state.event());
    assert(waited, "systempolicy: código 5 devolve o status da espera, o u64 e o modo");
    let signaled = check(start + 0xAD_F4FC + 10).is_ok_and(|reply| reply.item(5) == Some(&0u32.to_le_bytes()[..])) && dispatcher::read_state(state.event()) == 1 && state.notification() == 0x2222_0002;
    assert(signaled, "systempolicy: depois de 3,17 h não genuíno o evento é sinalizado com o modo do tipo 2");
    // De volta a genuína: a decisão seguinte zera o evento.
    GENUINE_LOCAL_STATUS.store(1, Ordering::SeqCst);
    let back = start + 0xAD_F4FC + 1000;
    let changed = check(back).is_ok() && dispatcher::read_state(state.event()) == 1;
    let reset = check(back + 0xA4_CBFB).is_ok() && dispatcher::read_state(state.event()) == 0;
    assert(changed && reset, "systempolicy: cópia genuína de novo zera o evento na decisão seguinte");
}

/// O serviço de modo usuário: a regra de 0x20 bytes, o InputData ausente,
/// a recusa de um pedido estragado sem tocar no OutputDataSize e a resposta
/// do tratador padrão (sem sal que sobre: igual byte a byte ao 19041).
pub fn user_service(assert: Assert) {
    use crate::ntos::ps::user::{memory, state};
    let Ok(block) = memory::map_user_region(0x2000) else {
        assert(false, "systempolicy: memoria de usuario");
        return;
    };
    let (information, returned, input, output, rsp) = (block, block + 0x40, block + 0x100, block + 0x400, block + 0x1F00);
    guest::write64(rsp + 0x28, 0);
    let query = |length: u64| state::handler("NtQuerySystemInformation").map(|handler| handler(134, information, length, returned, rsp).unwrap_or(1)).unwrap_or(1);
    let request = bytes(UNKNOWN_REQUEST);
    let expected = bytes(UNKNOWN_OUTPUT);
    // SYSTEM_POLICY_INFORMATION de usuário: InputData, OutputData,
    // InputDataSize, OutputDataSize, Version.
    let fill = |input_data: u64, output_data: u64, input_size: u32, output_size: u32| {
        guest::write64(information, input_data);
        guest::write64(information + 8, output_data);
        guest::write32(information + 0x10, input_size);
        guest::write32(information + 0x14, output_size);
        guest::write32(information + 0x18, 0);
        guest::write32(returned, 0);
    };
    fill(0, 0, 0, 0);
    let short = query(0x1F) == 0xC000_0004 && guest::read32(returned) == 0x20;
    fill(0, 0, 0, 0);
    let long = query(0x28) == 0xC000_0004 && guest::read32(returned) == 0x20;
    fill(0, 0, 0, 0);
    let empty = query(0x20) == 0xC000_0023 && guest::read32(returned) == 0x20;
    assert(short && long && empty, "systempolicy: exatamente 0x20 bytes e InputData ausente");
    guest::write_bytes(input, &request);
    let first = read_u32(&request, 0) as usize;
    guest::write8(input + 4 + first as u64 - 8, request[4 + first - 8] ^ 1);
    fill(input, output, request.len() as u32, 0x100);
    let refused = query(0x20) == 0xC000_0001 && guest::read32(information + 0x14) == 0x100;
    guest::write_bytes(input, &request);
    fill(input, output, request.len() as u32, expected.len() as u32 - 1);
    let small = query(0x20) == 0xC000_0023 && guest::read32(information + 0x14) == expected.len() as u32 - 1;
    assert(refused && small, "systempolicy: pedido estragado e OutputData curto não tocam no OutputDataSize");
    fill(input, 0, request.len() as u32, 0);
    let sized = query(0x20) == 0 && guest::read32(information + 0x14) == expected.len() as u32;
    fill(input, output, request.len() as u32, 0x200);
    let answered = query(0x20) == 0 && guest::read32(information + 0x14) == expected.len() as u32 && guest::read_bytes(output, expected.len()) == expected;
    assert(sized && answered, "systempolicy: resposta do tratador padrão no OutputData, com o tamanho");
}

pub fn run(assert: Assert) {
    cipher_vectors(assert);
    let Ok(state) = GenuineState::new() else {
        assert(false, "systempolicy: estado genuíno dos vetores");
        return;
    };
    dispatch_vectors(assert, &state);
    refusals(assert, &state);
    genuine_transitions(assert);
}
