//! A análise de uma parada pelo log da serial (COM1), sem o alvo: o que o
//! `cargo xtask crash` e o test-boot que falhou com um STOP imprimem.
//!
//! - [`kcrash`]: a linha `*** STOP` (ou a `*** EXCECAO DE KERNEL` da HAL) e o
//!   bloco `[kcrash]`: o código, os parâmetros com o sentido no 19041, onde
//!   parou, o módulo culpado, o componente provável e a pilha com nomes;
//! - [`wdlog`]: o log de erros do watchdog de vídeo que o dxgkrnl entrega
//!   nos dados secundários do bugcheck (os anéis de asserções, erros,
//!   avisos, eventos e rastro);
//! - [`display`]: as apresentações e mudanças de VidPn do WdLog e as
//!   linhas do dwm.exe (a primeira tela);
//! - [`serial`]: as linhas do log (boots, imagens carregadas, dados
//!   secundários);
//! - [`symbolizer`]: os nomes de `módulo+RVA` pelos PDBs públicos e pelo
//!   `kernel.elf`.
//!
//! O log de um boot que não para não tem os dados secundários: o
//! `cargo xtask test-boot --manual-crash` provoca a parada manual pelo
//! teclado no fim da execução para que eles saiam.

pub mod display;
pub mod kcrash;
pub mod serial;
pub mod symbolizer;
pub mod wdlog;

pub use symbolizer::{LogSymbolizer, ModuleRef, ModuleSymbols, NoSymbols};

use kcrash::Crash;
use serial::LoadedImage;

/// O que o relatório mostra.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Options {
    /// Todos os anéis do WdLog e todas as linhas do dwm.
    pub all: bool,
}

/// As linhas do dwm sem `--all`.
const DWM_LINES: usize = 40;

/// O WdLog do log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WdLog {
    /// A linha do registro.
    pub line: usize,
    pub length: usize,
    pub chunks: usize,
    pub sections: Result<Vec<wdlog::Section>, String>,
}

/// Um log analisado.
pub struct Analysis {
    pub lines: Vec<String>,
    pub crash: Option<Crash>,
    /// As imagens carregadas no boot da parada (até ela), ou no último boot.
    pub images: Vec<LoadedImage>,
    pub wdlog: Option<WdLog>,
    pub dwm: display::Dwm,
}

impl Analysis {
    pub fn parse(text: &str) -> Analysis {
        let lines = serial::split(text);
        let crash = kcrash::find_last(&lines);
        let (images_range, records_range) = match &crash {
            Some(crash) => {
                let line = crash.stop.line;
                (serial::boot_start(&lines, line)..line, line..serial::boot_end(&lines, line))
            }
            None => {
                let start = serial::boot_start(&lines, lines.len());
                (start..lines.len(), start..lines.len())
            }
        };
        let images = serial::loaded_images(&lines, images_range);
        let records = serial::secondary_records(&lines, records_range);
        let wdlog = wdlog::find(&records).map(|record| WdLog { line: record.line, length: record.bytes.len(), chunks: record.chunks, sections: wdlog::decode(&record.bytes) });
        let dwm = display::dwm(&lines);
        Analysis { lines, crash, images, wdlog, dwm }
    }

    /// As entradas do WdLog, se ele foi decodificado.
    fn sections(&self) -> &[wdlog::Section] {
        match &self.wdlog {
            Some(WdLog { sections: Ok(sections), .. }) => sections.as_slice(),
            _ => &[],
        }
    }

    /// Os módulos que o relatório cita: os do bloco `[kcrash]`, os dos
    /// parâmetros e os dos endereços de retorno do WdLog, com o caminho e o
    /// tamanho do log quando ele os traz.
    pub fn modules(&self) -> Vec<ModuleRef> {
        let mut names: Vec<String> = self.crash.as_ref().map(|crash| crash.modules(&self.images)).unwrap_or_default();
        for entry in self.sections().iter().flat_map(|section| section.entries.iter()) {
            if let Some(image) = serial::image_at(&self.images, entry.return_address).filter(|image| !image.name.is_empty()) {
                if !names.iter().any(|known| known.eq_ignore_ascii_case(&image.name)) {
                    names.push(image.name.clone());
                }
            }
        }
        names
            .into_iter()
            .map(|name| match serial::image_named(&self.images, &name) {
                Some(image) => ModuleRef { name, path: image.path.clone(), size: Some(image.size) },
                None => ModuleRef { path: name.clone(), name, size: None },
            })
            .collect()
    }

    /// Um endereço pelas imagens do log, com o nome.
    fn locate(&self, address: u64, symbols: &dyn ModuleSymbols, return_address: bool) -> String {
        kcrash::describe_address(address, &self.images, symbols, return_address)
    }

    /// O nome (sem o módulo) do endereço de retorno de uma entrada do WdLog.
    fn name_of(&self, address: u64, symbols: &dyn ModuleSymbols) -> Option<String> {
        let image = serial::image_at(&self.images, address).filter(|image| !image.name.is_empty())?;
        symbols.name(&image.name, address - image.base, true)
    }

    /// O relatório inteiro.
    pub fn report(&self, symbols: &dyn ModuleSymbols, options: Options) -> String {
        let mut output = String::new();
        match &self.crash {
            Some(crash) => {
                output.push_str("== parada\n");
                output.push_str(&crash.summary(&self.images, symbols));
                let stack = crash.stack(symbols);
                if !stack.is_empty() {
                    output.push_str("== pilha do [kcrash]\n");
                    output.push_str(&stack);
                }
            }
            None => output.push_str("== parada\nnenhuma parada no log (*** STOP ou *** EXCECAO DE KERNEL)\n"),
        }
        output.push_str("== WdLog do dxgkrnl\n");
        match &self.wdlog {
            None => output.push_str("o log nao traz o WdLog (dados secundarios do dxgkrnl): sem parada com o dxgkrnl carregado; o test-boot --manual-crash provoca a parada no fim\n"),
            Some(WdLog { sections: Err(error), line, .. }) => output.push_str(&format!("L{}: {error}\n", line + 1)),
            Some(WdLog { sections: Ok(sections), line, length, chunks }) => {
                output.push_str(&format!("registro na L{} ({length} bytes, {chunks} blocos)\n", line + 1));
                let locate = |address: u64| self.locate(address, symbols, true);
                output.push_str(&wdlog::render(sections, &locate, options.all));
                let name_of = |address: u64| self.name_of(address, symbols);
                let rows = display::rows(sections, &name_of);
                output.push_str("== primeira tela: apresentacoes e VidPn no WdLog, por sequencia\n");
                if rows.is_empty() {
                    output.push_str("nenhuma entrada de apresentacao nem de VidPn (sem os nomes do PDB do dxgkrnl elas nao sao reconhecidas)\n");
                } else {
                    output.push_str(&display::render(&rows));
                }
            }
        }
        if self.dwm.pid.is_some() || !self.dwm.lines.is_empty() {
            output.push_str("== dwm e tela\n");
            output.push_str(&display::render_dwm(&self.dwm, &self.lines, if options.all { None } else { Some(DWM_LINES) }));
        }
        output
    }
}

#[cfg(test)]
mod tests {
    use super::symbolizer::Table;
    use super::*;

    const MANUAL: &str = include_str!("../../tests/fixtures/crash/c29-manual.txt");

    fn pdb() -> Table {
        Table::new(&[
            ("dxgkrnl.sys", 0x21e000, "DXGADAPTER::DdiPresentDisplayOnly"),
            ("dxgkrnl.sys", 0x1a1b00, "DpiFdoStartAdapter"),
            ("BasicDisplay.sys", 0xe000, "BASIC_DISPLAY_DRIVER::QueryChildRelations"),
            ("i8042prt.sys", 0x7200, "I8xProcessCrashDump"),
        ])
    }

    #[test]
    fn the_manual_crash_log_gives_the_whole_report() {
        let analysis = Analysis::parse(MANUAL);
        let crash = analysis.crash.as_ref().expect("parada");
        assert_eq!(crash.stop.code, 0xe2);
        let wdlog = analysis.wdlog.as_ref().expect("WdLog");
        assert_eq!(wdlog.length, 13208);
        let sections = wdlog.sections.as_ref().expect("secoes");
        let errors = sections.iter().find(|section| section.id == wdlog::ERRORS).expect("anel de erros");
        assert_eq!(errors.entries.len(), 13);
        assert_eq!(errors.entries[0].sequence, 0x443);
        let trace = sections.iter().find(|section| section.id == 0x15).expect("anel de rastro");
        let presents: Vec<u64> = trace.entries.iter().filter(|entry| entry.return_address == 0xfffff8010032e00e).map(|entry| entry.parameters[2]).collect();
        assert_eq!(presents, [0x7fd9000, 0x82d9000]);
        let modules: Vec<String> = analysis.modules().into_iter().map(|module| module.name).collect();
        assert!(modules.contains(&"dxgkrnl.sys".to_string()) && modules.contains(&"BasicDisplay.sys".to_string()), "{modules:?}");
        let text = analysis.report(&pdb(), Options::default());
        assert!(text.contains("codigo 0x000000e2 MANUALLY_INITIATED_CRASH"), "{text}");
        assert!(text.contains("anel de erros (0x12): 13 entradas"), "{text}");
        assert!(text.contains("  seq=0x4 thr=ffffc000c00017f0 dxgkrnl.sys+0x1a1b2f (DpiFdoStartAdapter+0x2f)  p=1 ffffffffc00000bb 0 0 0  [STATUS_NOT_SUPPORTED]"), "{text}");
        assert!(text.contains("BasicDisplay.sys+0xeb75 (BASIC_DISPLAY_DRIVER::QueryChildRelations+0xb75)"), "{text}");
        // Por sequência: a 0x871 é a primeira apresentação (a origem do
        // cdd); a 0x892 apresenta outra origem.
        assert!(text.contains("seq=0x871 thr=091100 DXGADAPTER::DdiPresentDisplayOnly+0xe p=0 0 82d9000 0 1\n"), "{text}");
        assert!(text.contains("seq=0x892 thr=091100 DXGADAPTER::DdiPresentDisplayOnly+0xe p=0 0 7fd9000 0 1 NOVA-ORIGEM\n"), "{text}");
        assert!(text.contains("dwm.exe: pid 504"), "{text}");
        assert!(!text.contains("anel de rastro (0x15)"), "{text}");
        let text = analysis.report(&pdb(), Options { all: true });
        assert!(text.contains("anel de rastro (0x15)"), "{text}");
    }

    #[test]
    fn a_log_without_a_stop_says_so() {
        let analysis = Analysis::parse("[OpenNT] kernel 64-bit vivo\n[boot] fase 1\n");
        assert!(analysis.crash.is_none() && analysis.wdlog.is_none());
        let text = analysis.report(&NoSymbols, Options::default());
        assert!(text.contains("nenhuma parada no log"), "{text}");
        assert!(text.contains("--manual-crash"), "{text}");
        assert!(!text.contains("== dwm"), "{text}");
    }
}
