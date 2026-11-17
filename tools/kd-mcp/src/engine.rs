//! O dono da sessão com o alvo, do ponto de vista das ferramentas MCP.
//!
//! O `opennt-mcp` sozinho usa o `Standalone` (um `kd_client::Client`, o
//! `xtask` do `--launch` e o log da COM1). A janela do opennt-re hospeda o
//! mesmo servidor com a sessão dela: implementa `Engine` sobre o backend,
//! e a IA e o usuário mexem no mesmo alvo.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use kd_client::analysis::refs::{self, RefKind};
use kd_client::image::{self, ModuleImage};
use kd_client::launcher::{Launch, LaunchOptions};
use kd_client::rsp::Connection;
use kd_client::Client;

/// O que as ferramentas pedem ao dono da sessão.
pub trait Engine {
    /// A sessão viva (erro sem conexão).
    fn client(&mut self) -> Result<&mut Client, String>;
    /// Compila, abre o QEMU pelo `xtask` e anexa; devolve o texto do attach.
    fn launch(&mut self, options: LaunchOptions, timeout: Duration) -> Result<String, String>;
    /// Conecta a um QEMU aberto (`--kd=com2`) e anexa.
    fn connect(&mut self, address: &str, elf: Option<PathBuf>) -> Result<String, String>;
    /// Desliga a sessão (e fecha o QEMU que o próprio dono abriu).
    fn detach(&mut self) -> Result<String, String>;
    /// A raiz do repositório.
    fn root(&self) -> PathBuf;
    /// O log da COM1 (o `serial.log` do build), quando conhecido.
    fn serial_log(&self) -> Option<PathBuf>;
    /// O monitor HMP do QEMU (`127.0.0.1:porta`), quando o dono abriu o QEMU.
    fn monitor_address(&self) -> Option<String>;
    /// O diretório de build em uso.
    fn build_dir(&self) -> Option<PathBuf>;
    /// A sessão e o cache das imagens dos módulos (com os índices de
    /// referências cruzadas) ao mesmo tempo.
    fn parts(&mut self) -> Result<(&mut Client, &mut ImageCache), String>;
    /// Uma ferramenta mudou o estado do alvo (a janela relê a parada).
    fn changed(&mut self) {}
    /// As últimas linhas do `xtask` (build e QEMU).
    fn launch_log(&mut self) -> Vec<String> {
        Vec::new()
    }
}

/// As imagens dos módulos para as buscas (do arquivo desta máquina, do
/// `kernel.elf` ou da memória do alvo) e o índice de referências cruzadas
/// de cada uma, feito uma vez por módulo.
#[derive(Default)]
pub struct ImageCache {
    images: HashMap<u64, Arc<ModuleImage>>,
    xrefs: HashMap<u64, Arc<HashMap<u64, Vec<(u64, RefKind)>>>>,
    elf: Option<Arc<ModuleImage>>,
}

impl ImageCache {
    pub fn clear(&mut self) {
        self.images.clear();
        self.xrefs.clear();
    }

    /// A imagem do módulo que contém `address`.
    pub fn image(&mut self, client: &mut Client, elf: &std::path::Path, address: u64) -> Option<Arc<ModuleImage>> {
        let module = client.symbols.module_at(address)?.clone();
        if let Some(found) = self.images.get(&module.base) {
            return Some(Arc::clone(found));
        }
        let built = if client.symbols.is_kernel(&module) {
            if self.elf.is_none() {
                let bytes = std::fs::read(elf).ok()?;
                self.elf = Some(Arc::new(image::from_elf(&bytes, "kernel").ok()?));
            }
            self.elf.clone()?
        } else if let Some(pe) = &module.image {
            Arc::new(image::from_pe(module.base, module.end, &module.name, pe))
        } else {
            Arc::new(image::from_memory(module.base, module.end, &module.name, &mut |at, length| client.read_memory(at, length).ok().filter(|bytes| !bytes.is_empty())))
        };
        self.images.insert(module.base, Arc::clone(&built));
        Some(built)
    }

    /// O índice de referências cruzadas do módulo que contém `address`.
    pub fn xrefs(&mut self, client: &mut Client, elf: &std::path::Path, address: u64) -> Option<Arc<HashMap<u64, Vec<(u64, RefKind)>>>> {
        let image = self.image(client, elf, address)?;
        if let Some(found) = self.xrefs.get(&image.base) {
            return Some(Arc::clone(found));
        }
        let index = Arc::new(refs::xref_index(&image.instructions(), (image.base, image.base + image.bytes.len() as u64)));
        self.xrefs.insert(image.base, Arc::clone(&index));
        Some(index)
    }
}

/// A sessão do `opennt-mcp` sozinho.
pub struct Standalone {
    pub root: PathBuf,
    pub client: Option<Client>,
    launch: Option<Launch>,
    build: Option<PathBuf>,
    serial: Option<PathBuf>,
    cache: ImageCache,
    log: Vec<String>,
}

impl Standalone {
    pub fn new(root: PathBuf) -> Standalone {
        Standalone { root, client: None, launch: None, build: None, serial: None, cache: ImageCache::default(), log: Vec::new() }
    }

    /// Recolhe a saída do `xtask` (as últimas 200 linhas ficam).
    fn drain_launch(&mut self) {
        if let Some(launch) = self.launch.as_mut() {
            while let Ok(line) = launch.output.try_recv() {
                self.log.push(line);
            }
            if self.log.len() > 200 {
                let cut = self.log.len() - 200;
                self.log.drain(..cut);
            }
        }
    }

    fn open(&mut self, address: &str, elf: PathBuf, timeout: Duration, replay: Option<PathBuf>) -> Result<String, String> {
        let connection = Connection::connect(address, Instant::now() + Duration::from_secs(60))?;
        let mut client = Client::new(connection, self.root.clone(), elf);
        // O monitor do QEMU (snapshots) e, na reprodução, os módulos da gravação.
        client.set_qemu_monitor(self.launch.as_ref().and_then(|launch| launch.monitor.clone()));
        if let Some(recording) = replay {
            let modules = std::fs::read_to_string(kd_client::monitoring::modules_file(&recording)).map(|text| kd_client::monitoring::parse_modules(&text)).unwrap_or_default();
            client.set_replay(modules);
        }
        let text = client.attach(timeout)?;
        self.client = Some(client);
        self.cache.clear();
        Ok(text)
    }
}

impl Engine for Standalone {
    fn client(&mut self) -> Result<&mut Client, String> {
        self.drain_launch();
        self.client.as_mut().ok_or_else(|| "sem sessao com o alvo (use launch ou connect)".to_string())
    }

    fn launch(&mut self, options: LaunchOptions, timeout: Duration) -> Result<String, String> {
        let _ = self.detach();
        let build = options.build_path();
        let mut progress = Vec::new();
        let launch = Launch::start(&options, |line| {
            eprintln!("[opennt-mcp] {line}");
            progress.push(line.to_string());
        })?;
        let address = launch.address.clone();
        self.log = progress.into_iter().rev().take(200).rev().collect();
        self.launch = Some(launch);
        self.serial = Some(build.join("serial.log"));
        self.build = Some(build.clone());
        let replay = kd_client::monitoring::replay_recording(&options.extra, &options.root);
        match self.open(&address, build.join("kernel.elf"), timeout, replay) {
            Ok(text) => Ok(text),
            Err(error) => {
                if let Some(mut launch) = self.launch.take() {
                    launch.stop();
                }
                Err(error)
            }
        }
    }

    fn connect(&mut self, address: &str, elf: Option<PathBuf>) -> Result<String, String> {
        let _ = self.detach();
        let build = self.build.clone().unwrap_or_else(|| self.root.join("build"));
        let elf = elf.unwrap_or_else(|| build.join("kernel.elf"));
        if self.serial.is_none() {
            let log = build.join("serial.log");
            if log.is_file() {
                self.serial = Some(log);
            }
        }
        self.open(address, elf, Duration::from_secs(180), None)
    }

    fn detach(&mut self) -> Result<String, String> {
        let mut text = String::from("sem sessao");
        if let Some(mut client) = self.client.take() {
            text = if self.launch.is_none() { client.detach().unwrap_or_else(|error| format!("detach: {error}")) } else { "sessao encerrada".into() };
        }
        if let Some(mut launch) = self.launch.take() {
            launch.stop();
            text.push_str("; QEMU fechado");
        }
        self.cache.clear();
        Ok(text)
    }

    fn root(&self) -> PathBuf {
        self.root.clone()
    }

    fn serial_log(&self) -> Option<PathBuf> {
        self.serial.clone()
    }

    fn monitor_address(&self) -> Option<String> {
        self.launch.as_ref().and_then(|launch| launch.monitor.clone())
    }

    fn build_dir(&self) -> Option<PathBuf> {
        self.build.clone()
    }

    fn parts(&mut self) -> Result<(&mut Client, &mut ImageCache), String> {
        self.drain_launch();
        let client = self.client.as_mut().ok_or_else(|| "sem sessao com o alvo (use launch ou connect)".to_string())?;
        Ok((client, &mut self.cache))
    }

    fn launch_log(&mut self) -> Vec<String> {
        self.drain_launch();
        self.log.iter().rev().take(40).rev().cloned().collect()
    }
}

impl Drop for Standalone {
    fn drop(&mut self) {
        let _ = self.detach();
    }
}
