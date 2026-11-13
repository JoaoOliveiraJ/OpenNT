//! Exports Vf: adaptadores finos; a lógica está nos arquivos de assunto
//! do componente (ARQUITETURA, seção 3.1).

pub mod vf_verifier {
    //! Adaptadores do Driver Verifier — a lógica mora em `vf::verifier`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::vf::verifier;
    use crate::rtl::KernelError;

    fn check_nx_pool_type(call: &Call) -> Result<u64, KernelError> {
        verifier::check_nx_pool_type(call.arg(1) as u32, call.arg(2), call.arg(3) as u32);
        Ok(0)
    }

    fn query_dispatch_table(call: &Call) -> Result<u64, KernelError> {
        Ok(verifier::query_dispatch_table(call.arg(1) as u32, call.arg(2) as u32))
    }

    pub static GROUP: Group = Group {
        name: "vf-verifier",
        names: &["VfCheckNxPoolType", "VfQueryDispatchTable"],
        handlers: &[check_nx_pool_type, query_dispatch_table],
        data_exports: &[],
    };
}
