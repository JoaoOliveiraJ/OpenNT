//! Adaptadores do Errata Manager; a lógica mora em `em/provider.rs` e
//! `em/rule.rs`.

pub mod em_errata {
    use crate::ntos::em::{provider, rule};
    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::inc::field::{Field, NtStruct};
    use crate::rtl::KernelError;

    fn optional<T: Copy + 'static>(address: u64) -> Option<&'static Field<T>> {
        // SAFETY: parâmetro de saída opcional do chamador de kernel.
        (address != 0).then(|| unsafe { Field::<T>::at(address) })
    }

    fn client_rule_evaluate(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(rule::evaluate(call.arg(1), call.arg(2), call.arg(3) as u32, optional::<u32>(call.arg(4)))))
    }
    fn provider_register(call: &Call) -> Result<u64, KernelError> {
        let request = provider::Registration { driver_object: call.arg(1), entries: call.arg(2), entry_count: call.arg(3) as u32, callbacks: call.arg(4), callback_count: call.arg(5) as u32 };
        Ok(signed_status(provider::register(&request, optional::<u64>(call.arg(6)))))
    }
    fn provider_deregister(call: &Call) -> Result<u64, KernelError> {
        provider::deregister(call.arg(1));
        Ok(0)
    }

    pub static GROUP: Group = Group {
        name: "em-errata",
        names: &["EmClientRuleEvaluate", "EmProviderRegister", "EmProviderDeregister"],
        handlers: &[client_rule_evaluate, provider_register, provider_deregister],
        data_exports: &[],
    };
}
