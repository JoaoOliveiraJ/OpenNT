//! vf — o Driver Verifier como o ntoskrnl o vê: consultas e checagens que
//! só agem com o verificador ligado. O OpenNT não tem Driver Verifier;
//! `verifier` reproduz o comportamento do Windows com ele desligado.
pub mod exports;
pub mod verifier;
