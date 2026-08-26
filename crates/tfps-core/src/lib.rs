//! Núcleo do TFPS — sistema de prevenção de fraude IRSF para redes SIP.
//!
//! Este crate contém o domínio e **nenhum I/O**: nem rede, nem disco, nem kernel.
//! A fonte dos eventos (captura hoje, XDP depois) fica fora daqui, o que mantém tudo
//! aqui determinístico e testável sem privilégio nem hardware.
//!
//! Arquitetura em `SPEC.md`, vocabulário normativo em `CONTEXT.md`.

pub mod country;
pub mod dialplan;
pub mod engine;
pub mod net;
pub mod novelty;
pub mod perimeter;
pub mod sip;
