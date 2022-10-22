//!
//! # tendermint_dev
//!
//! Tendermint cluster management,
//! supports both single-machine multi-process mode
//! and multi-machine distributed mode.
//!

#![deny(warnings)]
//#![deny(missing_docs)]

#[cfg(feature = "substrate_based")]
pub mod substrate_based;

#[cfg(feature = "tendermint_based")]
pub mod tendermint_based;

pub use tendermint_based::ddev as tm_ddev;
pub use tendermint_based::dev as tm_dev;
