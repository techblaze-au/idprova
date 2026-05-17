//! HTTP route handlers.
//!
//! Sub-modules are organised by resource:
//! * [`meta`]  — protocol metadata (`/health`, `/v1/meta`)
//! * [`aids`]  — Agent Identity Document CRUD (`/v1/aids`, `/v1/aid/:id`,
//!   `/v1/aid/:id/key`)
//! * [`dats`]  — DAT verification and revocation (`/v1/dat/verify`,
//!   `/v1/dat/revoke`, `/v1/dat/revoked/:jti`)

pub mod aids;
pub mod dats;
pub mod meta;
