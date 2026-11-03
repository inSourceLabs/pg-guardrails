//! pg-guardrails: a read-only, governed SQL gateway exposed to AI agents over MCP.
//!
//! Four layers, each independently stopping a write or a leak:
//!   1. statement policy (src/policy.rs) - refused before any connection opens
//!   2. database grants - the connecting role is SELECT-only
//!   3. session - read-only transaction per connection
//!   4. result shaping - row cap, per-source column deny list, wall clock
//!
//! Every call is recorded in an append-only audit log. Credentials live only in
//! the registry file and never appear in tool output or audit records.

pub mod audit;
pub mod auth;
pub mod config;
pub mod gateway;
pub mod policy;
pub mod render;
pub mod server;
