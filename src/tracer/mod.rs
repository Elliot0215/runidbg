pub mod engine;
pub mod reader;
pub mod record;
pub mod taint;

pub use engine::{attach_code_hook, attach_mem_trace_hook, BinaryTracer};
pub use reader::{
    resolve_sibling_ext_path, CallTreeNode, CryptoHitGroup, MemPatternHit, TraceDiffEntry,
    TraceDiffSummary, TraceQueryHit, TraceReader,
};
pub use record::{
    decode_instruction_with_reg, format_ascii_hint, ExtKind, ExtRecord, HleOpEvent, HleTraceEvent,
    TraceFilter, TraceLevel, TraceRecord, TraceStats,
};
pub use taint::{format_reg_slot, parse_reg_slot, TaintOptions, TaintReport, TaintSeed, TaintStep};
