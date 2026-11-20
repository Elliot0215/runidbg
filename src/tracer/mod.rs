pub mod engine;
pub mod reader;
pub mod record;

pub use engine::{attach_code_hook, attach_mem_trace_hook, BinaryTracer};
pub use reader::{CallTreeNode, CryptoHitGroup, MemPatternHit, TraceReader};
pub use record::{
    decode_instruction_with_reg, format_ascii_hint, ExtKind, ExtRecord, TraceFilter, TraceLevel,
    TraceRecord, TraceStats,
};
