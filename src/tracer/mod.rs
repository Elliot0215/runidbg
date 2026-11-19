pub mod engine;
pub mod reader;
pub mod record;

pub use engine::{attach_code_hook, attach_mem_trace_hook, BinaryTracer};
pub use reader::TraceReader;
pub use record::{ExtKind, ExtRecord, TraceFilter, TraceLevel, TraceRecord, TraceStats};
