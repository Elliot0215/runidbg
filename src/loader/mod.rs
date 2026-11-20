#[cfg(feature = "apk")]
pub mod apk;
pub mod elf;
pub mod linker;
pub mod trampoline;

#[cfg(feature = "apk")]
pub use apk::ApkPackage;
pub use elf::{ElfLoader, LoadedModule};
pub use linker::DynamicLinker;
pub use trampoline::{attach_trampoline_hook, HleBuiltin, TrampolineTable};
