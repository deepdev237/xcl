//! Observe the title's buffer barriers and the indirect calls forwarded to the PC.

use std::ffi::c_void;
use std::fmt::Arguments;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::OnceLock;
use windows::Win32::Graphics::Direct3D12::*;
use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows_sys::Win32::System::Threading::GetCurrentProcess;

const MAX_GROUPS: usize = 256;
const MAX_BUFFERS: usize = 1024;
const MAX_LOGGED: usize = 2048;

struct Stream {
    logged: AtomicUsize,
    name: &'static str,
}

impl Stream {
    const fn new(name: &'static str) -> Self {
        Self { logged: AtomicUsize::new(0), name }
    }

    fn enabled(&self) -> bool {
        #[cfg(test)]
        if CAPTURE.with_borrow(|capture| capture.is_some()) {
            return self.logged.load(Ordering::Relaxed) < MAX_LOGGED;
        }
        static START: OnceLock<Option<u64>> = OnceLock::new();
        START.get_or_init(|| std::env::var("XCL_TRACE_INDIRECT_BARRIERS").ok()?.parse().ok())
            .is_some_and(|start| self.logged.load(Ordering::Relaxed) < MAX_LOGGED && crate::log::uptime() >= start as f64)
    }

    /// Returns whether the caller can keep scanning after this entry.
    fn emit(&self, args: Arguments<'_>) -> bool {
        let entry = self.logged.fetch_add(1, Ordering::Relaxed);
        if entry >= MAX_LOGGED {
            return false;
        }
        write_entry(args);
        if entry + 1 == MAX_LOGGED {
            write_entry(format_args!("D3D12.X: {} trace reached its {MAX_LOGGED}-entry limit", self.name));
            return false;
        }
        true
    }
}

fn write_entry(args: Arguments<'_>) {
    #[cfg(test)]
    if CAPTURE.with_borrow_mut(|capture| {
        capture.as_mut().is_some_and(|lines| { lines.push(args.to_string()); true })
    }) {
        return;
    }
    crate::xlog_info!("{args}");
}

#[cfg(test)]
thread_local! {
    static CAPTURE: std::cell::RefCell<Option<Vec<String>>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(super) fn capture(f: impl FnOnce()) -> Vec<String> {
    assert!(CAPTURE.replace(Some(Vec::new())).is_none());
    f();
    CAPTURE.take().unwrap()
}

// Wire layouts contain only integers so reading a guessed layout cannot create a COM object.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct BarrierGroup {
    kind: i32,
    count: u32,
    barriers: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct BufferBarrier {
    sync_before: i32,
    sync_after: i32,
    access_before: i32,
    access_after: i32,
    resource: usize,
    offset: u64,
    size: u64,
}

/// ReadProcessMemory handles unreadable pages, including pages decommitted during the copy.
/// The destination must be writable for `bytes` and accept arbitrary bit patterns.
unsafe fn snapshot(at: usize, out: *mut c_void, bytes: usize) -> bool {
    let mut copied = 0;
    at != 0 && ReadProcessMemory(GetCurrentProcess(), at as *const c_void, out, bytes, &mut copied) != 0 && copied == bytes
}

/// Read only the documented buffer barrier layout. The title may use slot #146 with other
/// layouts, so the trace leaves the existing forwarding path alone and skips unreadable data.
fn visit_indirect_buffers(groups: usize, count: usize, mut visit: impl FnMut(&BufferBarrier) -> bool) -> bool {
    if count == 0 {
        return false;
    }
    let mut truncated = count > MAX_GROUPS;
    let count = count.min(MAX_GROUPS);
    let mut groups_snapshot = vec![BarrierGroup::default(); count];
    let copied = unsafe {
        snapshot(groups, groups_snapshot.as_mut_ptr().cast(), size_of_val(groups_snapshot.as_slice()))
    };
    if !copied {
        return false;
    }
    let mut remaining = MAX_BUFFERS;
    let mut buffers = Vec::new();
    for group in groups_snapshot {
        if group.kind != D3D12_BARRIER_TYPE_BUFFER.0 {
            continue;
        }
        if group.count == 0 {
            continue;
        }
        if remaining == 0 {
            return true;
        }
        let count = (group.count as usize).min(remaining);
        truncated |= count < group.count as usize;
        remaining -= count;
        buffers.resize(count, BufferBarrier::default());
        let copied = unsafe {
            snapshot(group.barriers, buffers.as_mut_ptr().cast(), size_of_val(buffers.as_slice()))
        };
        if !copied {
            continue;
        }
        for barrier in &buffers {
            let accesses = barrier.access_before | barrier.access_after;
            if accesses & D3D12_BARRIER_ACCESS_INDIRECT_ARGUMENT.0 != 0 && !visit(barrier) {
                return false;
            }
        }
    }
    truncated
}

pub(super) fn enhanced_barriers(list: *mut c_void, count: u32, groups: *const c_void) {
    static STREAM: Stream = Stream::new("indirect buffer barrier");
    if !STREAM.enabled() {
        return;
    }
    let mut title_list = None;
    let mut list_id = || *title_list.get_or_insert_with(|| super::title_list::wrapper_of(list).unwrap_or(list));
    let truncated = visit_indirect_buffers(groups as usize, count as usize, |barrier| {
        if barrier.resource == 0 {
            return true;
        }
        let title_list = list_id();
        STREAM.emit(format_args!(
            "D3D12.X: indirect buffer barrier list={title_list:p} pc_list={list:p} resource={:#x} offset={:#x} size={:#x} sync={:#x}->{:#x} access={:#x}->{:#x}",
            barrier.resource, barrier.offset, barrier.size, barrier.sync_before, barrier.sync_after,
            barrier.access_before, barrier.access_after,
        ))
    });
    if truncated {
        let title_list = list_id();
        STREAM.emit(format_args!(
            "D3D12.X: indirect buffer barrier scan truncated list={title_list:p} pc_list={list:p} (up to {MAX_GROUPS} groups, {MAX_BUFFERS} buffers)"
        ));
    }
}

pub(super) fn execute(
    list: *mut c_void, args: usize, title_offset: u64, pc_offset: u64, max: u32,
    count: usize, title_count_offset: u64, pc_count_offset: u64,
) {
    static STREAM: Stream = Stream::new("indirect command");
    if STREAM.enabled() {
        let title_list = super::title_list::wrapper_of(list).unwrap_or(list);
        STREAM.emit(format_args!(
            "D3D12.X: indirect command list={title_list:p} pc_list={list:p} resource={args:#x} title_offset={title_offset:#x} pc_offset={pc_offset:#x} max={max} count_buffer={count:#x} title_count_offset={title_count_offset:#x} pc_count_offset={pc_count_offset:#x}"
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn visits_only_buffer_barriers_with_indirect_access() {
        let indirect = D3D12_BARRIER_ACCESS_INDIRECT_ARGUMENT;
        let storage = D3D12_BARRIER_ACCESS_UNORDERED_ACCESS;
        let barriers = [
            D3D12_BUFFER_BARRIER { AccessBefore: storage, AccessAfter: storage, ..Default::default() },
            D3D12_BUFFER_BARRIER { AccessBefore: storage, AccessAfter: indirect, Offset: 0x1_0000_0080, Size: 12, ..Default::default() },
            D3D12_BUFFER_BARRIER { AccessBefore: indirect, AccessAfter: storage, Offset: 0x80, Size: u64::MAX, ..Default::default() },
        ];
        let groups = [
            D3D12_BARRIER_GROUP { Type: D3D12_BARRIER_TYPE_TEXTURE, ..Default::default() },
            D3D12_BARRIER_GROUP {
                Type: D3D12_BARRIER_TYPE_BUFFER,
                NumBarriers: barriers.len() as u32,
                Anonymous: D3D12_BARRIER_GROUP_0 { pBufferBarriers: barriers.as_ptr() },
            },
        ];
        let mut observed = Vec::new();
        visit_indirect_buffers(groups.as_ptr() as usize, groups.len(), |barrier| {
            observed.push((barrier.offset, barrier.size));
            true
        });
        visit_indirect_buffers(0, 1, |_| panic!("null groups"));
        assert_eq!(observed, [(0x1_0000_0080, 12), (0x80, u64::MAX)]);
    }

    #[test]
    fn bounds_the_scan_and_reports_truncation() {
        let mut barriers = vec![BufferBarrier::default(); MAX_BUFFERS + 1];
        for offset in [0, MAX_BUFFERS - 1, MAX_BUFFERS] {
            barriers[offset] = BufferBarrier {
                access_after: D3D12_BARRIER_ACCESS_INDIRECT_ARGUMENT.0,
                resource: 0x1234,
                offset: offset as u64,
                ..Default::default()
            };
        }
        let group = BarrierGroup {
            kind: D3D12_BARRIER_TYPE_BUFFER.0,
            count: barriers.len() as u32,
            barriers: barriers.as_ptr() as usize,
        };
        let groups = [group, group];
        let lines = capture(|| enhanced_barriers(std::ptr::null_mut(), 2, groups.as_ptr().cast()));
        assert_eq!(lines.len(), 3);
        assert!(lines[0].contains("resource=0x1234 offset=0x0"));
        assert!(lines[1].contains("resource=0x1234 offset=0x3ff"));
        assert!(lines[2].contains("indirect buffer barrier scan truncated"));
    }

    #[test]
    fn each_stream_stops_at_its_own_entry_limit() {
        let barriers = Stream::new("indirect buffer barrier");
        let commands = Stream::new("indirect command");
        let lines = capture(|| {
            for stream in [&barriers, &commands] {
                stream.logged.store(MAX_LOGGED - 2, Ordering::Relaxed);
                assert!(stream.enabled());
                assert!(stream.emit(format_args!("penultimate entry")));
                assert!(stream.enabled());
                assert!(!stream.emit(format_args!("last entry")));
                assert!(!stream.enabled());
                assert!(!stream.emit(format_args!("over the limit")));
            }
        });
        assert_eq!(lines.len(), 6);
        assert_eq!(lines[0..2], ["penultimate entry", "last entry"]);
        assert!(lines[2].contains("indirect buffer barrier trace reached"));
        assert_eq!(lines[3..5], ["penultimate entry", "last entry"]);
        assert!(lines[5].contains("indirect command trace reached"));
    }

    #[repr(C)]
    struct FakeList {
        vtable: *const usize,
        forwarded_uav_barrier: std::cell::Cell<bool>,
    }

    unsafe extern "system" fn fake_release(_list: *mut c_void) -> u32 {
        0
    }

    unsafe extern "system" fn fake_resource_barrier(list: *mut c_void, count: u32, barrier: *const D3D12_RESOURCE_BARRIER) {
        let list = &*list.cast::<FakeList>();
        list.forwarded_uav_barrier.set(count == 1 && barrier.as_ref().is_some_and(|barrier| {
            barrier.Type == D3D12_RESOURCE_BARRIER_TYPE_UAV && barrier.Anonymous.UAV.pResource.is_none()
        }));
    }

    #[test]
    fn slot_146_and_indirect_commands_identify_the_same_split_title_list() {
        use super::super::{list_x, title_list};

        let mut original = [0usize; 27];
        original[2] = fake_release as usize;
        original[26] = fake_resource_barrier as usize;
        let mut extended = [0usize; 28];
        extended[0] = original.as_ptr() as usize;
        extended[1..].copy_from_slice(&original);
        let lists: [FakeList; 2] = std::array::from_fn(|_| FakeList {
            vtable: extended[1..].as_ptr(),
            forwarded_uav_barrier: std::cell::Cell::new(false),
        });
        let [primary, extra] = [&lists[0], &lists[1]].map(|l| std::ptr::from_ref(l).cast_mut().cast::<c_void>());
        let barrier = BufferBarrier {
            access_after: D3D12_BARRIER_ACCESS_INDIRECT_ARGUMENT.0,
            resource: 0x5678,
            ..Default::default()
        };
        let group = BarrierGroup {
            kind: D3D12_BARRIER_TYPE_BUFFER.0,
            count: 1,
            barriers: std::ptr::from_ref(&barrier) as usize,
        };
        let wrapper = unsafe { title_list::wrap(primary) };
        assert_ne!(wrapper, primary);
        let lines = capture(|| unsafe {
            list_x::uav_barrier_x(primary, 1, std::ptr::from_ref(&group).cast());
            title_list::activate_segment(wrapper, primary, extra);
            execute(extra, 0x5678, 0, 0, 1, 0, 0, 0);
        });
        let refs = unsafe {
            let slot = *(*(wrapper.cast::<*const usize>())).add(2);
            let release: unsafe extern "system" fn(*mut c_void) -> u32 = std::mem::transmute(slot);
            release(wrapper)
        };

        assert_eq!(refs, 0);
        assert!(lists[0].forwarded_uav_barrier.get());
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains(&format!("list={wrapper:p} pc_list={primary:p} resource=0x5678")));
        assert!(lines[1].contains(&format!("list={wrapper:p} pc_list={extra:p} resource=0x5678")));
    }

    #[test]
    fn skips_unreadable_barrier_arrays() {
        let group = BarrierGroup { kind: D3D12_BARRIER_TYPE_BUFFER.0, count: 1, barriers: 1 };
        visit_indirect_buffers(1, 1, |_| panic!("unreadable groups"));
        visit_indirect_buffers(&group as *const BarrierGroup as usize, 1, |_| panic!("unreadable buffers"));
        assert_eq!(size_of::<BarrierGroup>(), size_of::<D3D12_BARRIER_GROUP>());
        assert_eq!(size_of::<BufferBarrier>(), size_of::<D3D12_BUFFER_BARRIER>());
        assert_eq!(std::mem::offset_of!(BufferBarrier, resource), std::mem::offset_of!(D3D12_BUFFER_BARRIER, pResource));
        assert_eq!(std::mem::offset_of!(BufferBarrier, offset), std::mem::offset_of!(D3D12_BUFFER_BARRIER, Offset));
    }
}
