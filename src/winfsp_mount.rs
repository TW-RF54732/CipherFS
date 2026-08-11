use anyhow::{Context, Result};
use std::ffi::c_void;
use std::path::Path;
use windows::Win32::Foundation::{
    CloseHandle, HANDLE, HLOCAL, LocalFree, STATUS_BUFFER_TOO_SMALL, STATUS_DATA_ERROR,
    STATUS_FILE_IS_A_DIRECTORY, STATUS_MEDIA_WRITE_PROTECTED, STATUS_NOT_A_DIRECTORY,
    STATUS_OBJECT_NAME_NOT_FOUND,
};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{
    GetSecurityDescriptorLength, GetTokenInformation, PSECURITY_DESCRIPTOR, TOKEN_QUERY,
    TOKEN_USER, TokenUser,
};
use windows::Win32::Storage::FileSystem::{FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_READONLY};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::core::{HSTRING, PCWSTR, PWSTR};
use winfsp::U16CStr;
use winfsp::filesystem::{
    DirInfo, DirMarker, FileInfo, FileSecurity, FileSystemContext, ModificationDescriptor,
    OpenFileInfo, VolumeInfo, WideNameInfo,
};
use winfsp::host::{FileSystemHost, MountPoint, VolumeParams};
use winfsp_sys::{FILE_ACCESS_RIGHTS, FILE_FLAGS_AND_ATTRIBUTES};

use crate::readonly_fs::{FsError, FsErrorKind, Node, NodeKind, ReadOnlyFs};
use crate::windows_names::{WindowsNameMap, compare_display_names, equivalent};
use crate::winfsp_mountpoint::prepare as prepare_directory_mountpoint;
use crate::winfsp_runtime::initialize as initialize_winfsp;

pub struct WinFspCipherFs {
    core: ReadOnlyFs,
    names: WindowsNameMap,
    total_size: u64,
    security_descriptor: Vec<u8>,
}

impl WinFspCipherFs {
    fn open(path: &Path, password: &str, cache_mib: u64) -> Result<Self> {
        let core = ReadOnlyFs::open(path, password, cache_mib)?;
        let mut nodes = vec![core.metadata(1)?];
        let mut cursor = 0;
        let mut total_size = 0u64;
        while cursor < nodes.len() {
            let node = &nodes[cursor];
            if node.kind == NodeKind::Directory {
                nodes.extend(core.read_dir(node.id)?);
            } else {
                total_size = total_size
                    .checked_add(node.size)
                    .context("Mounted plaintext size overflow")?;
            }
            cursor += 1;
        }
        let names = WindowsNameMap::new(&nodes);
        names.warn();
        let security_descriptor = read_only_security_descriptor()?;
        Ok(Self {
            core,
            names,
            total_size,
            security_descriptor,
        })
    }

    fn resolve(&self, file_name: &U16CStr) -> winfsp::Result<Node> {
        let path = file_name.to_string_lossy();
        let mut id = 1u64;
        for component in path.split('\\').filter(|part| !part.is_empty()) {
            id = self
                .names
                .lookup(id, component)
                .ok_or_else(|| winfsp::FspError::from(STATUS_OBJECT_NAME_NOT_FOUND))?;
        }
        self.core.metadata(id).map_err(map_error)
    }

    fn copy_security_descriptor(&self, destination: Option<&mut [c_void]>) -> winfsp::Result<()> {
        let Some(destination) = destination else {
            return Ok(());
        };
        if destination.len() < self.security_descriptor.len() {
            return Err(STATUS_BUFFER_TOO_SMALL.into());
        }
        let destination = unsafe {
            std::slice::from_raw_parts_mut(destination.as_mut_ptr().cast::<u8>(), destination.len())
        };
        destination[..self.security_descriptor.len()].copy_from_slice(&self.security_descriptor);
        Ok(())
    }
}

impl FileSystemContext for WinFspCipherFs {
    type FileContext = Node;

    fn get_security_by_name(
        &self,
        file_name: &U16CStr,
        security_descriptor: Option<&mut [c_void]>,
        _reparse_point_resolver: impl FnOnce(&U16CStr) -> Option<FileSecurity>,
    ) -> winfsp::Result<FileSecurity> {
        let node = self.resolve(file_name)?;
        self.copy_security_descriptor(security_descriptor)?;
        Ok(FileSecurity {
            reparse: false,
            sz_security_descriptor: self.security_descriptor.len() as u64,
            attributes: attributes(&node),
        })
    }

    fn open(
        &self,
        file_name: &U16CStr,
        _create_options: u32,
        _granted_access: FILE_ACCESS_RIGHTS,
        file_info: &mut OpenFileInfo,
    ) -> winfsp::Result<Self::FileContext> {
        let node = self.resolve(file_name)?;
        fill_info(&node, file_info.as_mut());
        file_info.set_normalized_name(file_name.as_slice(), None);
        Ok(node)
    }

    fn close(&self, _context: Self::FileContext) {}

    fn get_security(
        &self,
        _context: &Self::FileContext,
        security_descriptor: Option<&mut [c_void]>,
    ) -> winfsp::Result<u64> {
        self.copy_security_descriptor(security_descriptor)?;
        Ok(self.security_descriptor.len() as u64)
    }

    fn create(
        &self,
        _file_name: &U16CStr,
        _create_options: u32,
        _granted_access: FILE_ACCESS_RIGHTS,
        _file_attributes: FILE_FLAGS_AND_ATTRIBUTES,
        _security_descriptor: Option<&[c_void]>,
        _allocation_size: u64,
        _extra_buffer: Option<&[u8]>,
        _extra_buffer_is_reparse_point: bool,
        _file_info: &mut OpenFileInfo,
    ) -> winfsp::Result<Self::FileContext> {
        Err(STATUS_MEDIA_WRITE_PROTECTED.into())
    }

    fn set_security(
        &self,
        _context: &Self::FileContext,
        _security_information: u32,
        _modification_descriptor: ModificationDescriptor,
    ) -> winfsp::Result<()> {
        Err(STATUS_MEDIA_WRITE_PROTECTED.into())
    }

    fn overwrite(
        &self,
        _context: &Self::FileContext,
        _file_attributes: FILE_FLAGS_AND_ATTRIBUTES,
        _replace_file_attributes: bool,
        _allocation_size: u64,
        _extra_buffer: Option<&[u8]>,
        _file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        Err(STATUS_MEDIA_WRITE_PROTECTED.into())
    }

    fn rename(
        &self,
        _context: &Self::FileContext,
        _file_name: &U16CStr,
        _new_file_name: &U16CStr,
        _replace_if_exists: bool,
    ) -> winfsp::Result<()> {
        Err(STATUS_MEDIA_WRITE_PROTECTED.into())
    }

    fn set_basic_info(
        &self,
        _context: &Self::FileContext,
        _file_attributes: u32,
        _creation_time: u64,
        _last_access_time: u64,
        _last_write_time: u64,
        _last_change_time: u64,
        _file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        Err(STATUS_MEDIA_WRITE_PROTECTED.into())
    }

    fn set_delete(
        &self,
        _context: &Self::FileContext,
        _file_name: &U16CStr,
        _delete_file: bool,
    ) -> winfsp::Result<()> {
        Err(STATUS_MEDIA_WRITE_PROTECTED.into())
    }

    fn set_file_size(
        &self,
        _context: &Self::FileContext,
        _new_size: u64,
        _set_allocation_size: bool,
        _file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        Err(STATUS_MEDIA_WRITE_PROTECTED.into())
    }

    fn get_file_info(
        &self,
        context: &Self::FileContext,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        fill_info(context, file_info);
        Ok(())
    }

    fn read_directory(
        &self,
        context: &Self::FileContext,
        _pattern: Option<&U16CStr>,
        marker: DirMarker,
        buffer: &mut [u8],
    ) -> winfsp::Result<u32> {
        if context.kind != NodeKind::Directory {
            return Err(STATUS_NOT_A_DIRECTORY.into());
        }
        let mut children = self.core.read_dir(context.id).map_err(map_error)?;
        children.sort_by(|left, right| {
            compare_display_names(self.names.name(left), self.names.name(right))
                .then(left.id.cmp(&right.id))
        });
        let marker = marker
            .inner_as_cstr()
            .map(U16CStr::to_string_lossy)
            .unwrap_or_default();
        let start = if marker.is_empty() {
            0
        } else {
            children
                .iter()
                .position(|child| equivalent(self.names.name(child), &marker))
                .map_or(0, |position| position + 1)
        };
        let mut cursor = 0u32;
        for child in children.into_iter().skip(start) {
            let display = self.names.name(&child);
            let mut info = DirInfo::<256>::new();
            fill_info(&child, info.file_info_mut());
            info.set_name(display)?;
            if !info.append_to_buffer(buffer, &mut cursor) {
                break;
            }
        }
        DirInfo::<256>::finalize_buffer(buffer, &mut cursor);
        Ok(cursor)
    }

    fn read(
        &self,
        context: &Self::FileContext,
        buffer: &mut [u8],
        offset: u64,
    ) -> winfsp::Result<u32> {
        if context.kind == NodeKind::Directory {
            return Err(STATUS_FILE_IS_A_DIRECTORY.into());
        }
        let requested = u32::try_from(buffer.len()).unwrap_or(u32::MAX);
        let plaintext = self
            .core
            .read(context.id, offset, requested)
            .map_err(map_error)?;
        buffer[..plaintext.len()].copy_from_slice(&plaintext);
        Ok(plaintext.len() as u32)
    }

    fn write(
        &self,
        _context: &Self::FileContext,
        _buffer: &[u8],
        _offset: u64,
        _write_to_eof: bool,
        _constrained_io: bool,
        _file_info: &mut FileInfo,
    ) -> winfsp::Result<u32> {
        Err(STATUS_MEDIA_WRITE_PROTECTED.into())
    }

    fn get_volume_info(&self, info: &mut VolumeInfo) -> winfsp::Result<()> {
        info.total_size = self.total_size;
        info.free_size = 0;
        info.set_volume_label("CipherFS");
        Ok(())
    }
}

pub fn mount(
    container: &Path,
    mountpoint: &Path,
    password: &str,
    cache_mib: u64,
    wait: impl FnOnce(),
) -> Result<()> {
    let _init = initialize_winfsp()?;
    println!("[Info] WinFsp - Windows File System Proxy, Copyright (C) Bill Zissimopoulos.");
    println!("[Info] https://github.com/winfsp/winfsp");
    println!("[Info] Run `cipherfs licenses` for licensing and no-warranty notices.");
    let filesystem = WinFspCipherFs::open(container, password, cache_mib)?;
    let params = volume_params();
    let mut host: FileSystemHost<WinFspCipherFs> =
        FileSystemHost::new(params, filesystem).context("Unable to create WinFsp host")?;
    host.start().context("Unable to start WinFsp dispatcher")?;
    let prepared_directory = prepare_directory_mountpoint(mountpoint)?;
    if mountpoint.to_string_lossy().eq_ignore_ascii_case("auto") {
        host.mount(MountPoint::NextFreeDrive)
            .context("Unable to select a free drive letter")?;
    } else if let Some(prepared) = &prepared_directory {
        host.mount(&prepared.mount_path)
            .context("Unable to mount WinFsp filesystem at the directory")?;
    } else {
        host.mount(&mountpoint.as_os_str())
            .context("Unable to mount WinFsp filesystem")?;
    }
    println!("[Success] CipherFS is mounted read-only through WinFsp.");
    println!("[Info] Press Ctrl+C to unmount.");
    wait();
    println!("\n[Info] Unmounting...");
    host.unmount();
    host.stop();
    Ok(())
}

fn volume_params() -> VolumeParams {
    let mut params = VolumeParams::new();
    params
        .filesystem_name("CipherFS")
        .sector_size(4096)
        .sectors_per_allocation_unit(1)
        .max_component_length(255)
        .case_sensitive_search(false)
        .case_preserved_names(true)
        .unicode_on_disk(true)
        .read_only_volume(true)
        .persistent_acls(true);
    params
}

fn read_only_security_descriptor() -> Result<Vec<u8>> {
    let mut token = HANDLE::default();
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }
        .context("Unable to inspect the interactive Windows user")?;
    let result = (|| {
        let mut required = 0u32;
        let _ = unsafe { GetTokenInformation(token, TokenUser, None, 0, &mut required) };
        anyhow::ensure!(required >= std::mem::size_of::<TOKEN_USER>() as u32);
        let words = (required as usize).div_ceil(std::mem::size_of::<usize>());
        let mut token_buffer = vec![0usize; words];
        unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                Some(token_buffer.as_mut_ptr().cast()),
                required,
                &mut required,
            )
        }
        .context("Unable to read the interactive Windows user SID")?;
        let token_user = unsafe { &*token_buffer.as_ptr().cast::<TOKEN_USER>() };
        let mut sid_text = PWSTR::null();
        unsafe { ConvertSidToStringSidW(token_user.User.Sid, &mut sid_text) }
            .context("Unable to format the interactive Windows user SID")?;
        let sid = unsafe { sid_text.to_string() }.context("Windows user SID is not valid text")?;
        let _ = unsafe { LocalFree(Some(HLOCAL(sid_text.0.cast()))) };

        let sddl = HSTRING::from(format!("O:{sid}G:{sid}D:P(A;;FR;;;SY)(A;;FR;;;{sid})"));
        let mut descriptor = PSECURITY_DESCRIPTOR(std::ptr::null_mut());
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(sddl.as_ptr()),
                SDDL_REVISION_1,
                &mut descriptor,
                None,
            )
        }
        .context("Unable to build the read-only Windows ACL")?;
        let length = unsafe { GetSecurityDescriptorLength(descriptor) } as usize;
        let bytes =
            unsafe { std::slice::from_raw_parts(descriptor.0.cast::<u8>(), length) }.to_vec();
        let _ = unsafe { LocalFree(Some(HLOCAL(descriptor.0))) };
        Ok(bytes)
    })();
    let _ = unsafe { CloseHandle(token) };
    result
}

fn attributes(node: &Node) -> u32 {
    if node.kind == NodeKind::Directory {
        FILE_ATTRIBUTE_DIRECTORY.0
    } else {
        FILE_ATTRIBUTE_READONLY.0
    }
}

fn fill_info(node: &Node, info: &mut FileInfo) {
    info.file_attributes = attributes(node);
    info.file_size = node.size;
    info.allocation_size = node.size.div_ceil(4096) * 4096;
    info.index_number = node.id;
}

fn map_error(error: FsError) -> winfsp::FspError {
    match error.kind() {
        FsErrorKind::NotFound => STATUS_OBJECT_NAME_NOT_FOUND.into(),
        FsErrorKind::NotDirectory => STATUS_NOT_A_DIRECTORY.into(),
        FsErrorKind::IsDirectory => STATUS_FILE_IS_A_DIRECTORY.into(),
        FsErrorKind::Integrity => {
            eprintln!("[Integrity] {error}");
            STATUS_DATA_ERROR.into()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    const CRASH_TEST_NAME: &str = "winfsp_mount::tests::hard_termination_folder_mount_recovers";

    fn random_test_password() -> String {
        let mut value = [0u8; 32];
        rand::rng().fill_bytes(&mut value);
        hex::encode(value)
    }

    #[test]
    fn directory_mount_rejects_reparse_ancestor() {
        let temp = tempfile::tempdir().unwrap();
        let outside = temp.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        let junction = temp.path().join("junction");
        let status = std::process::Command::new("cmd")
            .args([
                "/c",
                "mklink",
                "/J",
                junction.to_str().unwrap(),
                outside.to_str().unwrap(),
            ])
            .status()
            .unwrap();
        assert!(status.success());
        assert!(prepare_directory_mountpoint(&junction.join("mount")).is_err());
        assert!(!outside.join("mount").exists());
    }

    #[test]
    fn hard_termination_folder_mount_recovers() {
        if std::env::var_os("CIPHERFS_WINFSP_E2E").is_none() {
            return;
        }
        if std::env::var_os("CIPHERFS_WINFSP_CRASH_CHILD").is_some() {
            let container = std::path::PathBuf::from(
                std::env::var_os("CIPHERFS_WINFSP_CRASH_CONTAINER").unwrap(),
            );
            let mountpoint = std::path::PathBuf::from(
                std::env::var_os("CIPHERFS_WINFSP_CRASH_MOUNTPOINT").unwrap(),
            );
            let ready =
                std::path::PathBuf::from(std::env::var_os("CIPHERFS_WINFSP_CRASH_READY").unwrap());
            let password = std::env::var("CIPHERFS_WINFSP_CRASH_PASSWORD").unwrap();
            let _init = initialize_winfsp().unwrap();
            let filesystem = WinFspCipherFs::open(&container, &password, 0).unwrap();
            let mut host: FileSystemHost<WinFspCipherFs> =
                FileSystemHost::new(volume_params(), filesystem).unwrap();
            host.start().unwrap();
            let prepared = prepare_directory_mountpoint(&mountpoint).unwrap().unwrap();
            host.mount(&prepared.mount_path).unwrap();
            assert_eq!(
                std::fs::read(mountpoint.join("file.txt")).unwrap(),
                b"recovery"
            );
            std::fs::write(ready, b"mounted").unwrap();
            std::mem::forget(prepared);
            std::mem::forget(host);
            std::process::abort();
        }

        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let container = temp.path().join("vault.cfs");
        let mountpoint = temp.path().join("mount");
        let ready = temp.path().join("ready");
        let password = random_test_password();
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("file.txt"), b"recovery").unwrap();
        crate::pack::pack(
            &source,
            &container,
            &password,
            None,
            crate::v2::MIN_ARGON_MEMORY_KIB,
            1,
            1,
            crate::v2::MAX_INDEX_SIZE,
            1,
        )
        .unwrap();

        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([CRASH_TEST_NAME, "--exact", "--nocapture"])
            .env("CIPHERFS_WINFSP_CRASH_CHILD", "1")
            .env("CIPHERFS_WINFSP_CRASH_CONTAINER", &container)
            .env("CIPHERFS_WINFSP_CRASH_MOUNTPOINT", &mountpoint)
            .env("CIPHERFS_WINFSP_CRASH_READY", &ready)
            .env("CIPHERFS_WINFSP_CRASH_PASSWORD", &password)
            .status()
            .unwrap();
        assert!(!status.success());
        assert!(ready.is_file(), "child did not reach the mounted state");

        for _ in 0..50 {
            let recovered = !mountpoint.exists()
                || std::fs::read_dir(&mountpoint)
                    .map(|mut entries| entries.next().is_none())
                    .unwrap_or(false);
            if recovered {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }

        let _init = initialize_winfsp().unwrap();
        let filesystem = WinFspCipherFs::open(&container, &password, 0).unwrap();
        let mut host: FileSystemHost<WinFspCipherFs> =
            FileSystemHost::new(volume_params(), filesystem).unwrap();
        host.start().unwrap();
        let prepared = prepare_directory_mountpoint(&mountpoint).unwrap().unwrap();
        host.mount(&prepared.mount_path).unwrap();
        assert_eq!(
            std::fs::read(mountpoint.join("file.txt")).unwrap(),
            b"recovery"
        );
        host.unmount();
        host.stop();
        drop(prepared);
        assert!(mountpoint.is_dir());
    }

    #[test]
    #[allow(clippy::permissions_set_readonly_false)]
    fn runtime_mount_reads_files_and_rejects_mutation() {
        if std::env::var_os("CIPHERFS_WINFSP_E2E").is_none() {
            return;
        }

        let _init = initialize_winfsp().expect("WinFsp runtime must be installed for E2E");
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let container = temp.path().join("vault.cfs");
        let mountpoint = temp.path().join("mount");
        let password = random_test_password();
        std::fs::create_dir_all(source.join("empty")).unwrap();
        std::fs::create_dir(&mountpoint).unwrap();
        std::fs::write(source.join("small.txt"), b"private data").unwrap();
        let boundary = vec![0x5au8; crate::v2::CHUNK_SIZE + 17];
        std::fs::write(source.join("boundary.bin"), &boundary).unwrap();
        crate::pack::pack(
            &source,
            &container,
            &password,
            None,
            crate::v2::MIN_ARGON_MEMORY_KIB,
            1,
            1,
            crate::v2::MAX_INDEX_SIZE,
            2,
        )
        .unwrap();

        if std::env::var_os("CIPHERFS_WINFSP_FOLDER_E2E").is_some() {
            let filesystem = WinFspCipherFs::open(&container, &password, 8).unwrap();
            let mut host: FileSystemHost<WinFspCipherFs> =
                FileSystemHost::new(volume_params(), filesystem).unwrap();
            host.start().unwrap();
            let mountpoint_with_separator =
                std::path::PathBuf::from(format!("{}\\", mountpoint.display()));
            let prepared = prepare_directory_mountpoint(&mountpoint_with_separator)
                .unwrap()
                .unwrap();
            host.mount(&prepared.mount_path).unwrap();
            assert_eq!(
                std::fs::read(mountpoint.join("small.txt")).unwrap(),
                b"private data"
            );
            host.unmount();
            host.stop();
            drop(prepared);
            assert!(mountpoint.is_dir());
        }

        let occupied = unsafe { windows::Win32::Storage::FileSystem::GetLogicalDrives() };
        let drive_letter = (3u8..=25)
            .rev()
            .find(|index| occupied & (1 << index) == 0)
            .map(|index| (b'A' + index) as char)
            .expect("a free drive letter is required for WinFsp E2E");
        let drive_mount = format!("{drive_letter}:");
        let drive_filesystem = WinFspCipherFs::open(&container, &password, 8).unwrap();
        let mut drive_host: FileSystemHost<WinFspCipherFs> =
            FileSystemHost::new(volume_params(), drive_filesystem).unwrap();
        drive_host.start().unwrap();
        drive_host.mount(&drive_mount).unwrap();
        assert_eq!(
            std::fs::read(format!("{drive_mount}\\small.txt")).unwrap(),
            b"private data"
        );
        assert_eq!(
            std::fs::read(format!("{drive_mount}\\boundary.bin")).unwrap(),
            boundary
        );
        assert!(std::path::Path::new(&format!("{drive_mount}\\empty")).is_dir());
        assert!(std::fs::write(format!("{drive_mount}\\small.txt"), b"changed").is_err());
        assert!(std::fs::write(format!("{drive_mount}\\new.txt"), b"new").is_err());
        assert!(std::fs::remove_file(format!("{drive_mount}\\small.txt")).is_err());
        assert!(
            std::fs::rename(
                format!("{drive_mount}\\small.txt"),
                format!("{drive_mount}\\renamed.txt")
            )
            .is_err()
        );
        assert!(
            std::fs::OpenOptions::new()
                .write(true)
                .open(format!("{drive_mount}\\small.txt"))
                .and_then(|file| file.set_len(1))
                .is_err()
        );
        let mut permissions = std::fs::metadata(format!("{drive_mount}\\small.txt"))
            .unwrap()
            .permissions();
        permissions.set_readonly(false);
        assert!(
            std::fs::set_permissions(format!("{drive_mount}\\small.txt"), permissions).is_err()
        );
        drive_host.unmount();
        drive_host.stop();

        let before_auto = unsafe { windows::Win32::Storage::FileSystem::GetLogicalDrives() };
        let auto_filesystem = WinFspCipherFs::open(&container, &password, 8).unwrap();
        let mut auto_host: FileSystemHost<WinFspCipherFs> =
            FileSystemHost::new(volume_params(), auto_filesystem).unwrap();
        auto_host.start().unwrap();
        auto_host.mount(MountPoint::NextFreeDrive).unwrap();
        let after_auto = unsafe { windows::Win32::Storage::FileSystem::GetLogicalDrives() };
        let added = after_auto & !before_auto;
        assert_eq!(added.count_ones(), 1);
        let auto_letter = (b'A' + added.trailing_zeros() as u8) as char;
        assert_eq!(
            std::fs::read(format!("{auto_letter}:\\small.txt")).unwrap(),
            b"private data"
        );
        auto_host.unmount();
        auto_host.stop();

        let container_file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&container)
            .unwrap();
        let last = container_file.metadata().unwrap().len() - 1;
        let mut byte = [0u8; 1];
        crate::platform_io::PlatformFileExt::read_exact_at(&container_file, &mut byte, last)
            .unwrap();
        byte[0] ^= 1;
        crate::platform_io::PlatformFileExt::write_all_at(&container_file, &byte, last).unwrap();
        container_file.sync_all().unwrap();

        let corrupt_occupied = unsafe { windows::Win32::Storage::FileSystem::GetLogicalDrives() };
        let corrupt_letter = (3u8..=25)
            .rev()
            .find(|index| corrupt_occupied & (1 << index) == 0)
            .map(|index| (b'A' + index) as char)
            .expect("a free drive letter is required for corruption E2E");
        let corrupt_mount = format!("{corrupt_letter}:");
        let corrupt_filesystem = WinFspCipherFs::open(&container, &password, 0).unwrap();
        let mut corrupt_host: FileSystemHost<WinFspCipherFs> =
            FileSystemHost::new(volume_params(), corrupt_filesystem).unwrap();
        corrupt_host.start().unwrap();
        corrupt_host.mount(&corrupt_mount).unwrap();
        let small_result = std::fs::read(format!("{corrupt_mount}\\small.txt"));
        let boundary_result = std::fs::read(format!("{corrupt_mount}\\boundary.bin"));
        assert!(
            small_result.is_err(),
            "the specifically corrupted file was readable"
        );
        assert_eq!(boundary_result.unwrap(), boundary);
        corrupt_host.unmount();
        corrupt_host.stop();
    }
}
