use cap_fs_ext::DirExt;
use cap_std::ambient_authority;
#[cfg(unix)]
use cap_std::fs::OpenOptionsExt;
use cap_std::fs::{Dir, File, OpenOptions};
use std::ffi::OsString;
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};

pub(crate) fn write_atomically(output: &Path, bytes: &[u8]) -> io::Result<()> {
    write_atomically_with(output, bytes, |directory, from, to| {
        directory.rename(from, directory, to)
    })
}

fn write_atomically_with<F>(output: &Path, bytes: &[u8], replace: F) -> io::Result<()>
where
    F: FnOnce(&Dir, &Path, &Path) -> io::Result<()>,
{
    let (directory, leaf) = output_directory(output)?;
    check_destination(&directory, &leaf)?;
    let (temp_path, mut temp) = create_sibling_temp(&directory)?;
    if let Err(error) = write_and_sync(&mut temp, bytes) {
        drop(temp);
        let _ = directory.remove_file(&temp_path);
        return Err(error);
    }
    drop(temp);
    if let Err(error) = check_destination(&directory, &leaf)
        .and_then(|()| replace(&directory, &temp_path, Path::new(&leaf)))
    {
        let _ = directory.remove_file(&temp_path);
        return Err(error);
    }
    Ok(())
}

fn output_directory(output: &Path) -> io::Result<(Dir, OsString)> {
    let encoded = output.as_os_str().as_encoded_bytes();
    let directory_suffix = encoded.ends_with(b"/") || encoded.ends_with(b"/.");
    #[cfg(windows)]
    let directory_suffix =
        directory_suffix || encoded.ends_with(b"\\") || encoded.ends_with(b"\\.");
    if encoded.is_empty() || directory_suffix {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Output must name a file",
        ));
    }
    let absolute = if output.is_absolute() {
        output.to_path_buf()
    } else {
        std::env::current_dir()?.join(output)
    };
    let mut components = absolute.components().collect::<Vec<_>>();
    let Some(Component::Normal(leaf)) = components.pop() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Output must name a file",
        ));
    };
    let leaf = leaf.to_os_string();
    let mut root = PathBuf::new();
    let mut parents = Vec::new();
    for component in components {
        match component {
            Component::Prefix(prefix) => root.push(prefix.as_os_str()),
            Component::RootDir => root.push(component.as_os_str()),
            Component::Normal(name) => parents.push(name),
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Output paths cannot contain parent-directory components",
                ));
            }
        }
    }
    // Keep the selected parent handle through publication instead of resolving its path again.
    let mut directory = Dir::open_ambient_dir(root, ambient_authority())?;
    for parent in parents {
        directory = directory.open_dir_nofollow(parent)?;
    }
    Ok((directory, leaf))
}

fn check_destination(directory: &Dir, leaf: &std::ffi::OsStr) -> io::Result<()> {
    match directory.symlink_metadata(leaf) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => Ok(()),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Output must be a regular file, not a symbolic link or directory",
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn create_sibling_temp(directory: &Dir) -> io::Result<(PathBuf, File)> {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    for attempt in 0..128 {
        let candidate = PathBuf::from(format!(
            ".rhwp-output-{}.{}.{}.tmp",
            std::process::id(),
            nonce,
            attempt
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        match directory.open_with(&candidate, &options) {
            Ok(file) => return Ok((candidate, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "임시 출력 파일 이름을 확보할 수 없습니다",
    ))
}

fn write_and_sync(file: &mut File, bytes: &[u8]) -> io::Result<()> {
    file.write_all(bytes)?;
    file.sync_all()
}
