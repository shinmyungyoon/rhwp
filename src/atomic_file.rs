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
    // Hold each directory through publication instead of resolving its path again.
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

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_temp_dir() -> PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        std::env::temp_dir().join(format!("rhwp_atomic_file_{}_{nonce}", std::process::id()))
    }

    #[test]
    fn pre_replace_failure_preserves_destination_and_removes_temp_file() {
        let directory = unique_temp_dir();
        std::fs::create_dir_all(&directory).expect("create temp directory");
        let destination = directory.join("output.hml");
        std::fs::write(&destination, b"old bytes").expect("seed destination");

        let error = write_atomically_with(
            &destination,
            b"new bytes",
            |_directory, _temp, _destination| {
                Err(std::io::Error::other("injected replacement failure"))
            },
        )
        .expect_err("replacement should fail");

        assert_eq!(error.kind(), std::io::ErrorKind::Other);
        assert_eq!(
            std::fs::read(&destination).expect("read preserved destination"),
            b"old bytes"
        );
        assert_eq!(
            std::fs::read_dir(&directory)
                .expect("read temp directory")
                .filter_map(Result::ok)
                .count(),
            1,
            "only the original destination should remain"
        );
    }

    #[test]
    fn directory_syntax_cannot_be_normalized_into_a_file_replacement() {
        let directory = unique_temp_dir();
        std::fs::create_dir(&directory).unwrap();
        let destination = directory.join("output.hwp");
        std::fs::write(&destination, b"old output").unwrap();
        for path in [
            destination.join("."),
            directory.join("unused/../output.hwp"),
        ] {
            assert_eq!(
                write_atomically(&path, b"new output").unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
            assert_eq!(std::fs::read(&destination).unwrap(), b"old output");
        }
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn renamed_parent_does_not_redirect_publication_through_a_symlink() {
        let root = unique_temp_dir();
        std::fs::create_dir(&root).unwrap();
        let root = root.canonicalize().unwrap();
        let parent = root.join("parent");
        let retained = root.join("retained");
        let outside = root.join("outside");
        std::fs::create_dir(&parent).unwrap();
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(parent.join("output.hwp"), b"old output").unwrap();
        std::fs::write(outside.join("output.hwp"), b"protected output").unwrap();

        write_atomically_with(
            &parent.join("output.hwp"),
            b"new output",
            |directory, from, to| {
                std::fs::rename(&parent, &retained)?;
                std::os::unix::fs::symlink(&outside, &parent)?;
                directory.rename(from, directory, to)
            },
        )
        .unwrap();

        assert_eq!(
            std::fs::read(retained.join("output.hwp")).unwrap(),
            b"new output"
        );
        assert_eq!(
            std::fs::read(outside.join("output.hwp")).unwrap(),
            b"protected output"
        );
        assert_eq!(std::fs::read_dir(&retained).unwrap().count(), 1);
        std::fs::remove_dir_all(root).unwrap();
    }
}
