#![cfg(not(target_arch = "wasm32"))]

mod atomic_file {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/atomic_file.rs"));

    fn unique_temp_dir() -> PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("rhwp_atomic_file_{}_{nonce}", std::process::id()));
        std::fs::create_dir(&directory).expect("create temporary directory");
        directory
            .canonicalize()
            .expect("resolve temporary directory")
    }

    #[test]
    fn pre_replace_failure_preserves_destination_and_removes_temp_file() {
        let directory = unique_temp_dir();
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
        assert_eq!(std::fs::read(&destination).unwrap(), b"old bytes");
        assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 1);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn directory_syntax_cannot_be_normalized_into_a_file_replacement() {
        let directory = unique_temp_dir();
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
