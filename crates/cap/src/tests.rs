use super::op_for;

#[test]
fn shell_free_file_reads_are_the_download_op() {
    for p in ["/download", "/list", "/file-status", "/stat", "/hash"] {
        assert_eq!(op_for(p, None), Some(("download", String::new())), "{p}");
    }
    assert_eq!(op_for("/statx", None), None);
    assert_eq!(op_for("/hashes", None), None);
}
