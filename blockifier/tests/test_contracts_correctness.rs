use std::fs;
use std::process::Command;
extern crate blockifier;
use pretty_assertions::assert_eq;

#[test]
#[ignore]
fn compiled_files_correctness() -> Result<(), String> {
    for file in fs::read_dir("test_contracts/").unwrap() {
        let path = file.unwrap().path();

        // test `test_contracts/` file and directory structure.
        if !path.is_file() {
            match path.file_name() {
                Some(dir_name) if dir_name == "compiled" => continue,
                Some(dir_name) => {
                    return Err(format!(
                        "Found directory '{}' in 'test_contracts/', which should contain only the \
                         'compiled' directory.",
                        dir_name.to_string_lossy()
                    ));
                }
                None => return Err("IO error".to_string()),
            }
        }
        let path_str = path.to_str().unwrap();
        if path.extension().unwrap() != "cairo" {
            return Err(format!("Found non-cairo file '{}' in test_contracts/", path_str));
        }

        // Compare output of cairo-file on file with existing compiled file.
        let file_name = path.file_stem().unwrap().to_str().unwrap();
        let existing_compiled_path = format!("test_contracts/compiled/{file_name}.json");
        let existing_compiled_contents = match fs::read_to_string(&existing_compiled_path) {
            Ok(json_contents) => json_contents,
            Err(_) => return Err(format!("Can't read {}.", existing_compiled_path)),
        };

        let expected_compiled_output =
            Command::new("cairo-compile").args([path_str]).output().unwrap().stdout;

        assert_eq!(
            String::from_utf8(expected_compiled_output).unwrap(),
            existing_compiled_contents
        );
    }
    Ok(())
}
