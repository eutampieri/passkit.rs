mod field;
mod pass;
mod personalization;
mod signature;
mod util;

use std::collections::HashMap;
use std::fmt;
use std::fmt::Debug;
use std::fs;
use std::io::prelude::*;
use std::path;

pub use crate::field::*;
pub use crate::pass::*;
pub use crate::personalization::*;

// use Failure
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum PassCreateError {
    CantReadTempDir,
    CantReadEntry(String),
    CantParsePassFile(String),
    PassContentNotFound,
    CantCreateTempDir,
    CantCopySourceToTemp,
    CantSerializePass,
    CantWritePassFile(String),
    CantCalculateHashes,
    CantCreateManifestFile,
    CantSignManifest(String),
}

impl fmt::Display for PassCreateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use crate::PassCreateError::*;
        let stringified = match self {
            CantReadTempDir => "Can't read temporary directory".to_string(),
            CantReadEntry(cause) => format!("Can't read {}", cause),
            CantParsePassFile(cause) => format!("pass.json invalid: {}", cause),
            PassContentNotFound => {
                "Please, provide pass.json or instance of Pass with add_pass() method".to_string()
            }
            CantCreateTempDir => "Can't create temporary directory. Check rights".to_string(),
            CantCopySourceToTemp => "Can't copy source files to temp directory".to_string(),
            CantSerializePass => "Can't serialize pass.json".to_string(),
            CantWritePassFile(cause) => format!("Can't write pass.json {}", cause),
            CantCalculateHashes => "Can't calculate hashes for temp directory".to_string(),
            CantCreateManifestFile => "Can't create manifest file at temp directory".to_string(),
            CantSignManifest(e) => format!("OpenSSL error: {:?}", e),
        };
        write!(f, "PassCreateError: {}", stringified)
    }
}

impl std::error::Error for PassCreateError {}

impl From<std::io::Error> for PassCreateError {
    fn from(_: std::io::Error) -> Self {
        Self::CantCopySourceToTemp
    }
}
impl From<serde_json::Error> for PassCreateError {
    fn from(_e: serde_json::Error) -> Self {
        Self::CantSerializePass
    }
}

impl From<openssl::error::ErrorStack> for PassCreateError {
    fn from(value: openssl::error::ErrorStack) -> Self {
        Self::CantSignManifest(value.to_string())
    }
}

type PassResult<T> = Result<T, PassCreateError>;
type Manifest = HashMap<String, String>;

/// Describes .pass directory with source files
pub struct PassSource {
    /// place where images contains
    source_directory: String,
    certificate: openssl::x509::X509,
    private_key: openssl::pkcs12::ParsedPkcs12,
}

impl Debug for PassSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PassSource")
            .field("source_directory", &self.source_directory)
            .field("certificate", &self.certificate)
            .field("private_key", &"<Hidden>")
            .finish()
    }
}

impl PassSource {
    pub fn new<S: Into<String>>(
        source: S,
        certificate_bytes: &[u8],
        private_key_bytes: &[u8],
        private_key_password: &str,
    ) -> PassSource {
        PassSource {
            source_directory: source.into(),
            certificate: dbg!(openssl::x509::X509::from_der(certificate_bytes)).unwrap(),
            private_key: openssl::pkcs12::Pkcs12::from_der(private_key_bytes)
                .unwrap()
                .parse(private_key_password)
                .unwrap(),
        }
    }

    /// Create .pkpass and return it as a byte array
    pub fn build_pkpass(&mut self, pass: Option<Pass>) -> PassResult<Vec<u8>> {
        use sha1::Digest;

        let pass = self.resolve_pass_content(pass)?;

        let mut out_file = Vec::new();
        let mut zip_writer = zip::write::ZipWriter::new(std::io::Cursor::new(&mut out_file));

        let mut manifest = Manifest::new();

        // Add common files from specified folder
        for file in fs::read_dir(&self.source_directory)?
            .map(|x| self.read_file(x))
            .chain(
                ["pass.json"]
                    .iter()
                    .map(|x| Ok((x.to_string(), serde_json::to_vec(&pass)?))),
            )
        {
            let (filename, bytes) = file?;
            // Calculate hash and update manifest
            let hash = hex::encode(sha1::Sha1::digest(&bytes));
            manifest.insert(filename.clone(), hash);

            // Add file to ZIP
            self.add_file_to_zip(&mut zip_writer, &filename, &bytes);
        }

        let manifest = serde_json::to_vec(&manifest)?;

        // Add manifest
        self.add_file_to_zip(&mut zip_writer, "manifest.json", &manifest);

        // Sign manifest
        self.add_file_to_zip(
            &mut zip_writer,
            "signature",
            &crate::signature::sign(&self.certificate, &self.private_key.pkey, &manifest)?,
        );

        zip_writer.finish().unwrap();
        drop(zip_writer);
        Ok(out_file)
    }

    fn read_file(
        &self,
        file: std::io::Result<std::fs::DirEntry>,
    ) -> Result<(String, Vec<u8>), PassCreateError> {
        let file = file?;
        let entry_path = &file.path();
        let target = entry_path
            .strip_prefix(&self.source_directory)
            .map_err(|__| std::io::Error::from(std::io::ErrorKind::Other))?;

        let bytes = std::fs::read(entry_path)?;
        Ok((target.to_string_lossy().to_string(), bytes))
    }

    fn add_file_to_zip<W: Write + Seek>(
        &self,
        zip_writer: &mut zip::ZipWriter<W>,
        filename: &str,
        bytes: &[u8],
    ) {
        zip_writer.start_file(filename, Default::default());
        zip_writer.write_all(bytes);
    }

    /// Parse pass.json from source directory if Pass not provided
    fn resolve_pass_content(&mut self, pass_content: Option<Pass>) -> PassResult<Pass> {
        if pass_content.is_none() && self.pass_file_exists_in_source() {
            Ok(self.read_pass_file_from_source()?)
        } else if let Some(p) = pass_content {
            Ok(p)
        } else {
            Err(PassCreateError::PassContentNotFound)
        }
    }

    fn pass_file_exists_in_source(&self) -> bool {
        self.pass_source_file_path().exists()
    }

    fn read_pass_file_from_source(&self) -> PassResult<Pass> {
        let content = std::fs::read_to_string(self.pass_source_file_path())
            .map_err(|_| PassCreateError::CantReadEntry("pass.json".to_string()))?;
        let pass: Pass = serde_json::from_str(&content)
            .map_err(|cause| PassCreateError::CantParsePassFile(cause.to_string()))?;
        Ok(pass)
    }

    fn pass_source_file_path(&self) -> Box<path::Path> {
        let path = path::Path::new(&self.source_directory).join("pass.json");
        path.into_boxed_path()
    }
}
