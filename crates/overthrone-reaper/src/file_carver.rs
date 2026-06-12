//! File-Format-Aware Secret Carver
//!
//! Extracts secrets from structured file formats (DOCX, XLSX, PPTX, PDF, ZIP).
//! These formats are actually ZIP archives containing XML - we parse them to find:
//! - Embedded credentials in connection strings
//! - Hidden metadata with usernames/passwords
//! - Comments containing sensitive information
//! - Embedded objects with credentials
//!
//! Uses the `zip` crate for archive parsing and `quick-xml` for XML parsing.

use overthrone_core::error::Result;
use serde::{Deserialize, Serialize};
use std::io::Cursor;
use std::path::Path;
use tracing::{debug, info};

/// Secret found within a file's content
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CarvedSecret {
    /// Source file path
    pub source_file: String,
    /// File format (docx, xlsx, pdf, etc.)
    pub file_format: String,
    /// Type of secret found
    pub secret_type: String,
    /// The actual secret value (sanitized if needed)
    pub secret_value: String,
    /// Context around the secret
    pub context: String,
    /// Severity: 1=Critical, 2=High, 3=Medium, 4=Low
    pub severity: u8,
}

/// Result from carving a single file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CarveResult {
    /// File that was carved
    pub file_path: String,
    /// Whether carving succeeded
    pub success: bool,
    /// Secrets found
    pub secrets: Vec<CarvedSecret>,
    /// Error message if any
    pub error: Option<String>,
}

/// File format carver configuration
#[derive(Debug, Clone)]
pub struct FileCarverConfig {
    /// Maximum file size to carve (bytes, default 50MB)
    pub max_file_size: u64,
    /// Carve DOCX files
    pub carve_docx: bool,
    /// Carve XLSX files
    pub carve_xlsx: bool,
    /// Carve PPTX files
    pub carve_pptx: bool,
    /// Carve PDF files
    pub carve_pdf: bool,
    /// Extract connection strings
    pub extract_connections: bool,
    /// Extract credentials
    pub extract_credentials: bool,
    /// Extract metadata
    pub extract_metadata: bool,
    /// Extract comments
    pub extract_comments: bool,
}

impl Default for FileCarverConfig {
    fn default() -> Self {
        Self {
            max_file_size: 50 * 1024 * 1024, // 50MB
            carve_docx: true,
            carve_xlsx: true,
            carve_pptx: true,
            carve_pdf: true,
            extract_connections: true,
            extract_credentials: true,
            extract_metadata: true,
            extract_comments: true,
        }
    }
}

/// File format carver
pub struct FileCarver {
    config: FileCarverConfig,
}

impl Default for FileCarver {
    fn default() -> Self {
        Self::new()
    }
}

impl FileCarver {
    /// Create new file carver with default config
    pub fn new() -> Self {
        Self {
            config: FileCarverConfig::default(),
        }
    }

    /// Create new file carver with custom config
    pub fn with_config(config: FileCarverConfig) -> Self {
        Self { config }
    }

    /// Carve secrets from a single file
    pub async fn carve_file(&self, file_path: &str) -> Result<CarveResult> {
        let path = Path::new(file_path);

        if !path.exists() {
            return Ok(CarveResult {
                file_path: file_path.to_string(),
                success: false,
                secrets: vec![],
                error: Some("File does not exist".to_string()),
            });
        }

        let metadata = std::fs::metadata(path)?;
        if metadata.len() > self.config.max_file_size {
            return Ok(CarveResult {
                file_path: file_path.to_string(),
                success: false,
                secrets: vec![],
                error: Some(format!(
                    "File too large ({} bytes > {} bytes limit)",
                    metadata.len(),
                    self.config.max_file_size
                )),
            });
        }

        let extension = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();

        let file_data = tokio::fs::read(path).await?;

        match extension.as_str() {
            "docx" if self.config.carve_docx => {
                self.carve_office_file(&file_data, file_path, "DOCX").await
            }
            "xlsx" if self.config.carve_xlsx => {
                self.carve_office_file(&file_data, file_path, "XLSX").await
            }
            "pptx" if self.config.carve_pptx => {
                self.carve_office_file(&file_data, file_path, "PPTX").await
            }
            "pdf" if self.config.carve_pdf => self.carve_pdf_file(&file_data, file_path).await,
            _ => Ok(CarveResult {
                file_path: file_path.to_string(),
                success: false,
                secrets: vec![],
                error: Some(format!(
                    "Unsupported or disabled file format: {}",
                    extension
                )),
            }),
        }
    }

    /// Carve Office Open XML files (DOCX, XLSX, PPTX)
    async fn carve_office_file(
        &self,
        file_data: &[u8],
        file_path: &str,
        format: &str,
    ) -> Result<CarveResult> {
        let mut secrets = Vec::new();

        // Office files are ZIP archives
        let mut archive = match zip::ZipArchive::new(Cursor::new(file_data)) {
            Ok(arch) => arch,
            Err(e) => {
                return Ok(CarveResult {
                    file_path: file_path.to_string(),
                    success: false,
                    secrets: vec![],
                    error: Some(format!("Failed to open {} as ZIP: {}", format, e)),
                });
            }
        };

        let file_count = archive.len();
        debug!("Carving {} with {} internal files", format, file_count);

        for i in 0..file_count {
            let mut file = match archive.by_index(i) {
                Ok(f) => f,
                Err(_) => continue,
            };

            let name = file.name().to_string();

            // Skip non-XML files
            if !name.ends_with(".xml") && !name.ends_with(".rels") {
                continue;
            }

            let mut content = String::new();
            if std::io::Read::read_to_string(&mut file, &mut content).is_err() {
                continue;
            }

            // Extract secrets based on config
            if self.config.extract_connections {
                secrets.extend(self.extract_connection_strings(&content, file_path, format, &name));
            }
            if self.config.extract_credentials {
                secrets
                    .extend(self.extract_credentials_from_xml(&content, file_path, format, &name));
            }
            if self.config.extract_metadata {
                secrets.extend(self.extract_metadata_from_xml(&content, file_path, format, &name));
            }
            if self.config.extract_comments {
                secrets.extend(self.extract_comments_from_xml(&content, file_path, format, &name));
            }
        }

        info!(
            "Carved {} from {}: {} secrets found",
            format,
            file_path,
            secrets.len()
        );

        Ok(CarveResult {
            file_path: file_path.to_string(),
            success: true,
            secrets,
            error: None,
        })
    }

    /// Carve PDF files for embedded secrets
    async fn carve_pdf_file(&self, file_data: &[u8], file_path: &str) -> Result<CarveResult> {
        let mut secrets = Vec::new();

        // Convert to string (lossy) for pattern matching
        let content = String::from_utf8_lossy(file_data);

        // Extract connection strings
        if self.config.extract_connections {
            secrets.extend(self.extract_connection_strings(&content, file_path, "PDF", "embedded"));
        }

        // Extract credentials
        if self.config.extract_credentials {
            secrets
                .extend(self.extract_credentials_from_xml(&content, file_path, "PDF", "embedded"));
        }

        // Extract metadata from PDF info dictionary
        if self.config.extract_metadata {
            secrets.extend(self.extract_pdf_metadata(file_data, file_path));
        }

        info!("Carved PDF {}: {} secrets found", file_path, secrets.len());

        Ok(CarveResult {
            file_path: file_path.to_string(),
            success: true,
            secrets,
            error: None,
        })
    }

    /// Extract database connection strings from XML/text content
    fn extract_connection_strings(
        &self,
        content: &str,
        file_path: &str,
        format: &str,
        source: &str,
    ) -> Vec<CarvedSecret> {
        let mut secrets = Vec::new();

        // Patterns for connection strings
        let patterns = vec![
            (
                "connectionString",
                r#"connectionString\s*=\s*["\x27]([^"\x27]+)["\x27]"#,
                "Database connection string",
                1,
            ),
            (
                "Server=.*Database=",
                r"Server=[^;]+;Database=[^;]+(?:;User ID=[^;]+;Password=([^;]+))?",
                "SQL connection string",
                1,
            ),
            (
                "Data Source=",
                r"Data Source=[^;]+(?:;Initial Catalog=[^;]+)?(?:;User ID=[^;]+;Password=([^;]+))?",
                "ADO.NET connection string",
                1,
            ),
            ("jdbc:", r"jdbc:[^\s\x22\x27]+", "JDBC connection string", 2),
        ];

        for (pattern_name, regex_str, secret_type, severity) in patterns {
            if let Ok(regex) = regex::Regex::new(regex_str) {
                for cap in regex.captures_iter(content) {
                    if cap.get(0).is_some() {
                        let secret_value = if cap.len() > 1 {
                            cap.get(1)
                                .map(|m| m.as_str().to_string())
                                .unwrap_or_else(|| "[password present]".to_string())
                        } else {
                            "[connection string]".to_string()
                        };

                        secrets.push(CarvedSecret {
                            source_file: file_path.to_string(),
                            file_format: format.to_string(),
                            secret_type: secret_type.to_string(),
                            secret_value: self.sanitize_secret(&secret_value),
                            context: format!("Found in {} ({})", source, pattern_name),
                            severity,
                        });
                    }
                }
            }
        }

        secrets
    }

    /// Extract credentials from XML content
    fn extract_credentials_from_xml(
        &self,
        content: &str,
        file_path: &str,
        format: &str,
        source: &str,
    ) -> Vec<CarvedSecret> {
        let mut secrets = Vec::new();

        // Patterns for credentials
        let patterns = vec![
            (
                r#"password\s*=\s*["\x27]([^"\x27]{3,})["\x27]"#,
                "Password attribute",
                1,
            ),
            (
                r#"pwd\s*=\s*["\x27]([^"\x27]{3,})["\x27]"#,
                "Password (pwd) attribute",
                1,
            ),
            (
                r"<Password[^>]*>([^<]{3,})</Password>",
                "Password element",
                1,
            ),
            (
                r#"api[_-]?key\s*=\s*["\x27]([^"\x27]{8,})["\x27]"#,
                "API key",
                2,
            ),
            (
                r#"secret\s*=\s*["\x27]([^"\x27]{8,})["\x27]"#,
                "Secret key",
                1,
            ),
            (
                r#"access[_-]?token\s*=\s*["\x27]([^"\x27]{8,})["\x27]"#,
                "Access token",
                2,
            ),
        ];

        for (regex_str, secret_type, severity) in patterns {
            if let Ok(regex) = regex::Regex::new(regex_str) {
                for cap in regex.captures_iter(content) {
                    if let Some(matched) = cap.get(1) {
                        let value = matched.as_str();

                        // Skip common false positives
                        if self.is_false_positive(value) {
                            continue;
                        }

                        secrets.push(CarvedSecret {
                            source_file: file_path.to_string(),
                            file_format: format.to_string(),
                            secret_type: secret_type.to_string(),
                            secret_value: self.sanitize_secret(value),
                            context: format!("Found in {} ({})", source, secret_type),
                            severity,
                        });
                    }
                }
            }
        }

        secrets
    }

    /// Extract metadata from Office XML
    fn extract_metadata_from_xml(
        &self,
        content: &str,
        file_path: &str,
        format: &str,
        source: &str,
    ) -> Vec<CarvedSecret> {
        let mut secrets = Vec::new();

        // Look for author, lastModifiedBy, company with potential usernames
        let patterns = vec![
            (
                r"<dc:creator[^>]*>([^<]+)</dc:creator>",
                "Document author",
                3,
            ),
            (
                r"<cp:lastModifiedBy[^>]*>([^<]+)</cp:lastModifiedBy>",
                "Last modified by",
                3,
            ),
            (r"<Company[^>]*>([^<]+)</Company>", "Company name", 4),
        ];

        for (regex_str, secret_type, severity) in patterns {
            if let Ok(regex) = regex::Regex::new(regex_str) {
                for cap in regex.captures_iter(content) {
                    if let Some(matched) = cap.get(1) {
                        let value = matched.as_str().trim();

                        // Skip empty or generic values
                        if value.is_empty() || value == " " || value.len() < 2 {
                            continue;
                        }

                        secrets.push(CarvedSecret {
                            source_file: file_path.to_string(),
                            file_format: format.to_string(),
                            secret_type: secret_type.to_string(),
                            secret_value: value.to_string(),
                            context: format!("Found in {} metadata ({})", source, secret_type),
                            severity,
                        });
                    }
                }
            }
        }

        secrets
    }

    /// Extract comments from Office XML
    fn extract_comments_from_xml(
        &self,
        content: &str,
        file_path: &str,
        format: &str,
        source: &str,
    ) -> Vec<CarvedSecret> {
        let mut secrets = Vec::new();

        // Look for comments that might contain credentials or sensitive info
        let patterns = vec![
            (
                r"<!--[^>]*(?:password|credential|secret|key|token)[^>]*-->",
                "Sensitive comment",
                2,
            ),
            (r"<w:comment[^>]*>(.*?)</w:comment>", "Document comment", 3),
        ];

        for (regex_str, secret_type, severity) in patterns {
            if let Ok(regex) = regex::Regex::new(regex_str) {
                for cap in regex.captures_iter(content) {
                    if let Some(matched) = cap.get(0) {
                        let value = matched.as_str();

                        // Check if comment contains actual sensitive keywords
                        let lower = value.to_lowercase();
                        if lower.contains("password")
                            || lower.contains("credential")
                            || lower.contains("secret")
                            || lower.contains("api key")
                        {
                            secrets.push(CarvedSecret {
                                source_file: file_path.to_string(),
                                file_format: format.to_string(),
                                secret_type: secret_type.to_string(),
                                secret_value: self.sanitize_secret(value),
                                context: format!("Found in {} ({})", source, secret_type),
                                severity,
                            });
                        }
                    }
                }
            }
        }

        secrets
    }

    /// Extract PDF metadata
    fn extract_pdf_metadata(&self, file_data: &[u8], file_path: &str) -> Vec<CarvedSecret> {
        let mut secrets = Vec::new();
        let content = String::from_utf8_lossy(file_data);

        // PDF metadata patterns
        let patterns = vec![
            (r"/Author\s*\(([^)]+)\)", "PDF author", 3),
            (r"/Creator\s*\(([^)]+)\)", "PDF creator", 3),
            (r"/Producer\s*\(([^)]+)\)", "PDF producer", 4),
        ];

        for (regex_str, secret_type, severity) in patterns {
            if let Ok(regex) = regex::Regex::new(regex_str) {
                for cap in regex.captures_iter(&content) {
                    if let Some(matched) = cap.get(1) {
                        let value = matched.as_str().trim();

                        if value.is_empty() || value.len() < 2 {
                            continue;
                        }

                        secrets.push(CarvedSecret {
                            source_file: file_path.to_string(),
                            file_format: "PDF".to_string(),
                            secret_type: secret_type.to_string(),
                            secret_value: value.to_string(),
                            context: format!("Found in PDF metadata ({})", secret_type),
                            severity,
                        });
                    }
                }
            }
        }

        secrets
    }

    /// Sanitize secret for safe display (mask passwords)
    fn sanitize_secret(&self, value: &str) -> String {
        if value.len() <= 8 {
            return "[REDACTED]".to_string();
        }

        // Show first 2 and last 2 characters
        let first = &value[..2];
        let last = &value[value.len() - 2..];
        format!("{}...{}", first, last)
    }

    /// Check if a value is a common false positive
    fn is_false_positive(&self, value: &str) -> bool {
        let lower = value.to_lowercase();

        // Common placeholders and test values
        let false_positives = vec![
            "password",
            "your_password",
            "your_password_here",
            "changeme",
            "change_me",
            "xxx",
            "test",
            "example",
            "placeholder",
            "insert_password",
            "***",
            "****",
        ];

        false_positives.iter().any(|fp| lower.contains(*fp))
    }
}

/// Carve multiple files concurrently
pub async fn carve_files(
    file_paths: &[String],
    config: Option<FileCarverConfig>,
) -> Vec<CarveResult> {
    let carver = match config {
        Some(cfg) => FileCarver::with_config(cfg),
        None => FileCarver::new(),
    };

    let mut results = Vec::new();

    for file_path in file_paths {
        match carver.carve_file(file_path).await {
            Ok(result) => results.push(result),
            Err(e) => {
                results.push(CarveResult {
                    file_path: file_path.clone(),
                    success: false,
                    secrets: vec![],
                    error: Some(e.to_string()),
                });
            }
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_carver_config_default() {
        let config = FileCarverConfig::default();
        assert!(config.carve_docx);
        assert!(config.carve_xlsx);
        assert!(config.carve_pptx);
        assert!(config.carve_pdf);
        assert_eq!(config.max_file_size, 50 * 1024 * 1024);
    }

    #[test]
    fn test_sanitize_secret_short() {
        let carver = FileCarver::new();
        assert_eq!(carver.sanitize_secret("abc"), "[REDACTED]");
        assert_eq!(carver.sanitize_secret("12345678"), "[REDACTED]");
    }

    #[test]
    fn test_sanitize_secret_long() {
        let carver = FileCarver::new();
        let result = carver.sanitize_secret("MySecretPassword123!");
        assert!(result.starts_with("My"));
        assert!(result.ends_with("3!"));
        assert!(result.contains("..."));
    }

    #[test]
    fn test_is_false_positive() {
        let carver = FileCarver::new();
        assert!(carver.is_false_positive("password"));
        assert!(carver.is_false_positive("ChangeMe"));
        assert!(carver.is_false_positive("your_password_here"));
        assert!(!carver.is_false_positive("P@ssw0rd!2024"));
        assert!(!carver.is_false_positive("ActualSecretKey123"));
    }

    #[test]
    fn test_extract_connection_strings() {
        let carver = FileCarver::new();
        let content = r#"<configuration>
            <connectionStrings>
                <add name="Default" connectionString="Server=db.corp.local;Database=Production;User ID=sa;Password=S3cretP@ss!"/>
            </connectionStrings>
        </configuration>"#;

        let secrets = carver.extract_connection_strings(content, "test.config", "XML", "test.xml");

        assert!(!secrets.is_empty());
        assert!(secrets.iter().any(|s| s.secret_type.contains("connection")));
    }

    #[test]
    fn test_extract_credentials() {
        let carver = FileCarver::new();
        let content = r#"<settings>
            <api_key="sk-1234567890abcdef"/>
            <password="SuperSecret123!"/>
        </settings>"#;

        let secrets =
            carver.extract_credentials_from_xml(content, "test.xml", "XML", "settings.xml");

        assert!(!secrets.is_empty());
    }

    #[test]
    fn test_carve_nonexistent_file() {
        use tokio::runtime::Runtime;
        let rt = Runtime::new().unwrap();

        let result = rt.block_on(async {
            let carver = FileCarver::new();
            carver.carve_file("/nonexistent/file.docx").await.unwrap()
        });

        assert!(!result.success);
        assert!(result.error.is_some());
    }
}
