use std::collections::HashMap;
use serde::{Deserialize, Serialize};
/// HTTP Event - represents a parsed HTTP request or response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HTTPEvent {
    pub tid: u64,
    pub message_type: String,
    pub first_line: String,
    pub method: Option<String>,
    pub path: Option<String>,
    pub protocol: Option<String>,
    pub status_code: Option<u16>,
    pub status_text: Option<String>,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
    pub total_size: usize,
    pub has_body: bool,
    pub is_chunked: bool,
    pub content_length: Option<usize>,
    pub original_source: String,
    pub raw_data: Option<String>,
}

impl HTTPEvent {
    pub fn new(
        tid: u64,
        message_type: String,
        first_line: String,
        method: Option<String>,
        path: Option<String>,
        protocol: Option<String>,
        status_code: Option<u16>,
        status_text: Option<String>,
        headers: HashMap<String, String>,
        body: Option<String>,
        total_size: usize,
        has_body: bool,
        is_chunked: bool,
        content_length: Option<usize>,
        original_source: String,
    ) -> Self {
        HTTPEvent {
            tid,
            message_type,
            first_line,
            method,
            path,
            protocol,
            status_code,
            status_text,
            headers,
            body,
            total_size,
            has_body,
            is_chunked,
            content_length,
            original_source,
            raw_data: None,
        }
    }

    pub fn with_raw_data(mut self, raw_data: String) -> Self {
        self.raw_data = Some(raw_data);
        self
    }

}