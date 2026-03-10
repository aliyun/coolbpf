// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

use crate::http_event::HTTPEvent;
use crate::sse_event::SSEProcessorEvent;
use serde_json::Value;
use std::collections::HashMap;

/// SSE (Server-Sent Events) Processor
/// Aggregates HTTP events into complete SSE streams and parses individual SSE events
pub struct SSEProcessor {
    /// Buffer for accumulating incomplete SSE data
    buffer: String,
    /// Position in buffer that has been parsed (to avoid re-parsing)
    parsed_pos: usize,
    /// Connection ID for tracking SSE streams
    connection_id: String,
    /// Start time of the SSE stream (nanoseconds)
    start_time: u64,
    /// TID (thread ID) associated with this stream
    tid: u64,
    /// Original source identifier
    original_source: String,
    /// Accumulated SSE events
    sse_events: Vec<SSEEvent>,
    /// Total bytes processed
    total_size: usize,
    /// Function name extracted from the stream
    function: String,
    /// Message ID from SSE events
    message_id: Option<String>,
    /// Whether a message_start event was detected
    has_message_start: bool,
}

/// Represents a single SSE event parsed from the stream
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SSEEvent {
    /// Event type (e.g., "message", "error", "done")
    pub event: Option<String>,
    /// Event data (can be multi-line)
    pub data: String,
    /// Event ID
    pub id: Option<String>,
    /// Retry interval (in milliseconds)
    pub retry: Option<u64>,
    /// Parsed JSON data if the data field contains valid JSON
    pub parsed_json: Option<Value>,
}

impl SSEEvent {
    /// Parse a single SSE event from text
    pub fn parse(text: &str) -> Option<Self> {
        let mut event = SSEEvent {
            event: None,
            data: String::new(),
            id: None,
            retry: None,
            parsed_json: None,
        };

        let mut has_data = false;

        for line in text.lines() {
            if line.is_empty() {
                continue;
            }

            if let Some(value) = line.strip_prefix("event:") {
                event.event = Some(value.trim().to_string());
            } else if let Some(value) = line.strip_prefix("data:") {
                if !event.data.is_empty() {
                    event.data.push('\n');
                }
                event.data.push_str(value.trim());
                has_data = true;
            } else if let Some(value) = line.strip_prefix("id:") {
                event.id = Some(value.trim().to_string());
            } else if let Some(value) = line.strip_prefix("retry:") {
                event.retry = value.trim().parse().ok();
            }
        }

        if has_data {
            // Try to parse data as JSON
            if let Ok(json) = serde_json::from_str(&event.data) {
                event.parsed_json = Some(json);
            }
            Some(event)
        } else {
            None
        }
    }
}

impl SSEProcessor {
    /// Create a new SSE processor
    pub fn new() -> Self {
        Self {
            buffer: String::new(),
            parsed_pos: 0,
            connection_id: String::new(),
            start_time: 0,
            tid: 0,
            original_source: String::new(),
            sse_events: Vec::new(),
            total_size: 0,
            function: String::new(),
            message_id: None,
            has_message_start: false,
        }
    }

    /// Create a processor with a specific connection ID
    pub fn with_connection_id(connection_id: impl Into<String>) -> Self {
        let mut processor = Self::new();
        processor.connection_id = connection_id.into();
        processor
    }

    /// Check if an HTTP event is an SSE stream
    pub fn is_sse_response(event: &HTTPEvent) -> bool {
        // Check if it's a response with SSE content type
        if event.message_type != "response" {
            return false;
        }

        let content_type = event
            .headers
            .get("content-type")
            .map(|v| v.to_lowercase())
            .unwrap_or_default();

        content_type.contains("text/event-stream")
    }

    /// Process an HTTP event and extract SSE data
    /// Returns Some(SSEProcessorEvent) if a complete SSE stream is detected
    pub fn process_http_event(&mut self, event: &HTTPEvent, timestamp_ns: u64) -> Option<SSEProcessorEvent> {
        // Check if this is an SSE response
        if !Self::is_sse_response(event) {
            return None;
        }

        // Initialize processor state if this is a new stream
        if self.start_time == 0 {
            self.start_time = timestamp_ns;
            self.tid = event.tid;
            self.original_source = event.original_source.clone();
            self.connection_id = format!("{}-{}", event.tid, timestamp_ns);
        }

        // Extract body content
        let body = match &event.body {
            Some(b) => b,
            None => return None,
        };

        // Handle chunked encoding - strip chunk size markers
        let content = if event.is_chunked {
            self.decode_chunked(body)
        } else {
            body.clone()
        };

        // Accumulate data
        self.buffer.push_str(&content);
        self.total_size += content.len();

        // Parse SSE events from buffer
        self.parse_sse_events();

        // Check if the stream is complete
        // SSE streams typically end with "data: [DONE]" or similar markers
        if self.is_stream_complete() {
            self.create_sse_processor_event(timestamp_ns)
        } else {
            None
        }
    }

    /// Process raw SSE data directly
    pub fn process_raw_data(&mut self, data: &str, tid: u64, timestamp_ns: u64) -> Option<SSEProcessorEvent> {
        if self.start_time == 0 {
            self.start_time = timestamp_ns;
            self.tid = tid;
            self.original_source = "raw".to_string();
            self.connection_id = format!("{}-{}", tid, timestamp_ns);
        }

        self.buffer.push_str(data);
        self.total_size += data.len();

        self.parse_sse_events();

        if self.is_stream_complete() {
            self.create_sse_processor_event(timestamp_ns)
        } else {
            None
        }
    }

    /// Decode chunked transfer encoding
    fn decode_chunked(&self, data: &str) -> String {
        let mut result = String::new();
        let mut lines = data.lines();
        let mut in_chunk = false;
        let mut remaining_chunk_size = 0usize;

        while let Some(line) = lines.next() {
            if !in_chunk {
                // Parse chunk size
                if let Ok(size) = usize::from_str_radix(line.trim(), 16) {
                    if size == 0 {
                        break; // End of chunks
                    }
                    remaining_chunk_size = size;
                    in_chunk = true;
                }
            } else {
                // This is chunk data
                let line_bytes = line.len();
                if line_bytes <= remaining_chunk_size {
                    result.push_str(line);
                    remaining_chunk_size -= line_bytes;
                } else {
                    result.push_str(&line[..remaining_chunk_size]);
                    remaining_chunk_size = 0;
                }
                
                if remaining_chunk_size == 0 {
                    in_chunk = false;
                }
            }
        }

        result
    }

    /// Parse SSE events from the buffer (only new data since last parse)
    fn parse_sse_events(&mut self) {
        // Only process the unparsed portion of the buffer
        let unparsed = &self.buffer[self.parsed_pos..];
        
        // Find complete SSE events (ending with \n\n)
        let mut last_complete_end = 0;
        let mut search_start = 0;
        
        while let Some(pos) = unparsed[search_start..].find("\n\n") {
            let event_end = search_start + pos + 2; // Include the \n\n
            let event_text = &unparsed[last_complete_end..event_end - 2]; // Exclude \n\n for parsing
            
            if !event_text.trim().is_empty() {
                if let Some(sse_event) = SSEEvent::parse(event_text) {
                    self.process_sse_event(sse_event);
                }
            }
            
            last_complete_end = event_end;
            search_start = event_end;
        }
        
        // Update parsed position (only complete events)
        self.parsed_pos += last_complete_end;
        
        // Clean up buffer - remove fully parsed portion
        if self.parsed_pos > 0 && self.parsed_pos >= self.buffer.len() {
            self.buffer.clear();
            self.parsed_pos = 0;
        }
    }
    
    /// Process a single SSE event and extract metadata
    fn process_sse_event(&mut self, sse_event: SSEEvent) {
        // Check for special events
        if let Some(ref event_type) = sse_event.event {
            if event_type == "message_start" || event_type == "message_start_event" {
                self.has_message_start = true;
            }
        }

        // Extract function name from the first event if possible
        if self.function.is_empty() {
            if let Some(ref json) = sse_event.parsed_json {
                if let Some(func) = json.get("function").and_then(|v| v.as_str()) {
                    self.function = func.to_string();
                } else if let Some(func) = json.get("name").and_then(|v| v.as_str()) {
                    self.function = func.to_string();
                }
            }
        }

        // Extract message ID (only once)
        if self.message_id.is_none() {
            if let Some(ref id) = sse_event.id {
                self.message_id = Some(id.clone());
            } else if let Some(ref json) = sse_event.parsed_json {
                if let Some(id) = json.get("id").and_then(|v| v.as_str()) {
                    self.message_id = Some(id.to_string());
                }
            }
        }

        self.sse_events.push(sse_event);
    }

    /// Check if the SSE stream is complete
    fn is_stream_complete(&self) -> bool {
        // Check for common completion markers
        for event in &self.sse_events {
            // OpenAI style: data: [DONE]
            if event.data == "[DONE]" {
                return true;
            }
            
            // Check for done event type
            if let Some(ref event_type) = event.event {
                if event_type == "done" || event_type == "end" {
                    return true;
                }
            }

            // Check for finish_reason in parsed JSON
            if let Some(ref json) = event.parsed_json {
                if let Some(finish_reason) = json.get("finish_reason").and_then(|v| v.as_str()) {
                    if !finish_reason.is_empty() && finish_reason != "null" {
                        return true;
                    }
                }
            }
        }

        false
    }

    /// Create an SSEProcessorEvent from accumulated data
    fn create_sse_processor_event(&self, end_time: u64) -> Option<SSEProcessorEvent> {
        if self.sse_events.is_empty() {
            return None;
        }

        // Extract all text content
        let text_content: String = self
            .sse_events
            .iter()
            .filter_map(|e| {
                if e.data != "[DONE]" {
                    Some(e.data.clone())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
            .join("\n");

        // Extract all JSON content
        let json_content: String = self
            .sse_events
            .iter()
            .filter_map(|e| {
                if e.data != "[DONE]" {
                    e.parsed_json.as_ref().and_then(|j| {
                        serde_json::to_string(j).ok()
                    })
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
            .join("\n");

        // Convert SSE events to JSON values
        let sse_events_json: Vec<Value> = self
            .sse_events
            .iter()
            .filter_map(|e| serde_json::to_value(e).ok())
            .collect();

        Some(SSEProcessorEvent::new(
            self.connection_id.clone(),
            self.message_id.clone(),
            self.start_time,
            end_time,
            self.original_source.clone(),
            self.function.clone(),
            self.tid,
            json_content,
            text_content,
            self.total_size,
            self.sse_events.len(),
            self.has_message_start,
            sse_events_json,
        ))
    }

    /// Force completion of the current stream
    pub fn flush(&mut self, end_time: u64) -> Option<SSEProcessorEvent> {
        if self.sse_events.is_empty() && self.buffer.is_empty() {
            return None;
        }

        // Parse any remaining data in buffer
        if !self.buffer.is_empty() {
            // Try to parse remaining content as an event
            if let Some(sse_event) = SSEEvent::parse(&self.buffer) {
                self.sse_events.push(sse_event);
            }
            self.buffer.clear();
        }

        self.create_sse_processor_event(end_time)
    }

    /// Reset the processor for a new stream
    pub fn reset(&mut self) {
        self.buffer.clear();
        self.parsed_pos = 0;
        self.connection_id.clear();
        self.start_time = 0;
        self.tid = 0;
        self.original_source.clear();
        self.sse_events.clear();
        self.total_size = 0;
        self.function.clear();
        self.message_id = None;
        self.has_message_start = false;
    }

    /// Get the current buffer content
    pub fn buffer(&self) -> &str {
        &self.buffer
    }

    /// Get the number of parsed SSE events
    pub fn event_count(&self) -> usize {
        self.sse_events.len()
    }

    /// Get the total bytes processed
    pub fn total_size(&self) -> usize {
        self.total_size
    }

    /// Check if the processor has any data
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty() && self.sse_events.is_empty()
    }
}

impl Default for SSEProcessor {
    fn default() -> Self {
        Self::new()
    }
}

/// Utility function to parse SSE events from a string
pub fn parse_sse_events(data: &str) -> Vec<SSEEvent> {
    let mut events = Vec::new();
    let parts: Vec<&str> = data.split("\n\n").collect();

    for part in parts {
        if part.trim().is_empty() {
            continue;
        }
        if let Some(event) = SSEEvent::parse(part) {
            events.push(event);
        }
    }

    events
}

/// Utility function to extract text content from SSE events
pub fn extract_text_content(events: &[SSEEvent]) -> String {
    events
        .iter()
        .filter_map(|e| {
            if e.data != "[DONE]" {
                // Try to extract content field from JSON
                if let Some(ref json) = e.parsed_json {
                    if let Some(content) = json.get("content").and_then(|v| v.as_str()) {
                        return Some(content.to_string());
                    }
                    if let Some(delta) = json.get("delta").and_then(|v| v.get("content")) {
                        if let Some(content) = delta.as_str() {
                            return Some(content.to_string());
                        }
                    }
                }
                // Fall back to raw data
                Some(e.data.clone())
            } else {
                None
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sse_event_parse() {
        let data = "event: message\ndata: {\"text\": \"hello\"}\nid: 123";
        let event = SSEEvent::parse(data).unwrap();

        assert_eq!(event.event, Some("message".to_string()));
        assert_eq!(event.data, "{\"text\": \"hello\"}");
        assert_eq!(event.id, Some("123".to_string()));
        assert!(event.parsed_json.is_some());
    }

    #[test]
    fn test_sse_event_parse_multiline_data() {
        let data = "event: message\ndata: line1\ndata: line2";
        let event = SSEEvent::parse(data).unwrap();

        assert_eq!(event.data, "line1\nline2");
    }

    #[test]
    fn test_parse_sse_events() {
        let data = "event: message\ndata: {\"text\": \"hello\"}\n\nevent: done\ndata: [DONE]";
        let events = parse_sse_events(data);

        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event, Some("message".to_string()));
        assert_eq!(events[1].data, "[DONE]");
    }

    #[test]
    fn test_is_sse_response() {
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "text/event-stream".to_string());

        let event = HTTPEvent::new(
            1,
            "response".to_string(),
            "HTTP/1.1 200 OK".to_string(),
            None,
            None,
            Some("HTTP/1.1".to_string()),
            Some(200),
            Some("OK".to_string()),
            headers,
            None,
            0,
            false,
            false,
            None,
            "ssl".to_string(),
        );

        assert!(SSEProcessor::is_sse_response(&event));
    }

    #[test]
    fn test_chunked_decoding() {
        let processor = SSEProcessor::new();
        let chunked_data = "5\r\nhello\r\n6\r\n world\r\n0\r\n";
        let decoded = processor.decode_chunked(chunked_data);
        assert_eq!(decoded, "hello world");
    }

    #[test]
    fn test_stream_completion_detection() {
        let mut processor = SSEProcessor::new();
        
        // Add a [DONE] event
        let event = SSEEvent::parse("data: [DONE]").unwrap();
        processor.sse_events.push(event);
        
        assert!(processor.is_stream_complete());
    }
}
