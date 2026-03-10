use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// SSE Processor Event - represents a complete SSE interaction with timing information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SSEProcessorEvent {
    pub connection_id: String,
    pub message_id: Option<String>,
    pub start_time: u64,
    pub end_time: u64,
    pub duration_ns: u64,
    pub original_source: String,
    pub function: String,
    pub tid: u64,
    pub json_content: String,
    pub text_content: String,
    pub total_size: usize,
    pub event_count: usize,
    pub has_message_start: bool,
    pub sse_events: Vec<Value>,
}

impl SSEProcessorEvent {
    pub fn new(
        connection_id: String,
        message_id: Option<String>,
        start_time: u64,
        end_time: u64,
        original_source: String,
        function: String,
        tid: u64,
        json_content: String,
        text_content: String,
        total_size: usize,
        event_count: usize,
        has_message_start: bool,
        sse_events: Vec<Value>,
    ) -> Self {
        let duration_ns = end_time.saturating_sub(start_time);
        
        SSEProcessorEvent {
            connection_id,
            message_id,
            start_time,
            end_time,
            duration_ns,
            original_source,
            function,
            tid,
            json_content,
            text_content,
            total_size,
            event_count,
            has_message_start,
            sse_events,
        }
    }

}