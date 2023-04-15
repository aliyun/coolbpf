use metrics_exporter_prometheus::PrometheusBuilder;

pub fn start_prometheus_server() {
    PrometheusBuilder::new().install().unwrap();
}