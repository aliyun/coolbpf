#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 eunomia-bpf org.


# Stop Grafana stack
set -e

echo "🛑 Stopping Grafana stack..."

docker-compose down

echo "✅ Grafana stack stopped"
echo ""
echo "💡 To remove all data (volumes): docker-compose down -v"