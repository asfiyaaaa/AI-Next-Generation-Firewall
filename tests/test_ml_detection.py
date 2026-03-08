"""
Unit Tests — ML Detection & Connection Tracking

Tests for:
- Connection state management
- Connection table operations (lookup, insert, expiry)
- Sharded connection table performance characteristics
- ML prediction data validation
"""
import sys
import time
import pytest
from pathlib import Path

# Ensure project root is on path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.core.connection import (
    ConnectionState, Connection, ConnectionShard, ConnectionTable
)


# =========================================================================
# Connection Model Tests
# =========================================================================

class TestConnection:
    """Tests for the Connection data model."""

    def _make_connection(self, src_port=54321, dst_port=80) -> Connection:
        return Connection(
            src_ip="192.168.1.100", src_port=src_port,
            dst_ip="93.184.216.34", dst_port=dst_port,
            protocol=6,  # TCP
            state=ConnectionState.NEW
        )

    def test_connection_creation(self):
        conn = self._make_connection()
        assert conn.src_ip == "192.168.1.100"
        assert conn.state == ConnectionState.NEW
        assert conn.protocol == 6

    def test_connection_key_unique(self):
        conn1 = self._make_connection(src_port=54321)
        conn2 = self._make_connection(src_port=54322)
        assert conn1.get_key() != conn2.get_key()

    def test_reverse_key(self):
        conn = self._make_connection()
        key = conn.get_key()
        reverse_key = conn.get_reverse_key()
        assert key != reverse_key
        # Reverse should swap src/dst
        assert "93.184.216.34" in reverse_key
        assert "192.168.1.100" in reverse_key

    def test_update_stats_inbound(self):
        conn = self._make_connection()
        conn.update_stats(bytes_count=1500, is_inbound=True)
        assert conn.bytes_in == 1500
        assert conn.packets_in == 1

    def test_update_stats_outbound(self):
        conn = self._make_connection()
        conn.update_stats(bytes_count=500, is_inbound=False)
        assert conn.bytes_out == 500
        assert conn.packets_out == 1

    def test_connection_expiry(self):
        conn = self._make_connection()
        # Not expired with 300s timeout
        assert conn.is_expired(timeout=300) is False


# =========================================================================
# ConnectionShard Tests
# =========================================================================

class TestConnectionShard:
    """Tests for individual connection shard operations."""

    def test_put_and_get(self):
        shard = ConnectionShard(max_size=100)
        conn = Connection(
            src_ip="10.0.0.1", src_port=1234,
            dst_ip="10.0.0.2", dst_port=80,
            protocol=6, state=ConnectionState.NEW
        )
        key = conn.get_key()
        shard.put(conn)
        result = shard.get(key)
        assert result is not None
        assert result.src_ip == "10.0.0.1"

    def test_delete_connection(self):
        shard = ConnectionShard(max_size=100)
        conn = Connection(
            src_ip="10.0.0.1", src_port=1234,
            dst_ip="10.0.0.2", dst_port=80,
            protocol=6, state=ConnectionState.NEW
        )
        key = conn.get_key()
        shard.put(conn)
        shard.delete(key)
        assert shard.get(key) is None

    def test_shard_stats(self):
        shard = ConnectionShard(max_size=100)
        stats = shard.get_stats()
        assert stats["connections"] == 0


# =========================================================================
# ConnectionTable Tests
# =========================================================================

class TestConnectionTable:
    """Tests for the sharded high-performance connection table."""

    def test_table_creation(self):
        table = ConnectionTable(max_connections=1000, num_shards=16)
        assert len(table) == 0

    def test_track_and_lookup(self):
        table = ConnectionTable(max_connections=1000, num_shards=16)
        conn = Connection(
            src_ip="192.168.1.100", src_port=54321,
            dst_ip="8.8.8.8", dst_port=53,
            protocol=17, state=ConnectionState.NEW
        )
        table.put(conn)
        result = table.get(
            src_ip="192.168.1.100", src_port=54321,
            dst_ip="8.8.8.8", dst_port=53,
            protocol=17
        )
        assert result is not None
        assert result.dst_port == 53

    def test_reverse_lookup(self):
        table = ConnectionTable(max_connections=1000, num_shards=16)
        conn = Connection(
            src_ip="192.168.1.100", src_port=54321,
            dst_ip="8.8.8.8", dst_port=53,
            protocol=17, state=ConnectionState.NEW
        )
        table.put(conn)
        # Lookup by reverse direction (response packet)
        result = table.get_reverse(
            src_ip="8.8.8.8", src_port=53,
            dst_ip="192.168.1.100", dst_port=54321,
            protocol=17
        )
        assert result is not None

    def test_table_stats(self):
        table = ConnectionTable(max_connections=1000, num_shards=16)
        stats = table.get_stats()
        assert "num_shards" in stats
        assert "num_shards" in stats

    def test_multiple_connections(self):
        table = ConnectionTable(max_connections=10000, num_shards=16)
        for i in range(100):
            conn = Connection(
                src_ip="192.168.1.100", src_port=50000 + i,
                dst_ip="10.0.0.1", dst_port=80,
                protocol=6, state=ConnectionState.NEW
            )
            table.put(conn)
        assert len(table) == 100
