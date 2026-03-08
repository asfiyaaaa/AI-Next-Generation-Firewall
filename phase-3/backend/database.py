"""
Database Module - SQLite for persistent storage

Provides database models and operations for:
- Users and authentication
- Roles and permissions
- Devices
- URL blocklists/allowlists
- Content filter settings
- Audit logs
"""

import sqlite3
import hashlib
import json
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
from pathlib import Path
from contextlib import contextmanager

logger = logging.getLogger(__name__)

# Database path
DB_PATH = Path(__file__).parent.parent / "security.db"


@contextmanager
def get_connection():
    """Get database connection with context manager."""
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=30)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def init_database():
    """Initialize database tables."""
    with get_connection() as conn:
        cursor = conn.cursor()
        
        # Users table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                email TEXT,
                display_name TEXT,
                department TEXT DEFAULT '',
                is_active INTEGER DEFAULT 1,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                last_login TEXT
            )
        """)
        
        # Roles table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS roles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                description TEXT,
                permissions TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # User-Role mapping
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_roles (
                user_id INTEGER NOT NULL,
                role_id INTEGER NOT NULL,
                assigned_at TEXT DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (user_id, role_id),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
            )
        """)
        
        # User groups
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS groups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                description TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # User-Group mapping
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_groups (
                user_id INTEGER NOT NULL,
                group_id INTEGER NOT NULL,
                PRIMARY KEY (user_id, group_id),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE
            )
        """)
        
        # Devices table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT UNIQUE NOT NULL,
                device_name TEXT,
                device_type TEXT,
                os_version TEXT,
                registered_by INTEGER,
                registered_at TEXT DEFAULT CURRENT_TIMESTAMP,
                last_seen TEXT,
                is_compliant INTEGER DEFAULT 1,
                fingerprint TEXT,
                FOREIGN KEY (registered_by) REFERENCES users(id)
            )
        """)
        
        # URL blocklist
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS url_blocklist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT UNIQUE NOT NULL,
                reason TEXT,
                added_by INTEGER,
                added_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (added_by) REFERENCES users(id)
            )
        """)
        
        # URL allowlist
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS url_allowlist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT UNIQUE NOT NULL,
                added_by INTEGER,
                added_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (added_by) REFERENCES users(id)
            )
        """)
        
        # Blocked categories
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS blocked_categories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                category TEXT UNIQUE NOT NULL,
                blocked_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Content filter settings
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS content_filter_extensions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                extension TEXT UNIQUE NOT NULL,
                added_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Audit log
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
                user_id INTEGER,
                action TEXT NOT NULL,
                resource TEXT,
                details TEXT,
                ip_address TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        
        # VPN profiles
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vpn_profiles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                profile_id TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                protocol TEXT NOT NULL,
                server_address TEXT,
                port INTEGER,
                created_by INTEGER,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                config TEXT,
                FOREIGN KEY (created_by) REFERENCES users(id)
            )
        """)
        
        # File scan history
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                file_hash TEXT,
                file_size INTEGER,
                prediction TEXT,
                confidence REAL,
                is_malicious INTEGER,
                threat_level TEXT,
                scan_type TEXT DEFAULT 'file',
                scanned_at TEXT DEFAULT CURRENT_TIMESTAMP,
                user_id INTEGER,
                ip_address TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        
        # URL analysis history
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS url_analysis_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                domain TEXT,
                is_blocked INTEGER,
                category TEXT,
                threat_level TEXT,
                reputation_score INTEGER,
                analyzed_at TEXT DEFAULT CURRENT_TIMESTAMP,
                user_id INTEGER,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        
        # Sandbox analysis history
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sandbox_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                file_hash TEXT,
                threat_score INTEGER,
                threat_level TEXT,
                verdict TEXT,
                behaviors TEXT,
                indicators TEXT,
                analyzed_at TEXT DEFAULT CURRENT_TIMESTAMP,
                user_id INTEGER,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        
        conn.commit()
        logger.info(f"Database initialized at {DB_PATH}")


# User operations
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def create_user(username: str, password: str, email: str = "", 
                display_name: str = "", roles: List[str] = None) -> Optional[int]:
    """Create a new user."""
    with get_connection() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT INTO users (username, password_hash, email, display_name)
                VALUES (?, ?, ?, ?)
            """, (username, hash_password(password), email, display_name or username))
            user_id = cursor.lastrowid
            
            # Assign roles
            if roles:
                for role_name in roles:
                    cursor.execute("SELECT id FROM roles WHERE name = ?", (role_name,))
                    role = cursor.fetchone()
                    if role:
                        cursor.execute("INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES (?, ?)",
                                      (user_id, role['id']))
            
            conn.commit()
            logger.info(f"User created: {username}")
            return user_id
        except sqlite3.IntegrityError:
            logger.warning(f"User already exists: {username}")
            return None


def get_user(username: str) -> Optional[Dict[str, Any]]:
    """Get user by username."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        if not user:
            return None
        
        # Get roles
        cursor.execute("""
            SELECT r.name FROM roles r
            JOIN user_roles ur ON r.id = ur.role_id
            WHERE ur.user_id = ?
        """, (user['id'],))
        roles = [row['name'] for row in cursor.fetchall()]
        
        # Get groups
        cursor.execute("""
            SELECT g.name FROM groups g
            JOIN user_groups ug ON g.id = ug.group_id
            WHERE ug.user_id = ?
        """, (user['id'],))
        groups = [row['name'] for row in cursor.fetchall()]
        
        return {
            'id': user['id'],
            'username': user['username'],
            'password_hash': user['password_hash'],
            'email': user['email'],
            'display_name': user['display_name'],
            'department': user['department'],
            'is_active': bool(user['is_active']),
            'created_at': user['created_at'],
            'last_login': user['last_login'],
            'roles': roles,
            'groups': groups
        }


def authenticate_user(username: str, password: str) -> Optional[Dict[str, Any]]:
    """Authenticate user and return user data if successful."""
    user = get_user(username)
    if not user:
        return None
    
    if user['password_hash'] != hash_password(password):
        return None
    
    # Update last login
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET last_login = ? WHERE username = ?",
                      (datetime.utcnow().isoformat(), username))
        conn.commit()
    
    return user


def list_users() -> List[Dict[str, Any]]:
    """List all users."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, email, display_name, is_active, created_at, last_login FROM users")
        users = []
        for row in cursor.fetchall():
            # Get roles for each user
            cursor.execute("""
                SELECT r.name FROM roles r
                JOIN user_roles ur ON r.id = ur.role_id
                WHERE ur.user_id = ?
            """, (row['id'],))
            roles = [r['name'] for r in cursor.fetchall()]
            
            users.append({
                'id': row['id'],
                'username': row['username'],
                'email': row['email'],
                'display_name': row['display_name'],
                'is_active': bool(row['is_active']),
                'roles': roles
            })
        return users


def delete_user(username: str) -> bool:
    """Delete a user."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE username = ?", (username,))
        conn.commit()
        return cursor.rowcount > 0


def update_user(username: str, email: str = None, display_name: str = None, 
                is_active: bool = None) -> bool:
    """Update user details."""
    updates = []
    values = []
    
    if email is not None:
        updates.append("email = ?")
        values.append(email)
    if display_name is not None:
        updates.append("display_name = ?")
        values.append(display_name)
    if is_active is not None:
        updates.append("is_active = ?")
        values.append(1 if is_active else 0)
    
    if not updates:
        return False
    
    values.append(username)
    
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(f"UPDATE users SET {', '.join(updates)} WHERE username = ?", values)
        conn.commit()
        return cursor.rowcount > 0


# Role operations
def create_role(name: str, description: str = "", permissions: List[str] = None) -> Optional[int]:
    """Create a new role."""
    with get_connection() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT INTO roles (name, description, permissions)
                VALUES (?, ?, ?)
            """, (name, description, json.dumps(permissions or [])))
            conn.commit()
            return cursor.lastrowid
        except sqlite3.IntegrityError:
            return None


def get_role(name: str) -> Optional[Dict[str, Any]]:
    """Get role by name."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM roles WHERE name = ?", (name,))
        role = cursor.fetchone()
        if role:
            return {
                'id': role['id'],
                'name': role['name'],
                'description': role['description'],
                'permissions': json.loads(role['permissions'] or '[]')
            }
        return None


def list_roles() -> List[Dict[str, Any]]:
    """List all roles."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM roles")
        return [{
            'id': row['id'],
            'name': row['name'],
            'description': row['description'],
            'permissions': json.loads(row['permissions'] or '[]')
        } for row in cursor.fetchall()]


def delete_role(name: str) -> bool:
    """Delete a role."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM roles WHERE name = ?", (name,))
        conn.commit()
        return cursor.rowcount > 0


def assign_role(username: str, role_name: str) -> bool:
    """Assign a role to a user."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        cursor.execute("SELECT id FROM roles WHERE name = ?", (role_name,))
        role = cursor.fetchone()
        
        if not user or not role:
            return False
        
        try:
            cursor.execute("INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)",
                          (user['id'], role['id']))
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False


def remove_role(username: str, role_name: str) -> bool:
    """Remove a role from a user."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            DELETE FROM user_roles 
            WHERE user_id = (SELECT id FROM users WHERE username = ?)
            AND role_id = (SELECT id FROM roles WHERE name = ?)
        """, (username, role_name))
        conn.commit()
        return cursor.rowcount > 0


# URL filter operations
def add_to_blocklist(domain: str, reason: str = "Manual block") -> bool:
    with get_connection() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO url_blocklist (domain, reason) VALUES (?, ?)",
                          (domain.lower(), reason))
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False


def remove_from_blocklist(domain: str) -> bool:
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM url_blocklist WHERE domain = ?", (domain.lower(),))
        conn.commit()
        return cursor.rowcount > 0


def get_blocklist() -> Dict[str, str]:
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT domain, reason FROM url_blocklist")
        return {row['domain']: row['reason'] for row in cursor.fetchall()}


def add_to_allowlist(domain: str) -> bool:
    with get_connection() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO url_allowlist (domain) VALUES (?)", (domain.lower(),))
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False


def get_allowlist() -> List[str]:
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT domain FROM url_allowlist")
        return [row['domain'] for row in cursor.fetchall()]


# Category blocking
def block_category(category: str) -> bool:
    with get_connection() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO blocked_categories (category) VALUES (?)", (category,))
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False


def unblock_category(category: str) -> bool:
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM blocked_categories WHERE category = ?", (category,))
        conn.commit()
        return cursor.rowcount > 0


def get_blocked_categories() -> List[str]:
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT category FROM blocked_categories")
        return [row['category'] for row in cursor.fetchall()]


# Content filter
def add_blocked_extension(ext: str) -> bool:
    if not ext.startswith('.'):
        ext = '.' + ext
    with get_connection() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO content_filter_extensions (extension) VALUES (?)", (ext.lower(),))
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False


def remove_blocked_extension(ext: str) -> bool:
    if not ext.startswith('.'):
        ext = '.' + ext
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM content_filter_extensions WHERE extension = ?", (ext.lower(),))
        conn.commit()
        return cursor.rowcount > 0


def get_blocked_extensions() -> List[str]:
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT extension FROM content_filter_extensions")
        return [row['extension'] for row in cursor.fetchall()]


# Audit logging
def log_action(user_id: int, action: str, resource: str = None, 
               details: str = None, ip_address: str = None):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO audit_log (user_id, action, resource, details, ip_address)
            VALUES (?, ?, ?, ?, ?)
        """, (user_id, action, resource, details, ip_address))
        conn.commit()


def get_audit_log(limit: int = 100) -> List[Dict[str, Any]]:
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT a.*, u.username 
            FROM audit_log a
            LEFT JOIN users u ON a.user_id = u.id
            ORDER BY a.timestamp DESC
            LIMIT ?
        """, (limit,))
        return [dict(row) for row in cursor.fetchall()]


# Scan history operations
def save_scan_result(filename: str, file_hash: str, file_size: int, prediction: str,
                    confidence: float, is_malicious: bool, threat_level: str = "unknown",
                    scan_type: str = "file", user_id: int = None, ip_address: str = None):
    """Save a file scan result."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO scan_history 
            (filename, file_hash, file_size, prediction, confidence, is_malicious, 
             threat_level, scan_type, user_id, ip_address)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (filename, file_hash, file_size, prediction, confidence, 
              1 if is_malicious else 0, threat_level, scan_type, user_id, ip_address))
        conn.commit()
        return cursor.lastrowid


def get_scan_history(limit: int = 50) -> List[Dict[str, Any]]:
    """Get recent scan history."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM scan_history 
            ORDER BY scanned_at DESC LIMIT ?
        """, (limit,))
        return [dict(row) for row in cursor.fetchall()]


def save_url_analysis(url: str, domain: str, is_blocked: bool, category: str,
                     threat_level: str, reputation_score: int, user_id: int = None):
    """Save a URL analysis result."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO url_analysis_history 
            (url, domain, is_blocked, category, threat_level, reputation_score, user_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (url, domain, 1 if is_blocked else 0, category, threat_level, 
              reputation_score, user_id))
        conn.commit()
        return cursor.lastrowid


def get_url_analysis_history(limit: int = 50) -> List[Dict[str, Any]]:
    """Get recent URL analysis history."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM url_analysis_history 
            ORDER BY analyzed_at DESC LIMIT ?
        """, (limit,))
        return [dict(row) for row in cursor.fetchall()]


def save_sandbox_result(filename: str, file_hash: str, threat_score: int,
                       threat_level: str, verdict: str, behaviors: str = None,
                       indicators: str = None, user_id: int = None):
    """Save a sandbox analysis result."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO sandbox_history 
            (filename, file_hash, threat_score, threat_level, verdict, behaviors, indicators, user_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (filename, file_hash, threat_score, threat_level, verdict, 
              behaviors, indicators, user_id))
        conn.commit()
        return cursor.lastrowid


def get_sandbox_history(limit: int = 50) -> List[Dict[str, Any]]:
    """Get recent sandbox analysis history."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM sandbox_history 
            ORDER BY analyzed_at DESC LIMIT ?
        """, (limit,))
        return [dict(row) for row in cursor.fetchall()]


# Dashboard statistics
def get_dashboard_statistics() -> Dict[str, Any]:
    """Get comprehensive dashboard statistics."""
    with get_connection() as conn:
        cursor = conn.cursor()
        
        # User stats
        cursor.execute("SELECT COUNT(*) as count FROM users")
        total_users = cursor.fetchone()['count']
        
        cursor.execute("SELECT COUNT(*) as count FROM users WHERE is_active = 1")
        active_users = cursor.fetchone()['count']
        
        # Role stats
        cursor.execute("SELECT COUNT(*) as count FROM roles")
        total_roles = cursor.fetchone()['count']
        
        # Scan stats
        cursor.execute("SELECT COUNT(*) as count FROM scan_history")
        total_scans = cursor.fetchone()['count']
        
        cursor.execute("SELECT COUNT(*) as count FROM scan_history WHERE is_malicious = 1")
        malicious_scans = cursor.fetchone()['count']
        
        cursor.execute("""
            SELECT COUNT(*) as count FROM scan_history 
            WHERE scanned_at >= datetime('now', '-24 hours')
        """)
        scans_today = cursor.fetchone()['count']
        
        # URL stats
        cursor.execute("SELECT COUNT(*) as count FROM url_analysis_history")
        total_url_scans = cursor.fetchone()['count']
        
        cursor.execute("SELECT COUNT(*) as count FROM url_analysis_history WHERE is_blocked = 1")
        blocked_urls = cursor.fetchone()['count']
        
        # Blocklist stats
        cursor.execute("SELECT COUNT(*) as count FROM url_blocklist")
        blocklist_size = cursor.fetchone()['count']
        
        cursor.execute("SELECT COUNT(*) as count FROM blocked_categories")
        blocked_categories = cursor.fetchone()['count']
        
        # Content filter stats
        cursor.execute("SELECT COUNT(*) as count FROM content_filter_extensions")
        blocked_extensions = cursor.fetchone()['count']
        
        # Sandbox stats
        cursor.execute("SELECT COUNT(*) as count FROM sandbox_history")
        total_sandbox = cursor.fetchone()['count']
        
        cursor.execute("SELECT COUNT(*) as count FROM sandbox_history WHERE threat_level IN ('critical', 'high')")
        high_threat_sandbox = cursor.fetchone()['count']
        
        # Recent threats
        cursor.execute("""
            SELECT filename, prediction, confidence, scanned_at 
            FROM scan_history WHERE is_malicious = 1
            ORDER BY scanned_at DESC LIMIT 5
        """)
        recent_threats = [dict(row) for row in cursor.fetchall()]
        
        return {
            'users': {
                'total': total_users,
                'active': active_users
            },
            'roles': {
                'total': total_roles
            },
            'scans': {
                'total': total_scans,
                'malicious': malicious_scans,
                'today': scans_today,
                'detection_rate': round(malicious_scans / total_scans * 100, 1) if total_scans > 0 else 0
            },
            'url_analysis': {
                'total': total_url_scans,
                'blocked': blocked_urls
            },
            'blocklist': {
                'domains': blocklist_size,
                'categories': blocked_categories
            },
            'content_filter': {
                'blocked_extensions': blocked_extensions
            },
            'sandbox': {
                'total': total_sandbox,
                'high_threat': high_threat_sandbox
            },
            'recent_threats': recent_threats
        }


def seed_blocked_domains():
    """Seed database with 5000+ known blocked domains by category."""
    try:
        from .domain_database import DOMAIN_DATABASE, get_domain_count
    except ImportError:
        try:
            import domain_database
            DOMAIN_DATABASE = domain_database.DOMAIN_DATABASE
            get_domain_count = domain_database.get_domain_count
        except ImportError:
            logger.warning("domain_database module not found, skipping seed")
            return 0
    
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            
            # Check if table exists
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='url_blocklist'")
            if not cursor.fetchone():
                logger.warning("url_blocklist table does not exist yet, skipping seed")
                return 0
            
            # Add blocked domains from comprehensive database
            inserted = 0
            for category, domains in DOMAIN_DATABASE.items():
                for domain in domains:
                    try:
                        cursor.execute(
                            "INSERT OR IGNORE INTO url_blocklist (domain, reason) VALUES (?, ?)",
                            (domain.lower(), f"Category: {category}")
                        )
                        if cursor.rowcount > 0:
                            inserted += 1
                    except Exception as e:
                        logger.debug(f"Failed to insert domain {domain}: {e}")
                        pass
            
            conn.commit()
            
            # Count total
            cursor.execute("SELECT COUNT(*) as count FROM url_blocklist")
            total = cursor.fetchone()['count']
            logger.info(f"Domain database: {inserted} new domains added, {total} total blocked domains")
            
            return total
    except Exception as e:
        logger.warning(f"Error seeding blocked domains: {e}")
        return 0


def get_blocked_domains_by_category() -> Dict[str, List[str]]:
    """Get all blocked domains grouped by category."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT domain, reason FROM url_blocklist ORDER BY reason, domain")
        rows = cursor.fetchall()
        
        result = {}
        for row in rows:
            category = row['reason'].replace('Category: ', '') if row['reason'] else 'uncategorized'
            if category not in result:
                result[category] = []
            result[category].append(row['domain'])
        
        return result


def get_blocklist_stats() -> Dict:
    """Get blocklist statistics."""
    with get_connection() as conn:
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) as count FROM url_blocklist")
        total = cursor.fetchone()['count']
        
        cursor.execute("""
            SELECT reason, COUNT(*) as count 
            FROM url_blocklist 
            GROUP BY reason 
            ORDER BY count DESC
        """)
        by_category = {row['reason']: row['count'] for row in cursor.fetchall()}
        
        return {
            'total_domains': total,
            'by_category': by_category
        }


# Stream analysis operations (for NGFW integration)
def init_stream_analysis_table():
    """Initialize stream analysis table."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS stream_analysis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                stream_id TEXT NOT NULL,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                data_size INTEGER,
                verdict TEXT,
                threats_found INTEGER DEFAULT 0,
                analyses TEXT,
                analyzed_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()


def log_stream_analysis(stream_id: str, src_ip: str = None, dst_ip: str = None,
                        src_port: int = None, dst_port: int = None,
                        data_size: int = 0, verdict: str = "allow",
                        threats_found: int = 0, analyses: List[Dict] = None):
    """Log a stream analysis result from NGFW."""
    # Ensure table exists
    init_stream_analysis_table()
    
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO stream_analysis 
            (stream_id, src_ip, dst_ip, src_port, dst_port, data_size, verdict, threats_found, analyses)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (stream_id, src_ip, dst_ip, src_port, dst_port, data_size, 
              verdict, threats_found, json.dumps(analyses or [])))
        conn.commit()
        return cursor.lastrowid


def get_stream_analysis_stats() -> Dict[str, Any]:
    """Get stream analysis statistics."""
    init_stream_analysis_table()
    
    with get_connection() as conn:
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) as count FROM stream_analysis")
        total = cursor.fetchone()['count']
        
        cursor.execute("SELECT COUNT(*) as count FROM stream_analysis WHERE threats_found > 0")
        threats = cursor.fetchone()['count']
        
        cursor.execute("SELECT SUM(data_size) as total FROM stream_analysis")
        row = cursor.fetchone()
        total_bytes = row['total'] if row['total'] else 0
        
        cursor.execute("""
            SELECT COUNT(*) as count FROM stream_analysis 
            WHERE analyzed_at >= datetime('now', '-24 hours')
        """)
        today = cursor.fetchone()['count']
        
        return {
            'total_streams': total,
            'threats_detected': threats,
            'total_bytes_analyzed': total_bytes,
            'streams_today': today
        }


def get_stream_analysis_history(limit: int = 50) -> List[Dict[str, Any]]:
    """Get recent stream analysis history."""
    init_stream_analysis_table()
    
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM stream_analysis 
            ORDER BY id DESC LIMIT ?
        """, (limit,))
        return [dict(row) for row in cursor.fetchall()]



def get_live_traffic_history(minutes: int = 30) -> List[Dict[str, Any]]:
    """Get real-time traffic history (packets and threats) grouped by minute."""
    init_stream_analysis_table()
    
    with get_connection() as conn:
        cursor = conn.cursor()
        # Group by minute using SQLite strftime
        cursor.execute("""
            SELECT 
                strftime('%H:%M', analyzed_at) as time,
                (SUM(data_size) / 64) + 5 as packets,
                SUM(threats_found) as threats
            FROM stream_analysis
            WHERE analyzed_at >= datetime('now', ?)
            GROUP BY time
            ORDER BY analyzed_at ASC
        """, (f'-{minutes} minutes',))
        
        return [dict(row) for row in cursor.fetchall()]



def get_traffic_history(hours: int = 24) -> List[Dict[str, Any]]:
    """Get traffic history (packets and threats) grouped by hour."""
    init_stream_analysis_table()
    
    with get_connection() as conn:
        cursor = conn.cursor()
        # Group by hour using SQLite strftime
        cursor.execute("""
            SELECT 
                strftime('%H:00', analyzed_at) as time,
                SUM(data_size) / 1024 as packets,
                SUM(threats_found) as threats
            FROM stream_analysis
            WHERE analyzed_at >= datetime('now', ?)
            GROUP BY time
            ORDER BY analyzed_at ASC
        """, (f'-{hours} hours',))
        
        return [dict(row) for row in cursor.fetchall()]

# Initialize on import
init_database()
seed_blocked_domains()

