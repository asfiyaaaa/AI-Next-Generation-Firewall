"""
Identity Management Module - LDAP/Active Directory Integration

Provides user authentication, session management, and role-based access control.
Supports LDAP and Active Directory backends with SQLite database storage.
"""

import os
import secrets
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict, field

# Database
from . import database as db

# JWT handling
try:
    from jose import JWTError, jwt
except ImportError:
    jwt = None
    JWTError = Exception

# LDAP
try:
    from ldap3 import Server, Connection, ALL, SIMPLE
except ImportError:
    Server = None
    Connection = None

logger = logging.getLogger(__name__)


@dataclass
class User:
    """User model."""
    username: str
    email: str
    display_name: str
    groups: List[str] = field(default_factory=list)
    roles: List[str] = field(default_factory=list)
    department: str = ""
    is_active: bool = True
    last_login: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())


@dataclass
class Session:
    """User session model."""
    session_id: str
    user: User
    device_id: Optional[str]
    created_at: str
    expires_at: str
    ip_address: str
    user_agent: str
    is_active: bool = True


class Role:
    """Role definitions."""
    ADMIN = "admin"
    SECURITY_ADMIN = "security_admin"
    ANALYST = "analyst"
    USER = "user"
    GUEST = "guest"


class Permission:
    """Permission definitions."""
    VIEW_DASHBOARD = "view_dashboard"
    ANALYZE_FILES = "analyze_files"
    MANAGE_BLOCKLIST = "manage_blocklist"
    MANAGE_USERS = "manage_users"
    MANAGE_POLICIES = "manage_policies"
    VIEW_LOGS = "view_logs"
    EXPORT_REPORTS = "export_reports"
    CONFIGURE_VPN = "configure_vpn"
    MANAGE_DEVICES = "manage_devices"
    ANALYZE_PHISHING = "analyze_phishing"


# Role-Permission mapping
ROLE_PERMISSIONS = {
    Role.ADMIN: [
        Permission.VIEW_DASHBOARD, Permission.ANALYZE_FILES, Permission.MANAGE_BLOCKLIST,
        Permission.MANAGE_USERS, Permission.MANAGE_POLICIES, Permission.VIEW_LOGS,
        Permission.EXPORT_REPORTS, Permission.CONFIGURE_VPN, Permission.MANAGE_DEVICES,
        Permission.ANALYZE_PHISHING
    ],
    Role.SECURITY_ADMIN: [
        Permission.VIEW_DASHBOARD, Permission.ANALYZE_FILES, Permission.MANAGE_BLOCKLIST,
        Permission.MANAGE_POLICIES, Permission.VIEW_LOGS, Permission.EXPORT_REPORTS,
        Permission.CONFIGURE_VPN, Permission.MANAGE_DEVICES, Permission.ANALYZE_PHISHING
    ],
    Role.ANALYST: [
        Permission.VIEW_DASHBOARD, Permission.ANALYZE_FILES, Permission.MANAGE_BLOCKLIST,
        Permission.VIEW_LOGS, Permission.EXPORT_REPORTS, Permission.ANALYZE_PHISHING
    ],
    Role.USER: [
        Permission.VIEW_DASHBOARD, Permission.VIEW_LOGS
    ],
    Role.GUEST: [
        Permission.VIEW_DASHBOARD
    ]
}


class IdentityManager:
    """
    Identity management for user authentication and authorization.
    Uses SQLite database for persistent storage.
    """
    
    def __init__(
        self,
        ldap_server: str = "",
        ldap_base_dn: str = "",
        secret_key: str = "your-secret-key-change-in-production",
        jwt_expiration_hours: int = 24
    ):
        self.ldap_server = ldap_server
        self.ldap_base_dn = ldap_base_dn
        self.secret_key = secret_key
        self.jwt_expiration_hours = jwt_expiration_hours
        
        # Session storage (in-memory, could also use database)
        self.sessions: Dict[str, Session] = {}
        
        # Initialize default roles in database
        self._init_default_roles()
    
    def _init_default_roles(self):
        """Initialize default roles in database."""
        default_roles = [
            (Role.ADMIN, "Administrator with full access", list(ROLE_PERMISSIONS[Role.ADMIN])),
            (Role.SECURITY_ADMIN, "Security administrator", list(ROLE_PERMISSIONS[Role.SECURITY_ADMIN])),
            (Role.ANALYST, "Security analyst", list(ROLE_PERMISSIONS[Role.ANALYST])),
            (Role.USER, "Standard user", list(ROLE_PERMISSIONS[Role.USER])),
            (Role.GUEST, "Guest user", list(ROLE_PERMISSIONS[Role.GUEST]))
        ]
        
        for name, description, permissions in default_roles:
            if not db.get_role(name):
                db.create_role(name, description, permissions)
    
    def create_user(self, username: str, password: str, email: str,
                   display_name: str, roles: List[str] = None, groups: List[str] = None) -> Optional[User]:
        """Create a new user in the database."""
        user_id = db.create_user(username, password, email, display_name, roles)
        
        if not user_id:
            raise ValueError(f"User {username} already exists")
        
        return User(
            username=username,
            email=email,
            display_name=display_name,
            roles=roles or [Role.USER],
            groups=groups or []
        )
    
    def delete_user(self, username: str) -> bool:
        """Delete a user from the database."""
        return db.delete_user(username)
    
    def authenticate_local(self, username: str, password: str) -> Optional[User]:
        """Authenticate using database."""
        user_data = db.authenticate_user(username, password)
        
        if not user_data:
            return None
        
        return User(
            username=user_data['username'],
            email=user_data['email'] or "",
            display_name=user_data['display_name'] or username,
            groups=user_data.get('groups', []),
            roles=user_data.get('roles', [Role.USER]),
            is_active=user_data['is_active'],
            last_login=user_data['last_login']
        )
    
    def authenticate_ldap(self, username: str, password: str) -> Optional[User]:
        """Authenticate using LDAP/Active Directory."""
        if not Server or not self.ldap_server:
            logger.warning("LDAP not configured, falling back to local auth")
            return self.authenticate_local(username, password)
        
        try:
            server = Server(self.ldap_server, get_info=ALL)
            user_dn = f"cn={username},{self.ldap_base_dn}"
            
            conn = Connection(server, user=user_dn, password=password, authentication=SIMPLE)
            
            if not conn.bind():
                logger.info(f"LDAP authentication failed for {username}")
                return None
            
            conn.search(self.ldap_base_dn, f"(cn={username})",
                       attributes=['cn', 'mail', 'displayName', 'memberOf', 'department'])
            
            if not conn.entries:
                conn.unbind()
                return None
            
            entry = conn.entries[0]
            
            groups = []
            if hasattr(entry, 'memberOf'):
                for group_dn in entry.memberOf.values:
                    if 'CN=' in group_dn:
                        group_name = group_dn.split(',')[0].replace('CN=', '')
                        groups.append(group_name)
            
            user = User(
                username=str(entry.cn),
                email=str(entry.mail) if hasattr(entry, 'mail') else "",
                display_name=str(entry.displayName) if hasattr(entry, 'displayName') else username,
                groups=groups,
                roles=self._map_groups_to_roles(groups),
                department=str(entry.department) if hasattr(entry, 'department') else "",
                last_login=datetime.utcnow().isoformat()
            )
            
            conn.unbind()
            return user
            
        except Exception as e:
            logger.error(f"LDAP authentication error: {e}")
            return None
    
    def _map_groups_to_roles(self, groups: List[str]) -> List[str]:
        """Map LDAP groups to application roles."""
        roles = []
        group_role_mapping = {
            "Domain Admins": Role.ADMIN,
            "Administrators": Role.ADMIN,
            "Security Admins": Role.SECURITY_ADMIN,
            "Security Team": Role.ANALYST,
            "Domain Users": Role.USER
        }
        
        for group in groups:
            if group in group_role_mapping:
                role = group_role_mapping[group]
                if role not in roles:
                    roles.append(role)
        
        if not roles:
            roles.append(Role.USER)
        
        return roles
    
    def authenticate(self, username: str, password: str, use_ldap: bool = False) -> Optional[User]:
        """Authenticate a user."""
        if use_ldap and self.ldap_server:
            return self.authenticate_ldap(username, password)
        return self.authenticate_local(username, password)
    
    def create_session(self, user: User, ip_address: str, user_agent: str,
                      device_id: Optional[str] = None) -> Session:
        """Create a new session for authenticated user."""
        session_id = secrets.token_urlsafe(32)
        now = datetime.utcnow()
        expires = now + timedelta(hours=self.jwt_expiration_hours)
        
        session = Session(
            session_id=session_id,
            user=user,
            device_id=device_id,
            created_at=now.isoformat(),
            expires_at=expires.isoformat(),
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        self.sessions[session_id] = session
        return session
    
    def create_token(self, user: User, session_id: str) -> str:
        """Create a JWT token for a user."""
        if not jwt:
            return session_id
        
        expires = datetime.utcnow() + timedelta(hours=self.jwt_expiration_hours)
        
        payload = {
            "sub": user.username,
            "email": user.email,
            "roles": user.roles,
            "session_id": session_id,
            "exp": expires
        }
        
        return jwt.encode(payload, self.secret_key, algorithm="HS256")
    
    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify a JWT token."""
        if not jwt:
            session = self.sessions.get(token)
            if session and session.is_active:
                return {
                    "sub": session.user.username,
                    "roles": session.user.roles,
                    "session_id": session.session_id
                }
            return None
        
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=["HS256"])
            session = self.sessions.get(payload.get("session_id"))
            if not session or not session.is_active:
                return None
            return payload
        except JWTError:
            return None
    
    def invalidate_session(self, session_id: str):
        """Invalidate a session."""
        if session_id in self.sessions:
            self.sessions[session_id].is_active = False
    
    def check_permission(self, user: User, permission: str) -> bool:
        """Check if user has a specific permission."""
        for role in user.roles:
            if role in ROLE_PERMISSIONS:
                if permission in ROLE_PERMISSIONS[role]:
                    return True
        return False
    
    def get_user_permissions(self, user: User) -> List[str]:
        """Get all permissions for a user."""
        permissions = set()
        for role in user.roles:
            if role in ROLE_PERMISSIONS:
                permissions.update(ROLE_PERMISSIONS[role])
        return list(permissions)
    
    @property
    def local_users(self) -> Dict[str, Dict[str, Any]]:
        """Get all users from database (for compatibility)."""
        users = db.list_users()
        return {u['username']: u for u in users}


# Global instance
identity_manager = IdentityManager()


def authenticate_user(username: str, password: str, use_ldap: bool = False, 
                      ip_address: str = "127.0.0.1", user_agent: str = "Unknown") -> Optional[Dict[str, Any]]:
    """Main function to authenticate a user."""
    user = identity_manager.authenticate(username, password, use_ldap)
    
    if not user:
        return None
    
    session = identity_manager.create_session(
        user=user,
        ip_address=ip_address,
        user_agent=user_agent
    )
    
    token = identity_manager.create_token(user, session.session_id)
    
    # Log the action
    try:
        user_data = db.get_user(username)
        if user_data:
            db.log_action(user_data['id'], "login", "auth", f"User logged in")
    except Exception as e:
        logger.warning(f"Failed to log login action: {e}")
    
    return {
        "user": asdict(user),
        "token": token,
        "session_id": session.session_id,
        "expires_at": session.expires_at,
        "permissions": identity_manager.get_user_permissions(user)
    }


def verify_session(token: str) -> Optional[Dict[str, Any]]:
    """Verify a session token and return user info."""
    payload = identity_manager.verify_token(token)
    if not payload:
        return None
    
    session = identity_manager.sessions.get(payload.get("session_id"))
    if not session:
        return None
    
    return {
        "user": asdict(session.user),
        "session_id": session.session_id,
        "permissions": identity_manager.get_user_permissions(session.user)
    }
