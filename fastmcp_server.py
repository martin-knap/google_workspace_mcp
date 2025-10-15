# ruff: noqa
"""
FastMCP CLI entrypoint for Google Workspace MCP Server.
This file imports all tool modules to register them with the server instance.
Includes full initialization bootstrap that main.py provides.
"""
import logging
import os
import sys
from dotenv import load_dotenv

from auth.oauth_config import reload_oauth_config, is_stateless_mode
from core.log_formatter import EnhancedLogFormatter, configure_file_logging
from core.utils import check_credentials_directory_permissions
from core.server import server, set_transport_mode, configure_server_for_http
from core.tool_registry import set_enabled_tools as set_enabled_tool_names, wrap_server_tool_method, filter_server_tools
from auth.scopes import set_enabled_tools

# Load environment variables
dotenv_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
load_dotenv(dotenv_path=dotenv_path)

# Suppress googleapiclient discovery cache warning
logging.getLogger('googleapiclient.discovery_cache').setLevel(logging.ERROR)

# Reload OAuth configuration after env vars loaded
reload_oauth_config()

# Configure basic logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Configure file logging based on stateless mode
configure_file_logging()

def configure_safe_logging():
    """Configure safe Unicode handling for logging."""
    class SafeEnhancedFormatter(EnhancedLogFormatter):
        """Enhanced ASCII formatter with additional Windows safety."""
        def format(self, record):
            try:
                return super().format(record)
            except UnicodeEncodeError:
                # Fallback to ASCII-safe formatting
                service_prefix = self._get_ascii_prefix(record.name, record.levelname)
                safe_msg = str(record.getMessage()).encode('ascii', errors='replace').decode('ascii')
                return f"{service_prefix} {safe_msg}"

    # Replace all console handlers' formatters with safe enhanced ones
    for handler in logging.root.handlers:
        # Only apply to console/stream handlers, keep file handlers as-is
        if isinstance(handler, logging.StreamHandler) and handler.stream.name in ['<stderr>', '<stdout>']:
            safe_formatter = SafeEnhancedFormatter(use_colors=True)
            handler.setFormatter(safe_formatter)

# Configure safe logging
configure_safe_logging()


def parse_enabled_services_from_env():
    """
    Parse ENABLED_SERVICES environment variable into a list of service names.

    Format: Comma-separated list (case-insensitive)
    Example: "Drive,Calendar,Docs,Sheets" or "gmail, drive, calendar"

    Returns:
        List of lowercase service names, or None if not set
    """
    enabled_services = os.getenv('ENABLED_SERVICES')
    if not enabled_services:
        return None

    # Parse comma-separated values, strip whitespace, convert to lowercase
    services = [s.strip().lower() for s in enabled_services.split(',') if s.strip()]

    # Valid service names
    valid_services = {'gmail', 'drive', 'calendar', 'docs', 'sheets', 'chat', 'forms', 'slides', 'tasks', 'search'}

    # Filter to only valid services and warn about invalid ones
    valid_parsed = []
    invalid = []
    for service in services:
        if service in valid_services:
            valid_parsed.append(service)
        else:
            invalid.append(service)

    if invalid:
        logger.warning(f"Ignoring invalid services from ENABLED_SERVICES: {', '.join(invalid)}")

    if valid_parsed:
        logger.info(f"Loaded services from ENABLED_SERVICES: {', '.join(valid_parsed)}")
        return valid_parsed

    return None


# Check credentials directory permissions (skip in stateless mode)
if not is_stateless_mode():
    try:
        logger.info("Checking credentials directory permissions...")
        check_credentials_directory_permissions()
        logger.info("Credentials directory permissions verified")
    except (PermissionError, OSError) as e:
        logger.error(f"Credentials directory permission check failed: {e}")
        logger.error("   Please ensure the service has write permissions to create/access the credentials directory")
        sys.exit(1)
else:
    logger.info("🔍 Skipping credentials directory check (stateless mode)")

# Set transport mode for HTTP (FastMCP CLI defaults to streamable-http)
set_transport_mode('streamable-http')

# Parse ENABLED_SERVICES environment variable
env_services = parse_enabled_services_from_env()

# Determine which services to import
if env_services is not None:
    services_to_import = env_services
    logger.info(f"Importing services from ENABLED_SERVICES: {', '.join(services_to_import)}")
else:
    # Default: import all services
    services_to_import = ['gmail', 'drive', 'calendar', 'docs', 'sheets', 'chat', 'forms', 'slides', 'tasks', 'search']
    logger.info("Importing all services (no ENABLED_SERVICES set)")

# Service name to module mapping
service_modules = {
    'gmail': 'gmail.gmail_tools',
    'drive': 'gdrive.drive_tools',
    'calendar': 'gcalendar.calendar_tools',
    'docs': 'gdocs.docs_tools',
    'sheets': 'gsheets.sheets_tools',
    'chat': 'gchat.chat_tools',
    'forms': 'gforms.forms_tools',
    'slides': 'gslides.slides_tools',
    'tasks': 'gtasks.tasks_tools',
    'search': 'gsearch.search_tools'
}

# Import selected tool modules to register their @server.tool() decorators
for service in services_to_import:
    if service in service_modules:
        try:
            __import__(service_modules[service])
            logger.info(f"Loaded service module: {service}")
        except ImportError as e:
            logger.error(f"Failed to import {service}: {e}")

# Configure tool registration
wrap_server_tool_method(server)

# Enable selected services for scope management
set_enabled_tools(list(services_to_import))
set_enabled_tool_names(None)  # Don't filter individual tools - enable all tools for selected services

# Filter tools based on configuration
filter_server_tools(server)

# Configure authentication after scopes are known
configure_server_for_http()

# Export server instance for FastMCP CLI (looks for 'mcp', 'server', or 'app')
mcp = server
app = server
