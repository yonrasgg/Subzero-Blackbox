"""
Plugin Manager for Subzero-Blackbox.

Handles dynamic discovery, loading, and management of plugins in:
- modules/audits/
- modules/attacks/
"""

import importlib
import logging
import yaml
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Any, Set

logger = logging.getLogger(__name__)

CONFIG_PATH = Path(__file__).resolve().parent.parent.parent / "config" / "config.yaml"

@dataclass
class PluginMetadata:
    """Metadata for a plugin."""
    name: str
    category: str
    description: str = ""
    version: str = "1.0.0"
    author: str = "Unknown"
    can_run_parallel: bool = False
    required_profile: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "category": self.category,
            "description": self.description,
            "version": self.version,
            "author": self.author,
            "can_run_parallel": self.can_run_parallel,
            "required_profile": self.required_profile
        }

@dataclass
class Plugin:
    """Represents a loaded plugin."""
    name: str
    category: str
    module: Any
    metadata: PluginMetadata
    enabled: bool = True
    
    def run(self, job: Any) -> None:
        """Execute plugin's run() function."""
        if hasattr(self.module, 'run'):
            self.module.run(job)
        else:
            raise AttributeError(f"Plugin {self.name} has no run() function")

class PluginManager:
    """
    Manages dynamic plugin discovery, loading, and execution.
    
    Features:
    - Dynamic plugin discovery in 'audits' and 'attacks' folders
    - Enable/disable plugins via toggles
    - Metadata extraction
    """
    
    def __init__(self, base_dir: Path):
        self.base_dir = base_dir
        self.plugins: Dict[str, Dict[str, Plugin]] = {
            'audits': {},
            'attacks': {}
        }
        self.enabled_plugins: Set[str] = set()
        self._load_enabled_state()
        logger.info(f"PluginManager initialized at {base_dir}")

    def _load_enabled_state(self):
        """Load enabled plugins from config.yaml."""
        if not CONFIG_PATH.is_file():
            return
        try:
            data = yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8")) or {}
            enabled_list = data.get("enabled_plugins", [])
            self.enabled_plugins = set(enabled_list)
        except Exception as e:
            logger.error(f"Failed to load enabled plugins from config: {e}")

    def _save_enabled_state(self):
        """Save enabled plugins to config.yaml."""
        if not CONFIG_PATH.is_file():
            return
        try:
            data = yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8")) or {}
            data["enabled_plugins"] = list(self.enabled_plugins)
            with open(CONFIG_PATH, 'w') as f:
                yaml.dump(data, f)
        except Exception as e:
            logger.error(f"Failed to save enabled plugins to config: {e}")

    def discover_plugins(self) -> Dict[str, List[str]]:
        """
        Discover plugins in audits and attacks directories.
        
        Returns:
            Dict with plugin names by category
        """
        discovered = {'audits': [], 'attacks': []}
        logger.info("Discovering plugins...")
        
        for category in self.plugins.keys():
            plugin_dir = self.base_dir / category
            
            if not plugin_dir.exists():
                logger.warning(f"⚠️ Plugin directory not found: {plugin_dir}")
                continue
                
            # Scan for .py files
            for plugin_file in sorted(plugin_dir.glob("*.py")):
                if plugin_file.name.startswith("__"):
                    continue
                    
                plugin_name = plugin_file.stem
                module_path = f"modules.{category}.{plugin_name}"
                
                try:
                    # Import module
                    module = importlib.import_module(module_path)
                    importlib.reload(module)  # Ensure fresh load
                    
                    # Check for run() function
                    if not hasattr(module, 'run'):
                        logger.warning(f"⚠️ Plugin {plugin_name} missing run() function")
                        continue
                        
                    # Extract metadata
                    metadata = self._extract_metadata(module, category, plugin_name)
                    
                    # Create plugin instance
                    plugin = Plugin(plugin_name, category, module, metadata)
                    self.plugins[category][plugin_name] = plugin
                    discovered[category].append(plugin_name)
                    
                    # Check if enabled in config, otherwise default to enabled
                    plugin_id = f"{category}/{plugin_name}"
                    if plugin_id in self.enabled_plugins:
                        plugin.enabled = True
                    else:
                        # If not in config (first run), enable by default and save
                        plugin.enabled = True
                        self.enabled_plugins.add(plugin_id)
                        self._save_enabled_state()
                    
                    logger.info(f"✅ Discovered: {category}/{plugin_name}")
                    
                except Exception as e:
                    logger.error(f"❌ Error loading plugin {plugin_name}: {e}")
                    
        logger.info(f"Total plugins discovered: {sum(len(p) for p in discovered.values())}")
        return discovered

    def _extract_metadata(self, module, category: str, plugin_name: str) -> PluginMetadata:
        """Extract metadata from module docstring or variables."""
        description = module.__doc__.strip().split('\n')[0] if module.__doc__ else "No description"
        
        return PluginMetadata(
            name=plugin_name,
            category=category,
            description=description,
            version=getattr(module, '__version__', "1.0.0"),
            author=getattr(module, '__author__', "Unknown"),
            can_run_parallel=getattr(module, 'CAN_RUN_PARALLEL', False),
            required_profile=getattr(module, 'REQUIRED_PROFILE', None)
        )

    def enable_plugin(self, category: str, plugin_name: str) -> bool:
        """Enable a plugin."""
        if category not in self.plugins:
            return False
            
        if plugin_name not in self.plugins[category]:
            logger.error(f"Plugin not found: {category}/{plugin_name}")
            return False
            
        self.plugins[category][plugin_name].enabled = True
        self.enabled_plugins.add(f"{category}/{plugin_name}")
        self._save_enabled_state()
        logger.info(f"✅ Enabled: {category}/{plugin_name}")
        return True

    def disable_plugin(self, category: str, plugin_name: str) -> bool:
        """Disable a plugin."""
        if category not in self.plugins:
            return False
            
        if plugin_name not in self.plugins[category]:
            return False
            
        self.plugins[category][plugin_name].enabled = False
        self.enabled_plugins.discard(f"{category}/{plugin_name}")
        self._save_enabled_state()
        logger.info(f"⚠️ Disabled: {category}/{plugin_name}")
        return True

    def get_enabled_plugins(self, category: str = None) -> List[Plugin]:
        """
        Get list of enabled plugins.
        
        Args:
            category: Optional category filter
            
        Returns:
            List of enabled Plugin objects
        """
        enabled = []
        categories = [category] if category else self.plugins.keys()
        
        for cat in categories:
            if cat in self.plugins:
                for plugin in self.plugins[cat].values():
                    if plugin.enabled:
                        enabled.append(plugin)
                        
        return enabled

    def get_plugin_info(self, category: str = None) -> Dict[str, Any]:
        """
        Get information about all plugins.
        
        Returns:
            Dict with plugin information
        """
        info = {}
        categories = [category] if category else self.plugins.keys()
        
        for cat in categories:
            if cat in self.plugins:
                info[cat] = {}
                for name, plugin in self.plugins[cat].items():
                    info[cat][name] = {
                        'enabled': plugin.enabled,
                        'metadata': plugin.metadata.to_dict()
                    }
        return info

# Global plugin manager instance
_plugin_manager: Optional[PluginManager] = None

def get_plugin_manager() -> PluginManager:
    """Get global plugin manager instance."""
    global _plugin_manager
    if _plugin_manager is None:
        base_dir = Path(__file__).resolve().parent.parent
        _plugin_manager = PluginManager(base_dir)
        _plugin_manager.discover_plugins()
    return _plugin_manager
