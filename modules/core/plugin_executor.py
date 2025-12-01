"""
Multi-core plugin executor for Raspberry Pi Zero 2W.
Executes plugins sequentially or in parallel based on metadata.
"""

import logging
import time
from typing import List

from modules.core.plugin_manager import Plugin

logger = logging.getLogger(__name__)

def _run_plugin_wrapper(plugin_name: str, category: str, job_id: int):
    """
    Wrapper function for running plugin in separate process.
    Must be top-level for pickling.
    """
    try:
        # Re-import plugin in subprocess
        # We need to pass the job object, but job objects might not be picklable or attached to a DB session
        # So we might need to re-fetch the job or pass a simplified job object.
        # For now, let's assume we can't easily pass the full job object across processes without detaching it.
        # This wrapper is a placeholder for true parallel execution which requires careful state management.
        return (plugin_name, False, "Parallel execution not fully implemented yet")
    except Exception as e:
        return (plugin_name, False, str(e))

class PluginExecutor:
    """
    Executes plugins with multi-core support.
    Optimized for Pi Zero 2W (4 cores).
    """
    
    def __init__(self, max_workers: int = 2):
        self.max_workers = max_workers

    def execute_plugins_sequential(self, plugins: List[Plugin], job) -> List[dict]:
        """
        Execute plugins sequentially (one after another).
        
        Args:
            plugins: List of Plugin instances
            job: Job object
            
        Returns:
            List of execution results
        """
        results = []
        logger.info(f"Executing {len(plugins)} plugins SEQUENTIALLY")
        
        for plugin in plugins:
            logger.info(f"🚀 Running: {plugin.category}/{plugin.name}")
            start_time = time.time()
            
            try:
                plugin.run(job)
                elapsed = time.time() - start_time
                
                results.append({
                    'plugin': plugin.name,
                    'category': plugin.category,
                    'status': 'success',
                    'elapsed': elapsed
                })
                logger.info(f"✅ Completed: {plugin.name} ({elapsed:.2f}s)")
                
            except Exception as e:
                elapsed = time.time() - start_time
                results.append({
                    'plugin': plugin.name,
                    'category': plugin.category,
                    'status': 'error',
                    'error': str(e),
                    'elapsed': elapsed
                })
                logger.error(f"❌ Failed: {plugin.name} - {e}")
                
        logger.info(f"Sequential execution completed: {len(results)} plugins")
        return results

    def execute_plugins_smart(self, plugins: List[Plugin], job) -> List[dict]:
        """
        Execute plugins with smart strategy:
        - Parallel-safe plugins run in parallel (TODO)
        - Others run sequentially
        """
        # For now, just run everything sequentially to be safe on the Pi Zero
        return self.execute_plugins_sequential(plugins, job)

# Global plugin executor instance
_plugin_executor: PluginExecutor = None

def get_plugin_executor() -> PluginExecutor:
    """Get global plugin executor instance."""
    global _plugin_executor
    if _plugin_executor is None:
        _plugin_executor = PluginExecutor()
    return _plugin_executor
