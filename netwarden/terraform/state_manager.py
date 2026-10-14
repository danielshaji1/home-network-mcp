"""
NetWarden State Manager and Rollback Engine.
Creates atomic snapshots prior to applies and manages configuration restores.
"""

from typing import List, Dict, Any, Optional
import json
import shutil
from pathlib import Path
from datetime import datetime, timezone
from netwarden.core.exceptions import RollbackError


class StateManager:
    """Manages snapshots and safe rollback checkpoints for Terraform and device states."""

    def __init__(self, backup_dir: str = "./terraform/backups"):
        self.backup_dir = Path(backup_dir)
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self.history_index: List[Dict[str, Any]] = []

    def create_snapshot(self, description: str, state_data: Dict[str, Any]) -> str:
        """Create a versioned JSON snapshot before applying modifications."""
        now = datetime.now(timezone.utc)
        timestamp = now.strftime("%Y%m%d_%H%M%S")
        snapshot_id = f"snap_{timestamp}"
        snapshot_file = self.backup_dir / f"{snapshot_id}.json"

        payload = {
            "snapshot_id": snapshot_id,
            "timestamp": now.isoformat(),
            "description": description,
            "state": state_data,
        }

        with open(snapshot_file, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, default=str)

        self.history_index.append({
            "snapshot_id": snapshot_id,
            "timestamp": payload["timestamp"],
            "description": description,
            "path": str(snapshot_file),
        })

        return snapshot_id

    def list_snapshots(self) -> List[Dict[str, Any]]:
        """List all available rollback snapshots sorted by newest first."""
        snapshots = []
        for file in sorted(self.backup_dir.glob("snap_*.json"), reverse=True):
            try:
                with open(file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    snapshots.append({
                        "snapshot_id": data.get("snapshot_id"),
                        "timestamp": data.get("timestamp"),
                        "description": data.get("description"),
                        "file": str(file),
                    })
            except Exception:
                continue
        return snapshots

    def get_snapshot(self, snapshot_id: Optional[str] = None) -> Dict[str, Any]:
        """Retrieve a specific snapshot or the latest if omitted."""
        if snapshot_id:
            target = self.backup_dir / f"{snapshot_id}.json"
        else:
            snaps = sorted(self.backup_dir.glob("snap_*.json"), reverse=True)
            if not snaps:
                raise RollbackError("No snapshots available for rollback.")
            target = snaps[0]

        if not target.exists():
            raise RollbackError(f"Snapshot file not found: {target}")

        with open(target, "r", encoding="utf-8") as f:
            return json.load(f)
