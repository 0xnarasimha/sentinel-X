# sentinelx/config.py
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sentinelx.models import MAC, EngineConfig

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ModuleNotFoundError:  # pragma: no cover
        tomllib = None  # type: ignore[assignment]


def _parse_simple_toml(text: str) -> dict[str, Any]:
    """Minimal fallback TOML parser for standard section/key-value config files."""
    result: dict[str, Any] = {}
    current_section: dict[str, Any] = result
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            sec = line[1:-1].strip()
            result.setdefault(sec, {})
            current_section = result[sec]
            continue
        if "=" in line:
            k, v = line.split("=", 1)
            key = k.strip()
            val_str = v.strip()
            if val_str.startswith('"') and val_str.endswith('"'):
                current_section[key] = val_str[1:-1]
            elif val_str.startswith("'") and val_str.endswith("'"):
                current_section[key] = val_str[1:-1]
            elif val_str.lower() in ("true", "false"):
                current_section[key] = val_str.lower() == "true"
            elif val_str.startswith("[") and val_str.endswith("]"):
                inner = val_str[1:-1].strip()
                if not inner:
                    current_section[key] = []
                else:
                    items = [
                        item.strip().strip('"').strip("'")
                        for item in inner.split(",")
                        if item.strip()
                    ]
                    current_section[key] = items
            else:
                try:
                    current_section[key] = int(val_str)
                except ValueError:
                    try:
                        current_section[key] = float(val_str)
                    except ValueError:
                        current_section[key] = val_str
    return result


def load_toml_bytes(raw: bytes) -> dict[str, Any]:
    if tomllib is not None:
        return tomllib.loads(raw.decode("utf-8"))
    return _parse_simple_toml(raw.decode("utf-8"))


@dataclass(frozen=True, slots=True)
class CoreConfig:
    iface: str = "auto"
    state_dir: Path = Path("/var/lib/sentinelx")
    pin_mode: str = "always"
    unpin_on_exit: bool = True
    dry_run: bool = False


@dataclass(frozen=True, slots=True)
class DetectConfig:
    heal_cooldown_ms: int = 1000
    incident_idle_s: float = 10.0
    tofu_probes: int = 5
    tofu_window_ms: int = 1000
    tofu_max_retries: int = 3
    queue_max: int = 1000


@dataclass(frozen=True, slots=True)
class WhitelistConfig:
    allowed_macs: tuple[MAC, ...] = ()


@dataclass(frozen=True, slots=True)
class LlmConfig:
    enabled: bool = False
    provider: str = "ollama"
    model: str = ""


@dataclass(frozen=True, slots=True)
class AppConfig:
    core: CoreConfig = field(default_factory=CoreConfig)
    detect: DetectConfig = field(default_factory=DetectConfig)
    whitelist: WhitelistConfig = field(default_factory=WhitelistConfig)
    llm: LlmConfig = field(default_factory=LlmConfig)

    def to_engine_config(self) -> EngineConfig:
        return EngineConfig(
            pin_mode=self.core.pin_mode,
            heal_cooldown_ms=self.detect.heal_cooldown_ms,
            incident_idle_s=float(self.detect.incident_idle_s),
            tofu_probes=self.detect.tofu_probes,
            tofu_window_ms=self.detect.tofu_window_ms,
            tofu_max_retries=self.detect.tofu_max_retries,
            extra_allowed_macs=tuple(m.lower() for m in self.whitelist.allowed_macs),
        )

    @classmethod
    def load(cls, path: Path | str | None = None) -> AppConfig:
        if path is None:
            return cls()
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Config file not found: {p}")
        data = load_toml_bytes(p.read_bytes())
        core_d = data.get("core", {})
        detect_d = data.get("detect", {})
        whitelist_d = data.get("whitelist", {})
        llm_d = data.get("llm", {})

        core = CoreConfig(
            iface=str(core_d.get("iface", "auto")),
            state_dir=Path(str(core_d.get("state_dir", "/var/lib/sentinelx"))),
            pin_mode=str(core_d.get("pin_mode", "always")),
            unpin_on_exit=bool(core_d.get("unpin_on_exit", True)),
            dry_run=bool(core_d.get("dry_run", False)),
        )
        detect = DetectConfig(
            heal_cooldown_ms=int(detect_d.get("heal_cooldown_ms", 1000)),
            incident_idle_s=float(detect_d.get("incident_idle_s", 10.0)),
            tofu_probes=int(detect_d.get("tofu_probes", 5)),
            tofu_window_ms=int(detect_d.get("tofu_window_ms", 1000)),
            tofu_max_retries=int(detect_d.get("tofu_max_retries", 3)),
            queue_max=int(detect_d.get("queue_max", 1000)),
        )
        allowed_raw = whitelist_d.get("allowed_macs", [])
        whitelist = WhitelistConfig(
            allowed_macs=tuple(str(m).strip().lower() for m in allowed_raw if str(m).strip())
        )
        llm = LlmConfig(
            enabled=bool(llm_d.get("enabled", False)),
            provider=str(llm_d.get("provider", "ollama")),
            model=str(llm_d.get("model", "")),
        )
        return cls(core=core, detect=detect, whitelist=whitelist, llm=llm)
