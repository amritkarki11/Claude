"""One interface to three brains, routed by job. Redacts before cloud calls."""
import os
import pathlib
import yaml
from litellm import completion
from .redact import redact

_CFG = yaml.safe_load((pathlib.Path(__file__).parent.parent / "config.yaml").read_text())
_MODELS, _ROUTING = _CFG["models"], _CFG["routing"]
_REDACT = _CFG["privacy"]["redact_before_cloud"]


def ask(job: str, prompt: str, system: str = "", **kw) -> str:
    if job not in _ROUTING:
        raise ValueError(f"Unknown job {job!r}; add it to routing in config.yaml")
    tier = _ROUTING[job]
    is_local = tier == "local"
    text = prompt if (is_local or not _REDACT) else redact(prompt)
    msgs = ([{"role": "system", "content": system}] if system else []) \
        + [{"role": "user", "content": text}]
    extra = {"api_base": os.getenv("OLLAMA_API_BASE", "http://localhost:11434")} if is_local else {}
    resp = completion(model=_MODELS[tier], messages=msgs, **extra, **kw)
    return resp["choices"][0]["message"]["content"]
