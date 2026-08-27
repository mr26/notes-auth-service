"""LocalFile operator.

Watches LocalFile custom resources and reconciles the filesystem to match them:
a LocalFile exists -> the file exists; the LocalFile is deleted -> the file is gone.

The admission half of this lab (timestamp mutation + filename validation) is done
by Kyverno before these handlers ever run. See ../policies/.
"""

import datetime
import os
import pathlib

import kopf

BASE_DIR = pathlib.Path(os.getenv("LOCALFILE_DIR", "/tmp/localfiles"))
TIMESTAMP_ANNOTATION = "mehdi.dev/created-at"


def _target(spec) -> pathlib.Path:
    return BASE_DIR / spec["filename"]


@kopf.on.create("mehdi.dev", "v1alpha1", "localfiles")
@kopf.on.update("mehdi.dev", "v1alpha1", "localfiles")
def reconcile(spec, meta, name, patch, logger, **_):
    """Write the file described by the resource, then report back in .status."""
    target = _target(spec)

    # Set by the Kyverno mutating policy at admission time. If this shows
    # "<not mutated>", the mutating webhook never fired.
    stamped = meta.get("annotations", {}).get(TIMESTAMP_ANNOTATION, "<not mutated>")

    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        f"# LocalFile: {name}\n"
        f"# admission-stamped-at: {stamped}\n"
        f"{spec.get('content', '')}\n"
    )

    patch.status["path"] = str(target)
    patch.status["writtenAt"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    logger.info("wrote %s", target)


@kopf.on.delete("mehdi.dev", "v1alpha1", "localfiles")
def cleanup(spec, logger, **_):
    """Remove the file when its resource is deleted."""
    target = _target(spec)
    if target.exists():
        target.unlink()
        logger.info("deleted %s", target)
