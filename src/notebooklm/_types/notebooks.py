"""Private notebook type implementations."""

from __future__ import annotations

import logging
import reprlib
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from ..rpc import RPCMethod, safe_index
from ..rpc.types import SharePermission, share_permission_to_str
from .common import _datetime_from_timestamp
from .sources import SourceType

logger = logging.getLogger(__name__)

# ``Notebook.from_api_response`` decodes rows from BOTH ``LIST_NOTEBOOKS`` (each
# row in the list envelope) and ``GET_NOTEBOOK`` (the single ``nb_info`` row).
# The positional descents below route through ``safe_index`` purely for the
# shared schema-drift telemetry seam; every descent is *length-guarded first*
# so ``safe_index`` is only ever invoked on a slot the guard already proved
# present — it therefore cannot raise here, preserving the historical
# "short / malformed rows soft-degrade to a default" contract (the same
# length-guard-then-``safe_index`` style ``NoteRow`` uses). ``LIST_NOTEBOOKS``
# is used as the representative ``method_id`` for diagnostics since the list
# path is the primary producer; a drift diagnostic would still point at the
# notebook-row family.
_NOTEBOOK_METHOD_ID = RPCMethod.LIST_NOTEBOOKS.value


@dataclass
class SourceSummary:
    """Simplified source information for metadata export."""

    kind: SourceType
    title: str | None = None
    url: str | None = None

    def to_dict(self) -> dict[str, str | None]:
        """Convert to dictionary for JSON serialization."""
        return {
            "type": self.kind.value,
            "title": self.title,
            "url": self.url,
        }


def _extract_notebook_sources_count(data: list[Any]) -> int:
    """Extract the embedded source count from a notebook API payload."""
    sources = (
        safe_index(data, 1, method_id=_NOTEBOOK_METHOD_ID, source="Notebook.sources_count")
        if len(data) > 1
        else None
    )
    return len(sources) if isinstance(sources, list) else 0


#: Wire codes the ``userRole`` slot may legitimately carry, as plain ints —
#: comparing ints to ints rather than relying on ``SharePermission`` hashing as
#: its value, so the check cannot quietly start rejecting everything if the enum
#: ever stops mixing in ``int``. ``SharePermission`` also owns ``_REMOVE = 4``
#: (proto ``NOT_SHARED``), but that is a write-only sentinel for the
#: share-mutation call — a notebook row never reports it (a revoked account gets
#: ``PERMISSION_DENIED``, not role 4), so it is excluded here rather than
#: surfaced as a nonsensical role.
_NOTEBOOK_ROLES = frozenset(
    {SharePermission.OWNER.value, SharePermission.EDITOR.value, SharePermission.VIEWER.value}
)


def _role_from_wire(raw_role: Any, row: list[Any]) -> SharePermission | None:
    """Map a raw ``userRole`` slot to :class:`SharePermission`, or ``None``.

    ``None`` means "not stated by this row" — an absent slot, or a value this
    client does not recognize. Callers treat that as unknown rather than
    guessing a level. An unmapped *present* value logs a WARNING because it is
    the signature of protocol drift (#1485 absence-vs-malformed policy).
    """
    if raw_role is None:
        return None
    # ``bool`` is an ``int`` subclass, so ``SharePermission(True)`` would
    # silently yield ``OWNER``. Reject booleans explicitly: they are the shape
    # of the neighbouring has-sharing slot, i.e. exactly the drift we would
    # most want to notice.
    if isinstance(raw_role, int) and not isinstance(raw_role, bool):
        if raw_role in _NOTEBOOK_ROLES:
            return SharePermission(raw_role)
    logger.warning(
        "Notebook row userRole slot unmapped — reporting unknown role "
        "(expected 1/2/3 at data[5][0], got %r; row=%s)",
        raw_role,
        reprlib.repr(row),
    )
    return None


@dataclass
class Notebook:
    """Represents a NotebookLM notebook."""

    id: str
    title: str
    created_at: datetime | None = None
    sources_count: int = 0
    #: ``True`` when :attr:`role` is :attr:`~notebooklm.types.SharePermission.OWNER`.
    #: Kept as a convenience derivation of :attr:`role`; it can no longer
    #: distinguish an editor from a viewer, so prefer :attr:`role` (#2125).
    is_owner: bool = True
    # ``modified_at`` / ``role`` are appended at the END of the field list so
    # positional construction stays unaffected (additive, default ``None``).
    modified_at: datetime | None = None
    #: The calling account's permission level on this notebook, decoded from
    #: ``ProjectMetadata.userRole``. ``None`` when the row omits the slot or
    #: carries an unmapped code.
    role: SharePermission | None = None

    def __setattr__(self, name: str, value: Any) -> None:
        """Keep ``is_owner`` in lock-step with ``role``, at construction *and* after.

        ``is_owner`` stays a *field* rather than becoming a property because the
        MCP/REST serializer emits ``dataclasses.fields`` only — a property would
        silently vanish from every adapter's response, a breaking wire change.
        So the invariant is maintained on assignment instead.

        Hooking ``__setattr__`` rather than ``__post_init__`` matters because
        this dataclass is mutated in place after construction (see the
        timestamp backfill in ``_app.notebooks._backfill_created_timestamps``);
        a construction-only hook would let ``is_owner`` go stale the moment
        anyone assigned ``role``.

        A contradictory ``is_owner`` is *corrected*, not rejected. Raising is not
        actually available here: ``is_owner`` has a plain ``True`` default, so
        the ordinary ``Notebook(id=..., title=..., role=VIEWER)`` call is
        indistinguishable from an explicit ``is_owner=True``, and rejecting the
        contradiction would reject the most natural construction in the codebase.

        When ``role`` is ``None`` (the row stated no level) the caller's
        ``is_owner`` is left untouched, preserving the historical
        optimistic-``True`` soft-degrade.
        """
        super().__setattr__(name, value)
        if name == "role" and value is not None:
            super().__setattr__("is_owner", value is SharePermission.OWNER)

    @classmethod
    def from_api_response(cls, data: list[Any]) -> Notebook:
        """Parse notebook from API response."""
        title_slot = (
            safe_index(data, 0, method_id=_NOTEBOOK_METHOD_ID, source="Notebook.title")
            if len(data) > 0
            else None
        )
        raw_title = title_slot if isinstance(title_slot, str) else ""
        title = raw_title.replace("thought\n", "").strip()
        sources_count = _extract_notebook_sources_count(data)
        # ``data[2]`` is the notebook id. A short row / ``None`` slot keeps
        # the historical silent ``""``-degrade — this factory parses rows out
        # of whole-list responses, so raising would abort sibling rows. A
        # *present-but-malformed* slot (non-str, non-None) still degrades to
        # ``""`` for the same reason, but now logs a WARNING: a silently
        # fabricated empty id is otherwise indistinguishable from a real row
        # (#1485 absence-vs-malformed policy).
        notebook_id = ""
        if len(data) > 2:
            raw_id = safe_index(data, 2, method_id=_NOTEBOOK_METHOD_ID, source="Notebook.id")
            if isinstance(raw_id, str):
                notebook_id = raw_id
            elif raw_id is not None:
                logger.warning(
                    "Notebook row id slot malformed — fabricating empty id "
                    "(expected str at data[2], got %s; row=%s)",
                    type(raw_id).__name__,
                    reprlib.repr(data),
                )

        # ``data[5]`` is the metadata block; bind it once so the timestamp and
        # role descents read a single named local instead of re-chaining
        # ``data[5][...]`` (the legitimately-absent block defaults below). The
        # slot read goes through ``safe_index`` (length-guarded first, so it
        # cannot raise) and the result is only retained when it is a list.
        meta_slot = (
            safe_index(data, 5, method_id=_NOTEBOOK_METHOD_ID, source="Notebook.metadata")
            if len(data) > 5
            else None
        )
        meta = meta_slot if isinstance(meta_slot, list) else None

        # ``meta[8]`` (``data[5][8][0]``) is the CREATION instant: a controlled
        # probe (create → add source @T0 → add source @T1) showed this slot
        # stayed pinned at the creation time across modifications, while
        # ``meta[5]`` advanced on each edit. The two slots were historically
        # swapped — ``created_at`` read ``meta[5]`` and so exposed the
        # last-modified time. ``meta[5]`` (``data[5][5][0]``) is now correctly
        # surfaced as ``modified_at``.
        created_at = None
        if meta is not None and len(meta) > 8:
            created_ts = safe_index(
                meta, 8, method_id=_NOTEBOOK_METHOD_ID, source="Notebook.created_at"
            )
            if isinstance(created_ts, list) and len(created_ts) > 0:
                created_at = _datetime_from_timestamp(
                    safe_index(
                        created_ts, 0, method_id=_NOTEBOOK_METHOD_ID, source="Notebook.created_at"
                    )
                )

        modified_at = None
        if meta is not None and len(meta) > 5:
            modified_ts = safe_index(
                meta, 5, method_id=_NOTEBOOK_METHOD_ID, source="Notebook.modified_at"
            )
            if isinstance(modified_ts, list) and len(modified_ts) > 0:
                modified_at = _datetime_from_timestamp(
                    safe_index(
                        modified_ts, 0, method_id=_NOTEBOOK_METHOD_ID, source="Notebook.modified_at"
                    )
                )

        # ``meta[0]`` (``data[5][0]``) is ``ProjectMetadata.userRole`` — the
        # CALLING account's permission level on this notebook (1 OWNER /
        # 2 WRITER / 3 READER, value-identical to ``SharePermission``).
        #
        # This used to be read from ``meta[1]`` instead, on the belief that the
        # slot was an owner flag. A two-account live probe (#2125) showed
        # ``meta[1]`` actually tracks "this notebook has ANY sharing at all":
        # it flipped ``False -> True`` the moment a collaborator was added to a
        # notebook the account owned, and back on revoke. So the old expression
        # evaluated to ``not (shared with anyone)`` and reported ``is_owner=False``
        # for every notebook the user owned *and had shared*. ``meta[0]`` stayed
        # pinned at ``1`` for the owner across every stage of that probe, and is
        # present on 100% of ``LIST_NOTEBOOKS`` *and* ``GET_NOTEBOOK`` rows, so
        # the correct read costs no extra RPC.
        role = None
        if meta is not None and len(meta) > 0:
            raw_role = safe_index(meta, 0, method_id=_NOTEBOOK_METHOD_ID, source="Notebook.role")
            role = _role_from_wire(raw_role, data)

        # ``is_owner`` is derived from ``role`` in ``__post_init__``. An unknown
        # / absent role leaves the field's default of ``True``: the
        # overwhelmingly common case is the caller's own notebook, and a short
        # or malformed row must soft-degrade rather than mislabel every entry.
        return cls(
            id=notebook_id,
            title=title,
            created_at=created_at,
            sources_count=sources_count,
            modified_at=modified_at,
            role=role,
        )


@dataclass
class SuggestedTopic:
    """A suggested topic/question for the notebook."""

    question: str
    prompt: str


@dataclass(frozen=True)
class PromptSuggestion:
    """An AI-suggested question/prompt to ask a notebook.

    Returned by :meth:`NotebooksAPI.suggest_prompts` (the ``otmP3b`` /
    ``GeneratePromptSuggestions`` RPC). Each suggestion pairs a short,
    human-readable ``title`` with a ready-to-send multi-line ``prompt`` that can
    be passed straight to :meth:`ChatAPI.ask`.

    Attributes:
        title: Short label for the suggestion (e.g. ``"Professional Briefing"``).
        prompt: The full multi-line instruction string to ask the notebook.
    """

    title: str
    prompt: str


@dataclass
class NotebookDescription:
    """AI-generated description and suggested topics for a notebook."""

    summary: str
    suggested_topics: list[SuggestedTopic] = field(default_factory=list)

    @classmethod
    def from_api_response(cls, data: dict[str, Any]) -> NotebookDescription:
        """Parse from get_notebook_description() response."""
        topics = [
            SuggestedTopic(question=t.get("question", ""), prompt=t.get("prompt", ""))
            for t in data.get("suggested_topics", [])
        ]
        return cls(
            summary=data.get("summary", ""),
            suggested_topics=topics,
        )


@dataclass
class NotebookMetadata:
    """Combined notebook metadata with sources list."""

    notebook: Notebook
    sources: list[SourceSummary] = field(default_factory=list)

    @property
    def id(self) -> str:
        """Get notebook ID."""
        return self.notebook.id

    @property
    def title(self) -> str:
        """Get notebook title."""
        return self.notebook.title

    @property
    def created_at(self) -> datetime | None:
        """Get creation timestamp."""
        return self.notebook.created_at

    @property
    def modified_at(self) -> datetime | None:
        """Get last-modified timestamp."""
        return self.notebook.modified_at

    @property
    def is_owner(self) -> bool:
        """Get owner status (``role is SharePermission.OWNER``)."""
        return self.notebook.is_owner

    @property
    def role(self) -> SharePermission | None:
        """Get the calling account's permission level on the notebook."""
        return self.notebook.role

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "id": self.id,
            "title": self.title,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "modified_at": self.modified_at.isoformat() if self.modified_at else None,
            "is_owner": self.is_owner,
            "role": share_permission_to_str(self.role) if self.role is not None else None,
            "sources": [s.to_dict() for s in self.sources],
        }
