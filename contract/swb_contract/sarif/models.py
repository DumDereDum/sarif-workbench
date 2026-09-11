from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class SarifRegion:
    start_line: int
    end_line: int | None = None
    start_column: int | None = None


@dataclass
class SarifLocation:
    uri: str
    region: SarifRegion
    uri_base_id: str | None = None
    # Index into `run.artifacts[]` — the canonical link from a result to its
    # file; uri stays the fallback when the index is absent.
    artifact_index: int | None = None


@dataclass
class SarifRelatedLocation:
    """`result.relatedLocations[]` — same physicalLocation shape as
    `locations[]`, plus an optional message (T-39). Payload, not identity
    (ADR 0001 §8)."""
    uri: str
    region: SarifRegion
    uri_base_id: str | None = None
    message: str = ""


@dataclass
class CodeFlowStep:
    """One `threadFlows[].locations[]` entry of a SARIF codeFlow (T-39)."""
    uri: str
    line: int | None
    message: str


@dataclass
class SarifThreadFlow:
    steps: list[CodeFlowStep] = field(default_factory=list)


@dataclass
class SarifCodeFlow:
    thread_flows: list[SarifThreadFlow] = field(default_factory=list)


@dataclass
class SarifArtifact:
    """A file results point at, with its text when the tool embedded it
    (`artifacts[].contents.text`).

    The spec provides for embedding precisely when the sources are not next
    to the report: Svace exports with contents, and the uris in its results
    name a build directory of another machine (`/.build/main.cpp`) that does
    not exist on disk here. Without reading the embedded text the snippet is
    lost even though the report carries it.
    """

    uri: str
    contents: str | None = None


@dataclass
class SarifResult:
    run_index: int
    result_index: int
    rule_id: str
    # None — поля `level` в SARIF нет. Отличать это от явно написанного
    # "warning" обязательно: по спецификации 2.1.0 отсутствующий уровень
    # берётся с defaultConfiguration правила, и только при его отсутствии
    # становится "warning". Semgrep уровень на результате не пишет вовсе —
    # он весь задан в правилах, и подстановка дефолта прямо здесь схлопывала
    # весь его вывод в один уровень.
    level: str | None    # error | warning | note | none | None
    message: str
    locations: list[SarifLocation] = field(default_factory=list)
    related_locations: list[SarifRelatedLocation] = field(default_factory=list)
    code_flows: list[SarifCodeFlow] = field(default_factory=list)
    fingerprints: dict[str, str] = field(default_factory=dict)
    partial_fingerprints: dict[str, str] = field(default_factory=dict)
    # Собственная качественная оценка анализатора, если он её отдал. У Svacer
    # это `properties.checker_severity` — именно она, а не соседняя
    # `properties.severity`: вторую перезаписывает разметка (в обоих наших
    # отчётах она равна Minor у всех 424 находок, тогда как checker_severity
    # различается).
    tool_severity: str | None = None


@dataclass
class SarifRule:
    rule_id: str
    name: str | None = None
    full_description: str | None = None
    help_uri: str | None = None
    security_severity: float | None = None  # from properties["security-severity"]
    # T-35: needed by server ingest (was read from the raw SARIF dict there,
    # not previously modeled by the typed CLI parser).
    tags: list[str] = field(default_factory=list)  # from properties["tags"]
    default_level: str = "warning"  # from defaultConfiguration.level
    # Every place this SARIF puts a CWE reference, as written. Analyzers do
    # not agree: CodeQL and Semgrep use `properties.tags`, Svacer uses
    # `properties.cwe[].name` and the spec-standard `relationships[].target.id`
    # pointing into `run.taxonomies`. Knowing WHERE a CWE hides is knowledge
    # about the format and belongs to the parser; normalizing the number
    # (dropping leading zeros, canonical `CWE-89`) belongs to the consumer.
    cwe_refs: list[str] = field(default_factory=list)


@dataclass
class SarifTool:
    name: str
    version: str | None
    rules: list[SarifRule] = field(default_factory=list)


@dataclass
class SarifRun:
    index: int
    tool: SarifTool
    results: list[SarifResult] = field(default_factory=list)
    # Raw `originalUriBaseIds` mapping: base id -> artifactLocation dict
    # ({"uri": ..., "uriBaseId": ...}); used to resolve location uriBaseId.
    original_uri_base_ids: dict = field(default_factory=dict)
    # `run.artifacts[]` in document order: a result's `artifactLocation.index`
    # is a position in this list.
    artifacts: list[SarifArtifact] = field(default_factory=list)


@dataclass
class SarifDocumentInfo:
    """Сведения о прогоне, которые анализатор кладёт в `properties` документа.

    Спецификация SARIF отводит под них свободный property bag, поэтому ключи
    у каждого инструмента свои. Здесь разбираются те, что пишет Svacer: имя
    проекта, ветка, снимок и версия конфигурации анализатора.

    Без этого отчёты Svacer приходилось привязывать к проекту вручную: имя
    бралось из каталога, в котором запускался CLI, а ветка и коммит
    оставались `unknown`. Для отчёта регулятору важно и то, и другое — там
    должно быть видно, что и в какой конфигурации сканировали.
    """

    project: str | None = None
    branch: str | None = None
    # Версия конфигурации анализатора — не то же самое, что версия драйвера:
    # у Svacer драйвер это svacer, а сканирует Svace, и его версия лежит здесь.
    analyzer_config: str | None = None
