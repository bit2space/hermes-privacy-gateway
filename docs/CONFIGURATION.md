# Configuration

Hermes resolves the manifest's `config_schema` under:

```text
plugins.entries.privacy-gateway.settings
```

## Example

```yaml
plugins:
  enabled:
    - privacy-gateway

  entries:
    privacy-gateway:
      settings:
        language: en
        score_threshold: 0.55
        enable_langextract: false
        langextract_config_path: ""
        nlp_config: nlp.yaml
        allow_list: []
        enable_pl_recognizers: false
        block_non_text_content: true
        rehydrate_tool_allowlist: []
```

## Settings

### `language`

Default: `en`

Passed to Presidio Analyzer. The included `nlp.yaml` only configures an English spaCy model. Adding another language requires updating both the NLP configuration and Presidio recognizer support; do not merely change this string and assume multilingual detection exists.

### `score_threshold`

Default: `0.55`

Passed to `AnalyzerEngine.analyze(..., score_threshold=...)`. Raising it usually reduces false positives and can increase false negatives. Lowering it does the reverse. Evaluate on a private corpus representative of your mail/data.

### `enable_langextract`

Default: `false`

When enabled, the plugin adds Presidio's `BasicLangExtractRecognizer` programmatically. Presidio marks this feature experimental and documents local Ollama support.

With no custom config path, the recognizer uses Presidio's default LangExtract configuration. Current Presidio docs say that default uses a local Ollama model and that the model must be pulled/running first.

### `nlp_config`

Default: `nlp.yaml`

Presidio NLP configuration, relative to the plugin directory or absolute. `nlp.yaml` uses `en_core_web_lg`; `nlp-pl.yaml` uses `pl_core_news_lg` for mostly-Polish text. The English model tags many Polish common words as people or organizations, so Polish conversations end up heavily aliased. The model must be installed the same way as `en_core_web_lg` (see INSTALL.md), using the `pl_core_news_lg-3.8.0` wheel. `nlp-pl.yaml` keeps the `en` registry label so the pattern recognizers stay active, and ignores spaCy's relative date/time labels.

### `allow_list`

Default: `[]`

Terms that are never aliased, such as product and tool names the NER model mistakes for people or organizations (`Notion`, `MCP`, `Claude`). Matching is case-insensitive on the whole detected span, ignoring surrounding punctuation, so `Notion` does not exempt a span like `Notion Kamil`.

### `enable_pl_recognizers`

Default: `false`

Registers Polish recognizers on the analyzer's language registry (`language`, normally `en`). Presidio ships its Polish recognizers for the `pl` registry only, so with the default English configuration Polish identifiers are not detected at all.

| Entity | Detected when |
|---|---|
| `PHONE_NUMBER` | `+48`/`0048` prefix; a bare 9-digit or `(22) 123-45-67` number only next to a phone context word (`tel`, `komórka`, `phone`, `sms`, ...) |
| `PL_PESEL` | 11 digits with a valid date part and checksum |
| `PL_NIP` | valid checksum and a `PL` prefix or dashed grouping; a plain 10-digit number only next to `NIP`/`VAT` |
| `PL_ID_CARD` | `ABC123456` with a valid checksum next to `dowód`/`seria` |

Bare numbers that merely pass a checksum keep a low score, so order IDs and timestamps are not aliased without context. Identifiers are matched as whole tokens only.

### `langextract_config_path`

Default: empty string.

If set, the path is passed directly to:

```python
BasicLangExtractRecognizer(config_path=...)
```

Presidio's official LangExtract documentation lists configuration fields including:

- `model_id`
- provider name
- provider kwargs such as Ollama model URL / OpenAI-compatible base URL
- extraction parameters
- model parameters
- supported entities
- entity mappings
- minimum score

This repo intentionally does not invent a model/endpoint-specific config. Create it from the Presidio documentation for the Ollama model you actually run.

### `block_non_text_content`

Default: `true`.

The plugin pseudonymizes **text**. It detects common model-request shapes for images, audio, and files. When one is found, it replaces the main content root with a block marker instead of sending the non-text payload onward.

If you set this to `false`, image/audio/file content can bypass text redaction. Only do so when a separate trusted local privacy pipeline handles that modality.

### `rehydrate_tool_allowlist`

Default: `[]`.

This is deliberately deny-by-default. When the cloud model emits:

```text
[EMAIL_ADDRESS_ABC...]
```

the plugin does **not** automatically turn it back into a real address for every tool. Otherwise a web-search, browser, webhook, or unrelated external tool could receive the plaintext.

Add only exact trusted Hermes tool names that genuinely need real values. Example shape:

```yaml
rehydrate_tool_allowlist:
  - exact_tool_name_here
  - another_exact_tool_name_here
```

Do not copy those placeholders literally. Discover the exact tool identifiers in your Hermes installation/Gmail integration and review what each tool sends off-host before allowlisting it.

## Organization detection

The included `nlp.yaml` maps `ORG`/`ORGANIZATION` to Presidio's `ORGANIZATION` entity and does not put organizations in `labels_to_ignore`.

That is an intentional privacy-biased deviation from Presidio's conservative default behavior, because company/customer/vendor names in mail can be sensitive. Expect more false positives and tune against your data.

## Auxiliary Hermes models

The plugin's `llm_request` middleware protects the main provider request. Hermes documents auxiliary calls (for example session titling, context compression, MoA tasks, vision, approval, memory and other side jobs) as running outside the main tool-calling loop.

For a privacy-sensitive profile, route every auxiliary task that may see sensitive context to a local endpoint. Hermes documents the common pattern as:

```yaml
auxiliary:
  compression:
    model: your-local-model
    base_url: http://127.0.0.1:11434/v1
    api_key: local-key
```

That is an example for the documented `compression` slot, not an exhaustive list of every enabled auxiliary task in your Hermes build. Review your current Hermes model configuration and route all applicable auxiliary slots locally.
