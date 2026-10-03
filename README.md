# AIRecon 🛡️

**AI / LLM application red-teaming scanner**, mapped to the OWASP LLM Top 10.

![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

AIRecon sends adversarial prompts (prompt injection, jailbreaks, system-prompt
extraction, insecure output, excessive agency) to any OpenAI-compatible chat
endpoint and checks whether the model obeyed or leaked data.

> ⚠️ Use ONLY on systems you own or have written permission to test.

## Screenshots

![Scan output](screenshots/scan.png)
![HTML report](screenshots/report.png)

## Features

- 20 probes in `probes.yaml`; add your own without touching code
- Multi-turn attacks (conversation history preserved)
- Canary token: a hidden secret planted in the system prompt; a leak is a confirmed finding
- Heuristic detector with optional LLM-as-judge
- JSON and HTML reports with severity, confidence and the model's actual response
- Works with llama.cpp, Ollama, Groq, OpenAI and any OpenAI-compatible API
- Roman Urdu probes included (multilingual coverage)

## How it works

```
probes.yaml -> AIRecon -> target chatbot -> response -> detector -> report
                      (canary planted in system prompt)
```

1. Load attack prompts from `probes.yaml`
2. Send each to the target (single or multi-turn)
3. Detect: canary leak, success pattern, refusal language, or LLM judge
4. Score by severity x confidence and write JSON + HTML reports

## OWASP LLM Top 10 coverage

| Category | Probes |
|---|---|
| LLM01 Prompt Injection / Jailbreak | direct, delimiter, RAG, base64, DAN, dev-mode, multi-turn |
| LLM02 Insecure Output Handling | HTML/JS and markdown link injection |
| LLM04 Model DoS | context flooding |
| LLM06 Sensitive Info Disclosure | system prompt, credentials, translation leak |
| LLM08 Excessive Agency | unauthorized tool call, privilege escalation |

## Install

```bash
git clone https://github.com/YOUR_USERNAME/airecon.git
cd airecon
python3 -m venv venv && source venv/bin/activate
pip install requests pyyaml
```

## Usage

```bash
python3 airecon.py \
  --target-url http://127.0.0.1:8080/v1/chat/completions \
  --model qwen --workers 1 --timeout 180 --probes probes.yaml
```

Optional LLM judge: `--judge-model <model>`

No model handy? Run `python3 mock_target.py` and scan `http://127.0.0.1:8000`
to test the full pipeline.

## Example result

Tested against a local Qwen2.5-0.5B (llama.cpp): **16 of 20 probes succeeded**,
including a confirmed canary leak (single and multi-turn), XSS payload output
and an unauthorized action. Small models follow injected instructions easily;
larger models do much better. A sample report is included in this repo.

## Limitations

- Detection is heuristic; false positives and negatives are possible
- 20 probes is basic coverage, not a full audit
- Results on one model do not generalize to others

## Roadmap

- [ ] SARIF output for CI/CD
- [ ] Crescendo-style multi-turn chains
- [ ] Multi-model comparison mode
- [ ] More languages (Urdu, Hindi, Arabic)

## License

MIT