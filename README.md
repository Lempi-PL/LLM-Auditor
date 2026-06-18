# Aegis-LLM Enterprise DAST 🛡️🤖

**Aegis-LLM** is an advanced, asynchronous DAST (Dynamic Application Security Testing) scanner designed specifically for auditing the security of applications based on Large Language Models (LLMs). The tool was built with the rigorous requirements of the **NIS2** directive and the **OWASP Top 10 for LLMs 2026** standards in mind.

The project features a *Secure-by-Design* architecture (resilient to SSRF, DoS, TOCTOU) and is adapted to run in containers with a *Read-Only* file system (DevSecOps).

---

## 📑 Table of Contents
1. [Detailed Description of Scanner Features](#1-detailed-description-of-scanner-features)
2. [Running via Podman / Docker (Recommended)](#2-running-via-podman--docker-recommended)
3. [How to Use Scanner Features (User Guide)](#3-how-to-use-scanner-features-user-guide)
4. [Environment Variables and the .env File](#4-environment-variables-and-the-env-file)
5. [Running Automated Tests](#5-running-automated-tests)

---

## 1. Detailed Description of Scanner Features

Aegis-LLM offers a multi-layered approach to AI security testing. Below is a breakdown of all built-in modules:

### 💉 1.1. Prompt Injection and Evasion
The scanner loads base attack vectors from YAML files (the `payloads/` directory) and automatically generates mutated versions to bypass WAF filters and built-in LLM safeguards.
* **Base64 Evasion:** Encodes the malicious prompt in Base64 format.
* **Homoglyph Evasion:** Replaces standard Latin characters with their visual equivalents from Cyrillic.
* **Cognitive Bypass:** Wraps the malicious vector in a hypothetical/academic scenario (so-called *Jailbreak*).

### 🕵️ 1.2. Indirect Prompt Injection (IPI)
A module testing the model's vulnerability to malicious instructions hidden in processed external data.
* **Hidden DOM Smuggling:** Hides the attack vector in invisible HTML elements (`display: none`).
* **Markdown Smuggling:** Injects malicious instructions into the `alt` or `title` attributes of images/links.

### 🌐 1.3. Two Scanning Modes (API & Browser)
* **API Mode (`httpx`):** Direct, high-performance hitting of REST/GraphQL endpoints.
* **Browser Mode (`playwright`):** Scanning Chatbot-type applications (UI). The scanner launches a headless Chromium browser, simulates text input, and reads the generated response.

### ⚖️ 1.4. LLM-as-a-Judge (Layered Evaluation)
Instead of relying solely on regular expressions, Aegis-LLM can connect to a local **Ollama** instance (e.g., the `mistral-nemo:12b` model), which acts as an arbiter to evaluate whether the target model has actually been compromised.

### 💥 1.5. Asymmetric DoS Tests (Model Denial of Service)
The scanner sends specially crafted prompts forcing the model into maximum token generation and complex reasoning, measuring delays (P95 Latency) and verifying vulnerability to resource exhaustion.

### 🔐 1.6. Authorization Analysis (JWT Auth Bypass)
A built-in cryptographic module that automatically takes the provided JWT token, generates a malicious token (**Algorithm Confusion** attack with `{"alg": "none"}`), and verifies if the backend API accepts it.

### 📋 1.7. NIS2 Compliance Scanning (Baseline)
Automatic verification of basic cybersecurity hygiene (requirement of Art. 21 of the NIS2 directive): HSTS, CSP, X-Content-Type-Options.

### 📊 1.8. Secure Reporting (JSON + PDF)
Generation of structured JSON reports and formalized PDF reports (the `reports/` directory). The PDF generator is 100% secured against SSRF, LFI, and Out-Of-Memory (OOM) attacks.

---

## 2. Running via Podman / Docker (Recommended)

For security reasons (DevSecOps), it is recommended to run the scanner in an isolated container with a **Read-Only** file system.

### Step 1: Building the image
The project uses the modern `uv` package manager. Ensure the `uv.lock` file is up to date.
```bash
# For Podman
podman build -t aegis-llm .

# For Docker
docker build -t aegis-llm .
```

### Step 2: Running the scanner in a container
For the scanner to save reports to your disk and read your payloads, you must mount the appropriate volumes. We use the `--read-only` and `--tmpfs` flags to secure the container. 

*Note: The image has a defined `ENTRYPOINT`, so you only provide the scanner arguments.*

```bash
podman run --rm -it \
  --read-only \
  --tmpfs /tmp \
  --tmpfs /home/aegis_user/app/templates \
  -v "$(pwd)/reports:/home/aegis_user/app/reports:Z" \
  -v "$(pwd)/payloads:/home/aegis_user/app/payloads:Z" \
  aegis-llm -t https://api.example.com/chat
```

---

## 3. How to Use Scanner Features (User Guide)

### 3.1. Using a Custom API Template (`--api-template`)
If your API requires a specific JSON structure (e.g., OpenAI format), use the ready-made templates in the `api_templates/` directory (e.g., `openai_template.json`). Use the `<<PAYLOAD>>` tag where the attack vector should be placed.

**Running (Docker/Podman):**
You must mount the templates directory into the container:
```bash
podman run --rm -it \
  --read-only \
  --tmpfs /tmp \
  --tmpfs /home/aegis_user/app/templates \
  -v "$(pwd)/reports:/home/aegis_user/app/reports:Z" \
  -v "$(pwd)/api_templates:/home/aegis_user/app/api_templates:Z" \
  aegis-llm -t https://api.example.com/v1/chat/completions \
  --api-template api_templates/openai_template.json
```

### 3.2. Scanning in Browser Mode and the `dummy_chat.html` file
The repository includes a `dummy_chat.html` file that simulates a vulnerable LLM chatbot interface. You can use it to test the `--mode browser` mode.

**Step 1: Start a local web server with the `dummy_chat.html` file**
```bash
python -m http.server 8080
```
The application will be available at `http://localhost:8080/dummy_chat.html`.

**Step 2: Run the scanner in Browser mode (Docker/Podman)**
Since we are scanning the host from inside the container, we use the `host.containers.internal` (or `host.docker.internal`) address and the `--allow-internal-target` flag, which disables SSRF protection for this test.

```bash
podman run --rm -it \
  --read-only \
  --tmpfs /tmp \
  --tmpfs /home/aegis_user/app/templates \
  -v "$(pwd)/reports:/home/aegis_user/app/reports:Z" \
  aegis-llm -t http://host.containers.internal:8080/dummy_chat.html \
  --mode browser \
  --browser-input "#chat-input" \
  --browser-submit "#chat-submit" \
  --browser-output "#chat-output" \
  --allow-internal-target
```

### 3.3. Running LLM DoS Tests
To verify if the application is resilient to asymmetric resource exhaustion attacks, add the `--run-dos` flag.
```bash
podman run --rm -it aegis-llm -t https://api.example.com/chat --run-dos
```

### 3.4. Enabling AI Evaluation (LLM-as-a-Judge)
Requires a running Ollama server in a local/containerized environment.
```bash
podman run --rm -it aegis-llm -t https://api.example.com/chat \
  --use-ai-judge \
  --judge-host "http://host.containers.internal:11434" \
  --ai-model "mistral-nemo:12b"
```

---

## 4. Environment Variables and the `.env` File

Aegis-LLM securely manages secrets via environment variables. To avoid leaking passwords in the shell history, it is recommended to use a `.env` file.

**Step 1: Create a `.env` file in the root directory of the project:**
```env
# Example .env file
AEGIS_BEARER_TOKEN=super_secret_token_123
AEGIS_API_KEY=sk-abc123def456
AEGIS_JWT_TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
AEGIS_RAW_HEADERS_JSON={"X-Custom-Auth": "secret", "Cookie": "session=123"}
```

**Step 2: Running with the `.env` file in a container**
Pass the file using the `--env-file` flag:
```bash
podman run --rm -it \
  --env-file .env \
  -v "$(pwd)/reports:/home/aegis_user/app/reports:Z" \
  aegis-llm -t https://api.example.com/chat
```

---

## 5. Running Automated Tests

The project includes a comprehensive suite of unit tests (the `tests/` directory) written using the `pytest` library. 

In accordance with DevSecOps best practices, the `aegis-llm` container image is built in production mode (`--no-dev`), which means it does not contain testing tools. To run the tests, use one of the following methods:

**Method 1: Local execution (Recommended during development)**
The `uv` tool automatically manages the environment:
```bash
uv run pytest -v
```

**Method 2: Container execution (For CI/CD pipelines)**
Installing test dependencies on the fly in a temporary container:
```bash
podman run --rm -it \
  --entrypoint /bin/bash \
  aegis-llm -c "uv sync --frozen && uv run pytest -v"
```

