---
title: OpenCode + Oh My OpenCode 配置
date: 2026-03-20
categories: [security, tooling]
tags: [opencode, oh-my-opencode, codex, config]
---

# OpenCode + Oh My OpenCode 配置

这篇文章记录我目前在本地使用的 **OpenCode + Oh My OpenCode** 配置.
默认开启 fast 模式 ```"serviceTier": "priority" ```

---

## 1) OpenCode：

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "provider": {
    "codex": {
      "npm": "@ai-sdk/openai",
      "name": "codex",
      "options": {
        "baseURL": "https://your-codex-gateway.example/v1",
        "apiKey": "${OPENCODE_API_KEY}",
        "setCacheKey": true
      },
      "models": {
        "gpt-5.3-codex": {
          "name": "GPT-5.3 Codex",
          "attachment": true,
          "reasoning": true,
          "tool_call": true,
          "cost": {
            "input": 1.75,
            "output": 14,
            "cache_read": 0.175
          },
          "modalities": {
            "input": ["text", "image", "pdf"],
            "output": ["text"]
          },
          "options": {
            "textVerbosity": "low",
            "reasoningSummary": "auto",
            "serviceTier": "priority"
          },
          "variants": {
            "low": { "reasoningEffort": "low" },
            "medium": { "reasoningEffort": "medium" },
            "high": { "reasoningEffort": "high" },
            "xhigh": { "reasoningEffort": "xhigh" }
          },
          "limit": {
            "context": 400000,
            "input": 272000,
            "output": 128000
          }
        },
        "gpt-5.4": {
          "name": "GPT-5.4",
          "attachment": true,
          "reasoning": true,
          "tool_call": true,
          "cost": {
            "input": 2.5,
            "output": 15,
            "cache_read": 0.25
          },
          "modalities": {
            "input": ["text", "image", "pdf"],
            "output": ["text"]
          },
          "options": {
            "textVerbosity": "low",
            "reasoningSummary": "auto",
            "serviceTier": "priority"
          },
          "variants": {
            "low": { "reasoningEffort": "low" },
            "medium": { "reasoningEffort": "medium" },
            "high": { "reasoningEffort": "high" },
            "xhigh": { "reasoningEffort": "xhigh" }
          },
          "limit": {
            "context": 1050000,
            "input": 922000,
            "output": 128000
          }
        },
        "gpt-5.4-mini": {
          "name": "GPT-5.4 Mini",
          "attachment": true,
          "reasoning": true,
          "tool_call": true,
          "cost": {
            "input": 0.75,
            "output": 4.5,
            "cache_read": 0.075
          },
          "modalities": {
            "input": ["text", "image", "pdf"],
            "output": ["text"]
          },
          "options": {
            "textVerbosity": "low",
            "reasoningSummary": "auto",
            "serviceTier": "priority"
          },
          "variants": {
            "low": { "reasoningEffort": "low" },
            "medium": { "reasoningEffort": "medium" },
            "high": { "reasoningEffort": "high" },
            "xhigh": { "reasoningEffort": "xhigh" }
          },
          "limit": {
            "context": 400000,
            "input": 272000,
            "output": 128000
          }
        }
      }
    }
  },
  "model": "codex/GPT-5.4",
  "compaction": {
    "auto": true,
    "prune": true
  }
}
```

---

## 2) Oh My OpenCode：我的 agent / category 配置

主要做了三件事：

- 按角色拆 agent（如 `sisyphus`、`oracle`、`librarian`）。
- 给每个 agent 配 fallback 模型，减少单点失败
- 用 `permission` 控制编辑、bash、外部目录访问范围

```json
{
  "$schema": "https://raw.githubusercontent.com/code-yeongyu/oh-my-opencode/master/assets/oh-my-opencode.schema.json",
  "hashline_edit": true,
  "runtime_fallback": {
    "enabled": true,
    "retry_on_errors": [400, 429, 503, 529],
    "max_fallback_attempts": 3,
    "cooldown_seconds": 60,
    "timeout_seconds": 30,
    "notify_on_fallback": true
  },
  "agents": {
    "sisyphus": {
      "model": "codex/gpt-5.4",
      "variant": "high",
      "fallback_models": ["codex/gpt-5.3-codex", "codex/gpt-5.4-mini"],
      "permission": {
        "edit": "allow",
        "bash": "allow",
        "webfetch": "allow",
        "external_directory": "ask"
      }
    },
    "hephaestus": {
      "model": "codex/gpt-5.3-codex",
      "variant": "medium",
      "fallback_models": ["codex/gpt-5.4", "codex/gpt-5.4-mini"],
      "permission": {
        "edit": "allow",
        "bash": "allow",
        "webfetch": "allow",
        "external_directory": "deny"
      }
    },
    "oracle": {
      "model": "codex/gpt-5.4",
      "variant": "high",
      "fallback_models": ["codex/gpt-5.3-codex", "codex/gpt-5.4-mini"],
      "permission": {
        "edit": "ask",
        "bash": "allow",
        "webfetch": "allow",
        "external_directory": "ask"
      }
    },
    "librarian": {
      "model": "codex/gpt-5.4-mini",
      "variant": "medium",
      "fallback_models": ["codex/gpt-5.4", "codex/gpt-5.3-codex"],
      "permission": {
        "edit": "deny",
        "bash": "deny",
        "webfetch": "allow",
        "external_directory": "deny"
      }
    },
    "explore": {
      "model": "codex/gpt-5.4-mini",
      "variant": "low",
      "fallback_models": ["codex/gpt-5.3-codex", "codex/gpt-5.4"],
      "permission": {
        "edit": "deny",
        "bash": "ask",
        "webfetch": "allow",
        "external_directory": "deny"
      }
    },
    "multimodal-looker": {
      "model": "codex/gpt-5.4",
      "variant": "high",
      "fallback_models": ["codex/gpt-5.4-mini", "codex/gpt-5.3-codex"],
      "permission": {
        "edit": "deny",
        "bash": "deny",
        "webfetch": "allow",
        "external_directory": "deny"
      }
    },
    "prometheus": {
      "model": "codex/gpt-5.4",
      "variant": "high",
      "fallback_models": ["codex/gpt-5.3-codex", "codex/gpt-5.4-mini"],
      "permission": {
        "edit": "deny",
        "bash": "deny",
        "webfetch": "allow",
        "external_directory": "ask"
      }
    },
    "metis": {
      "model": "codex/gpt-5.4",
      "variant": "xhigh",
      "fallback_models": ["codex/gpt-5.3-codex", "codex/gpt-5.4-mini"],
      "permission": {
        "edit": "deny",
        "bash": "deny",
        "webfetch": "allow",
        "external_directory": "deny"
      }
    },
    "momus": {
      "model": "codex/gpt-5.4",
      "variant": "high",
      "fallback_models": ["codex/gpt-5.3-codex", "codex/gpt-5.4-mini"],
      "permission": {
        "edit": "deny",
        "bash": "deny",
        "webfetch": "allow",
        "external_directory": "deny"
      }
    },
    "atlas": {
      "model": "codex/gpt-5.4",
      "variant": "xhigh",
      "fallback_models": ["codex/gpt-5.3-codex", "codex/gpt-5.4-mini"],
      "permission": {
        "edit": "ask",
        "bash": "allow",
        "webfetch": "allow",
        "external_directory": "deny"
      }
    }
  },
  "categories": {
    "visual-engineering": {
      "model": "codex/gpt-5.4",
      "variant": "high",
      "fallback_models": ["codex/gpt-5.4-mini", "codex/gpt-5.3-codex"]
    },
    "ultrabrain": {
      "model": "codex/gpt-5.4",
      "variant": "xhigh",
      "fallback_models": ["codex/gpt-5.3-codex", "codex/gpt-5.4-mini"]
    },
    "deep": {
      "model": "codex/gpt-5.3-codex",
      "variant": "medium",
      "fallback_models": ["codex/gpt-5.4", "codex/gpt-5.4-mini"]
    },
    "artistry": {
      "model": "codex/gpt-5.4",
      "variant": "medium",
      "fallback_models": ["codex/gpt-5.4-mini", "codex/gpt-5.3-codex"]
    },
    "quick": {
      "model": "codex/gpt-5.4-mini",
      "variant": "low",
      "fallback_models": ["codex/gpt-5.3-codex", "codex/gpt-5.4"]
    },
    "unspecified-low": {
      "model": "codex/gpt-5.4-mini",
      "variant": "medium",
      "fallback_models": ["codex/gpt-5.4", "codex/gpt-5.3-codex"]
    },
    "unspecified-high": {
      "model": "codex/gpt-5.4",
      "variant": "high",
      "fallback_models": ["codex/gpt-5.3-codex", "codex/gpt-5.4-mini"]
    },
    "writing": {
      "model": "codex/gpt-5.4-mini",
      "variant": "medium",
      "fallback_models": ["codex/gpt-5.4", "codex/gpt-5.3-codex"]
    }
  }
}
```

如果你也在折腾 OpenCode 生态，欢迎直接拿这个模板改成你自己的 provider / model 组合。
