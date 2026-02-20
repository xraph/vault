"use client";

import { motion } from "framer-motion";
import { CodeBlock } from "./code-block";
import { SectionHeader } from "./section-header";

const secretsCode = `package main

import (
  "context"
  "log"

  "github.com/xraph/vault"
  "github.com/xraph/vault/crypto"
  "github.com/xraph/vault/scope"
  "github.com/xraph/vault/secret"
  "github.com/xraph/vault/store/memory"
)

func main() {
  ctx := context.Background()
  st := memory.New()
  enc := crypto.NewEncryptor("my-32-byte-encryption-key-here!")

  svc := secret.NewService(st, enc)

  ctx = scope.WithAppID(ctx, "myapp")
  ctx = scope.WithTenantID(ctx, "tenant-1")

  // Store an encrypted secret
  _ = svc.Set(ctx, "api-key",
    []byte("sk-live-abc123"))

  // Retrieve and decrypt
  val, _ := svc.Get(ctx, "api-key")
  log.Printf("secret: %s", val)
  // secret: sk-live-abc123
}`;

const flagsCode = `package main

import (
  "context"
  "fmt"

  "github.com/xraph/vault/flag"
  "github.com/xraph/vault/scope"
  "github.com/xraph/vault/store/memory"
)

func main() {
  ctx := context.Background()
  st := memory.New()

  engine := flag.NewEngine(st)
  svc := flag.NewService(engine, st)

  ctx = scope.WithAppID(ctx, "myapp")
  ctx = scope.WithTenantID(ctx, "tenant-1")

  // Type-safe flag evaluation
  dark, _ := svc.Bool(ctx, "dark-mode", false)
  limit, _ := svc.Int(ctx, "rate-limit", 100)
  model, _ := svc.String(ctx, "ai-model", "gpt-4o")

  fmt.Printf("dark=%v limit=%d model=%s\\n",
    dark, limit, model)
  // dark=true limit=250 model=gpt-4o
}`;

export function CodeShowcase() {
  return (
    <section className="relative w-full py-20 sm:py-28">
      <div className="container max-w-(--fd-layout-width) mx-auto px-4 sm:px-6">
        <SectionHeader
          badge="Developer Experience"
          title="Simple API. Powerful primitives."
          description="Store an encrypted secret and evaluate a feature flag in under 20 lines. Vault handles encryption, scoping, and resolution."
        />

        <div className="mt-14 grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Secrets side */}
          <motion.div
            initial={{ opacity: 0, x: -20 }}
            whileInView={{ opacity: 1, x: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.5, delay: 0.1 }}
          >
            <div className="mb-3 flex items-center gap-2">
              <div className="size-2 rounded-full bg-amber-500" />
              <span className="text-xs font-medium text-fd-muted-foreground uppercase tracking-wider">
                Secrets
              </span>
            </div>
            <CodeBlock code={secretsCode} filename="main.go" />
          </motion.div>

          {/* Flags side */}
          <motion.div
            initial={{ opacity: 0, x: 20 }}
            whileInView={{ opacity: 1, x: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.5, delay: 0.2 }}
          >
            <div className="mb-3 flex items-center gap-2">
              <div className="size-2 rounded-full bg-orange-500" />
              <span className="text-xs font-medium text-fd-muted-foreground uppercase tracking-wider">
                Feature Flags
              </span>
            </div>
            <CodeBlock code={flagsCode} filename="flags.go" />
          </motion.div>
        </div>
      </div>
    </section>
  );
}
