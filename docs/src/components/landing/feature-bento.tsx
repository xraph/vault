"use client";

import { motion } from "framer-motion";
import { cn } from "@/lib/cn";
import { CodeBlock } from "./code-block";
import { SectionHeader } from "./section-header";

interface FeatureCard {
  title: string;
  description: string;
  icon: React.ReactNode;
  code: string;
  filename: string;
  colSpan?: number;
}

const features: FeatureCard[] = [
  {
    title: "Secrets Management",
    description:
      "AES-256-GCM encrypted, versioned secrets with automatic nonce generation. Store, retrieve, and rotate secrets with full audit trails.",
    icon: (
      <svg
        className="size-5"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
        aria-hidden="true"
      >
        <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
        <path d="M7 11V7a5 5 0 0110 0v4" />
        <circle cx="12" cy="16" r="1" />
      </svg>
    ),
    code: `svc := secret.NewService(store, encryptor)

err := svc.Set(ctx, "db-password",
  []byte("s3cret!"),
  secret.WithMetadata(map[string]string{
    "env": "production",
  }),
)

val, _ := svc.Get(ctx, "db-password")
// val = []byte("s3cret!")`,
    filename: "secrets.go",
  },
  {
    title: "Feature Flags",
    description:
      "Type-safe flag evaluation with targeting rules, tenant overrides, percentage rollouts, and schedule-based activation.",
    icon: (
      <svg
        className="size-5"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
        aria-hidden="true"
      >
        <path d="M4 2v20M4 4h12l-3 4 3 4H4" />
      </svg>
    ),
    code: `engine := flag.NewEngine(store)
svc := flag.NewService(engine, store)

dark, _ := svc.Bool(ctx, "dark-mode", false)
limit, _ := svc.Int(ctx, "rate-limit", 100)
model, _ := svc.String(ctx, "ai-model", "gpt-4o")
// dark=true, limit=250, model="gpt-4o"`,
    filename: "flags.go",
  },
  {
    title: "Runtime Config",
    description:
      "Type-safe configuration with Duration, JSON, and Watch support. Override resolution chains config sources with per-tenant overrides.",
    icon: (
      <svg
        className="size-5"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
        aria-hidden="true"
      >
        <circle cx="12" cy="12" r="3" />
        <path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42" />
      </svg>
    ),
    code: `svc := config.NewService(store)

ttl, _ := svc.Duration(ctx,
  "cache-ttl", 5*time.Minute)

svc.Watch(ctx, "cache-ttl",
  func(key string, val any) {
    cache.SetTTL(val.(time.Duration))
  })`,
    filename: "config.go",
  },
  {
    title: "Secret Rotation",
    description:
      "Schedule-based automatic rotation with custom rotator functions. Define policies per secret and let the manager handle the lifecycle.",
    icon: (
      <svg
        className="size-5"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
        aria-hidden="true"
      >
        <path d="M1 4v6h6M23 20v-6h-6" />
        <path d="M20.49 9A9 9 0 005.64 5.64L1 10M23 14l-4.64 4.36A9 9 0 013.51 15" />
      </svg>
    ),
    code: `mgr := rotation.NewManager(store, secretSvc)

mgr.RegisterRotator("db-password",
  func(ctx context.Context) ([]byte, error) {
    pw := generatePassword(32)
    return []byte(pw), nil
  })

mgr.Start(ctx) // runs on policy schedule`,
    filename: "rotation.go",
  },
  {
    title: "Multi-Tenant Isolation",
    description:
      "Every operation is scoped to tenant and app via context. Cross-tenant access is structurally impossible at the store layer.",
    icon: (
      <svg
        className="size-5"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
        aria-hidden="true"
      >
        <path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2" />
        <circle cx="9" cy="7" r="4" />
        <path d="M23 21v-2a4 4 0 00-3-3.87M16 3.13a4 4 0 010 7.75" />
      </svg>
    ),
    code: `ctx = scope.WithAppID(ctx, "myapp")
ctx = scope.WithTenantID(ctx, "tenant-1")
ctx = scope.WithUserID(ctx, "user-42")

// All secret, flag, config operations
// are automatically scoped to this tenant`,
    filename: "scope.go",
  },
  {
    title: "Plugin System",
    description:
      "Register plugins that implement any of 8 capability interfaces. The registry auto-discovers capabilities via type-switch.",
    icon: (
      <svg
        className="size-5"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
        aria-hidden="true"
      >
        <path d="M12 2L2 7l10 5 10-5-10-5z" />
        <path d="M2 17l10 5 10-5M2 12l10 5 10-5" />
      </svg>
    ),
    code: `reg := plugin.NewRegistry()
reg.Register(&DatadogPlugin{})
reg.Register(&SlackAlertsPlugin{})

// Auto-discovered capabilities:
// - OnInit, OnShutdown
// - OnSecretAccess, OnConfigChange
// - RotationStrategy`,
    filename: "plugins.go",
    colSpan: 2,
  },
];

const containerVariants = {
  hidden: {},
  visible: {
    transition: {
      staggerChildren: 0.08,
    },
  },
};

const itemVariants = {
  hidden: { opacity: 0, y: 20 },
  visible: {
    opacity: 1,
    y: 0,
    transition: { duration: 0.5, ease: "easeOut" as const },
  },
};

export function FeatureBento() {
  return (
    <section className="relative w-full py-20 sm:py-28">
      <div className="container max-w-(--fd-layout-width) mx-auto px-4 sm:px-6">
        <SectionHeader
          badge="Features"
          title="Everything you need for application secrets"
          description="Vault handles the hard parts — encryption, tenant isolation, flag evaluation, config resolution, and audit logging — so you can focus on your application."
        />

        <motion.div
          variants={containerVariants}
          initial="hidden"
          whileInView="visible"
          viewport={{ once: true, margin: "-50px" }}
          className="mt-14 grid grid-cols-1 md:grid-cols-2 gap-4"
        >
          {features.map((feature) => (
            <motion.div
              key={feature.title}
              variants={itemVariants}
              className={cn(
                "group relative rounded-xl border border-fd-border bg-fd-card/50 backdrop-blur-sm p-6 hover:border-amber-500/20 hover:bg-fd-card/80 transition-all duration-300",
                feature.colSpan === 2 && "md:col-span-2",
              )}
            >
              {/* Header */}
              <div className="flex items-start gap-3 mb-4">
                <div className="flex items-center justify-center size-9 rounded-lg bg-amber-500/10 text-amber-600 dark:text-amber-400 shrink-0">
                  {feature.icon}
                </div>
                <div>
                  <h3 className="text-sm font-semibold text-fd-foreground">
                    {feature.title}
                  </h3>
                  <p className="text-xs text-fd-muted-foreground mt-1 leading-relaxed">
                    {feature.description}
                  </p>
                </div>
              </div>

              {/* Code snippet */}
              <CodeBlock
                code={feature.code}
                filename={feature.filename}
                showLineNumbers={false}
                className="text-xs"
              />
            </motion.div>
          ))}
        </motion.div>
      </div>
    </section>
  );
}
