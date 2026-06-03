#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PresetField {
    pub env_name: &'static str,
    pub field: &'static str,
    pub required: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Preset {
    pub name: &'static str,
    pub env_name: &'static str,
    pub label: &'static str,
    pub service_url: &'static str,
    pub fields: &'static [PresetField],
}

pub const PRESETS: &[Preset] = &[
    Preset {
        name: "cloudflare",
        env_name: "CLOUDFLARE_API_TOKEN",
        label: "Cloudflare",
        service_url: "https://api.cloudflare.com/client/v4",
        fields: &[
            PresetField {
                env_name: "CLOUDFLARE_API_TOKEN",
                field: "token",
                required: true,
            },
            PresetField {
                env_name: "CLOUDFLARE_ACCOUNT_ID",
                field: "accountId",
                required: false,
            },
        ],
    },
    Preset {
        name: "openai",
        env_name: "OPENAI_API_KEY",
        label: "OpenAI",
        service_url: "https://api.openai.com/v1",
        fields: &[PresetField {
            env_name: "OPENAI_API_KEY",
            field: "token",
            required: true,
        }],
    },
    Preset {
        name: "anthropic",
        env_name: "ANTHROPIC_API_KEY",
        label: "Anthropic",
        service_url: "https://api.anthropic.com",
        fields: &[PresetField {
            env_name: "ANTHROPIC_API_KEY",
            field: "token",
            required: true,
        }],
    },
    Preset {
        name: "vercel",
        env_name: "VERCEL_TOKEN",
        label: "Vercel",
        service_url: "https://api.vercel.com",
        fields: &[PresetField {
            env_name: "VERCEL_TOKEN",
            field: "token",
            required: true,
        }],
    },
    Preset {
        name: "stripe",
        env_name: "STRIPE_API_KEY",
        label: "Stripe",
        service_url: "https://api.stripe.com",
        fields: &[PresetField {
            env_name: "STRIPE_API_KEY",
            field: "token",
            required: true,
        }],
    },
    Preset {
        name: "slack",
        env_name: "SLACK_BOT_TOKEN",
        label: "Slack",
        service_url: "https://slack.com/api",
        fields: &[PresetField {
            env_name: "SLACK_BOT_TOKEN",
            field: "token",
            required: true,
        }],
    },
    Preset {
        name: "github",
        env_name: "GITHUB_TOKEN",
        label: "GitHub",
        service_url: "https://api.github.com",
        fields: &[PresetField {
            env_name: "GITHUB_TOKEN",
            field: "token",
            required: true,
        }],
    },
];

pub fn find_preset(name: &str) -> Option<&'static Preset> {
    PRESETS
        .iter()
        .find(|preset| preset.name.eq_ignore_ascii_case(name.trim()))
}
