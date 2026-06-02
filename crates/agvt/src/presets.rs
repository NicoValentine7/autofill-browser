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
