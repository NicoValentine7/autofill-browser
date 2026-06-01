#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Preset {
    pub name: &'static str,
    pub env_name: &'static str,
    pub label: &'static str,
    pub service_url: &'static str,
}

pub const PRESETS: &[Preset] = &[
    Preset {
        name: "cloudflare",
        env_name: "CLOUDFLARE_API_TOKEN",
        label: "Cloudflare",
        service_url: "https://api.cloudflare.com/client/v4",
    },
    Preset {
        name: "github",
        env_name: "GITHUB_TOKEN",
        label: "GitHub",
        service_url: "https://api.github.com",
    },
];

pub fn find_preset(name: &str) -> Option<&'static Preset> {
    PRESETS
        .iter()
        .find(|preset| preset.name.eq_ignore_ascii_case(name.trim()))
}
